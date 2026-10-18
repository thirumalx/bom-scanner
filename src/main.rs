mod cbom;

use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const DEFAULT_TRIVY_PATH: &str = r"D:\trivy.exe";
const DEFAULT_SOURCE_DIR: &str = r"D:\Vulerability";
const DEFAULT_OUTPUT_DIR: &str = r"D:\Vulerability_SBOM_Reports";
const DEFAULT_HTML_TPL: &str = r"D:\html.tpl";

#[derive(Debug)]
struct Config {
    source_dir: PathBuf,
    output_dir: PathBuf,
    trivy_path: PathBuf,
    template_path: Option<PathBuf>,
    offline: bool,
}

#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results")]
    results: Option<Vec<TrivyResult>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: Option<String>,
    #[serde(rename = "Packages")]
    packages: Option<Vec<TrivyPackage>>,
    #[serde(rename = "Vulnerabilities")]
    vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct TrivyPackage {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    id: Option<String>,
    #[serde(rename = "Severity")]
    severity: Option<String>,
}

#[derive(Debug, Serialize)]
struct SummaryRecord {
    #[serde(rename = "Module Name")]
    module_name: String,
    #[serde(rename = "Dependencies Count")]
    dependencies_count: usize,
    #[serde(rename = "Critical Vulnerabilities")]
    critical: usize,
    #[serde(rename = "High Vulnerabilities")]
    high: usize,
    #[serde(rename = "Medium Vulnerabilities")]
    medium: usize,
    #[serde(rename = "Low Vulnerabilities")]
    low: usize,
    #[serde(rename = "Total Vulnerabilities")]
    total_vulns: usize,
    #[serde(rename = "Crypto Assets Count")]
    crypto_assets_count: usize,
    #[serde(rename = "CycloneDX SBOM File")]
    cyclonedx_file: String,
    #[serde(rename = "SPDX SBOM File")]
    spdx_file: String,
    #[serde(rename = "HTML Report File")]
    html_file: String,
    #[serde(rename = "JSON Report File")]
    json_file: String,
    #[serde(rename = "CycloneDX CBOM File")]
    cbom_file: String,
    #[serde(rename = "CBOM HTML Report")]
    cbom_html_file: String,
    #[serde(rename = "Scan Timestamp")]
    timestamp: String,
    #[serde(rename = "Status")]
    status: String,
}

fn print_banner() {
    println!("================================================================================");
    println!("      Multi-Module SBOM & CBOM Automation Engine (Rust)                         ");
    println!("      Compliant with CERT-In / ISO 27001 SBOM & CBOM Guidelines                 ");
    println!("================================================================================");
}

fn print_help() {
    print_banner();
    println!(
        r#"
USAGE:
    bom-scanner [OPTIONS] [SOURCE_DIR] [OUTPUT_DIR]

ARGUMENTS:
    [SOURCE_DIR]    Directory containing modules (default: D:\Vulerability)
    [OUTPUT_DIR]    Directory to save reports (default: D:\Vulerability_SBOM_Reports)

OPTIONS:
    -s, --source <PATH>     Specify source directory containing project modules
    -o, --output <PATH>     Specify output directory for generated SBOMs & reports
    -t, --trivy <PATH>      Specify path to trivy.exe executable
    --template <PATH>       Specify path to HTML report template (default: D:\html.tpl)
    --offline               Run in offline mode using local DB without remote repo queries (default)
    --online                Allow remote Maven repository queries (may trigger rate limits)
    -h, --help              Print this help information
    -v, --version           Print version information

OUTPUT DIRECTORY STRUCTURE:
    <OUTPUT_DIR>/
    ├── CycloneDX/                # CycloneDX v1.7 JSON SBOMs (for OWASP Dependency-Track & CERT-In)
    ├── SPDX/                     # SPDX-JSON SBOMs (ISO/IEC 5230 Standard)
    ├── HTML/                     # Human-readable visual vulnerability reports (<module>.html)
    ├── JSON/                     # Raw Trivy JSON vulnerability & package telemetry
    ├── CBOM/                     # CycloneDX v1.6 CBOM (.cbom.json) & Visual HTML Reports (.html)
    ├── CBOM_Executive_Dashboard.html # Consolidated visual HTML dashboard across all modules
    ├── CBOM_Executive_Register.csv # Comprehensive register of all algorithms, keys, keystores & PQC risks
    └── SBOM_Executive_Summary.csv  # Consolidated executive register across all modules
"#
    );
}

fn parse_args() -> Result<Option<Config>, String> {
    let args: Vec<String> = std::env::args().collect();

    let mut source_opt = None;
    let mut output_opt = None;
    let mut trivy_opt = None;
    let mut tpl_opt = None;
    let mut offline = true;

    let mut positional = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-h" || arg == "--help" {
            print_help();
            return Ok(None);
        } else if arg == "-v" || arg == "--version" {
            println!("bom-scanner v0.2.0 (SBOM & CBOM Automation)");
            return Ok(None);
        } else if arg == "-s" || arg == "--source" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --source".to_string());
            }
            source_opt = Some(PathBuf::from(&args[i]));
        } else if arg == "-o" || arg == "--output" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --output".to_string());
            }
            output_opt = Some(PathBuf::from(&args[i]));
        } else if arg == "-t" || arg == "--trivy" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --trivy".to_string());
            }
            trivy_opt = Some(PathBuf::from(&args[i]));
        } else if arg == "--template" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --template".to_string());
            }
            tpl_opt = Some(PathBuf::from(&args[i]));
        } else if arg == "--offline" {
            offline = true;
        } else if arg == "--online" {
            offline = false;
        } else if !arg.starts_with('-') {
            positional.push(arg.clone());
        } else {
            return Err(format!("Unknown option: {}", arg));
        }
        i += 1;
    }

    // Positional fallbacks
    if source_opt.is_none() && !positional.is_empty() {
        source_opt = Some(PathBuf::from(&positional[0]));
    }
    if output_opt.is_none() && positional.len() > 1 {
        output_opt = Some(PathBuf::from(&positional[1]));
    }

    // Resolve source dir
    let source_dir = source_opt.unwrap_or_else(|| {
        let default_path = PathBuf::from(DEFAULT_SOURCE_DIR);
        if default_path.exists() {
            default_path
        } else {
            PathBuf::from(".")
        }
    });

    // Resolve output dir
    let output_dir = output_opt.unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIR));

    // Resolve trivy path
    let trivy_path = trivy_opt.unwrap_or_else(|| {
        let default_trivy = PathBuf::from(DEFAULT_TRIVY_PATH);
        if default_trivy.exists() {
            default_trivy
        } else {
            PathBuf::from("trivy")
        }
    });

    // Resolve template path
    let template_path = tpl_opt
        .or_else(|| {
            let default_tpl = PathBuf::from(DEFAULT_HTML_TPL);
            if default_tpl.exists() {
                Some(default_tpl)
            } else {
                None
            }
        });

    Ok(Some(Config {
        source_dir,
        output_dir,
        trivy_path,
        template_path,
        offline,
    }))
}

fn is_project_root(dir: &Path) -> bool {
    let manifest_names = [
        "pom.xml",
        "build.xml",
        "build.gradle",
        "build.gradle.kts",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "requirements.txt",
    ];
    for name in &manifest_names {
        if dir.join(name).exists() {
            return true;
        }
    }
    false
}

fn discover_modules(source_dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    if !source_dir.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Source directory '{}' does not exist", source_dir.display()),
        ));
    }

    // If the selected source_dir is itself a project root with a manifest (e.g. pom.xml), scan it directly
    if is_project_root(source_dir) {
        return Ok(vec![source_dir.to_path_buf()]);
    }

    let mut module_dirs = Vec::new();
    let entries = fs::read_dir(source_dir)?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Ignore hidden directories, build artifacts, or source subfolders if any
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" && name != "bin" && name != "build" {
                    module_dirs.push(path);
                }
            }
        }
    }

    // If source_dir has no submodules, treat source_dir itself as single module
    if module_dirs.is_empty() {
        module_dirs.push(source_dir.to_path_buf());
    } else {
        module_dirs.sort();
    }

    Ok(module_dirs)
}

fn extract_error(stderr_bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr_bytes);
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if (trimmed.contains("FATAL") || trimmed.contains("ERROR")) && !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("Scan failed")
        .trim()
        .to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = match parse_args() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return Ok(()),
        Err(err) => {
            eprintln!("Error: {}", err);
            eprintln!("Run 'bom-scanner --help' for usage details.");
            std::process::exit(1);
        }
    };

    print_banner();
    println!(" Configuration:");
    println!("   • Source Directory : {}", config.source_dir.display());
    println!("   • Output Directory : {}", config.output_dir.display());
    println!("   • Trivy Executable : {}", config.trivy_path.display());
    println!(
        "   • Scan Mode        : {}",
        if config.offline {
            "Offline (Protects against 429 rate limits & internal 404s)"
        } else {
            "Online (Queries remote Maven repositories)"
        }
    );
    if let Some(ref tpl) = config.template_path {
        println!("   • HTML Template    : {}", tpl.display());
    } else {
        println!("   • HTML Template    : Not found (fallback to standard table)");
    }
    println!("--------------------------------------------------------------------------------");

    // Verify Trivy
    let trivy_check = Command::new(&config.trivy_path).arg("--version").output();
    match trivy_check {
        Ok(out) if out.status.success() => {
            let ver_str = String::from_utf8_lossy(&out.stdout);
            let first_line = ver_str.lines().next().unwrap_or("Trivy detected");
            println!(" [OK] Trivy Engine Ready: {}", first_line.trim());
        }
        _ => {
            eprintln!(
                " [ERROR] Could not execute Trivy at '{}'. Please verify the path or install Trivy.",
                config.trivy_path.display()
            );
            std::process::exit(1);
        }
    }

    // Discover modules
    let modules = discover_modules(&config.source_dir)?;
    let total_modules = modules.len();
    println!(" [OK] Found {} module(s) to scan.\n", total_modules);

    // Setup output directories
    let cyclonedx_dir = config.output_dir.join("CycloneDX");
    let spdx_dir = config.output_dir.join("SPDX");
    let html_dir = config.output_dir.join("HTML");
    let json_dir = config.output_dir.join("JSON");
    let cbom_dir = config.output_dir.join("CBOM");

    fs::create_dir_all(&cyclonedx_dir)?;
    fs::create_dir_all(&spdx_dir)?;
    fs::create_dir_all(&html_dir)?;
    fs::create_dir_all(&json_dir)?;
    fs::create_dir_all(&cbom_dir)?;

    let mut summary_records: Vec<SummaryRecord> = Vec::with_capacity(total_modules);
    let mut all_crypto_assets: Vec<cbom::CryptoAsset> = Vec::new();

    let mut total_deps_all = 0usize;
    let mut total_critical_all = 0usize;
    let mut total_high_all = 0usize;
    let mut total_medium_all = 0usize;
    let mut total_low_all = 0usize;

    let overall_start = Instant::now();

    for (index, module_path) in modules.iter().enumerate() {
        let module_name = module_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown_module")
            .to_string();

        let mod_start = Instant::now();
        let display_idx = index + 1;

        print!(
            "[{}/{}] Scanning module: {:<32} ... ",
            display_idx, total_modules, module_name
        );

        let cdx_file_name = format!("{}.cdx.json", module_name);
        let spdx_file_name = format!("{}.spdx.json", module_name);
        let html_file_name = format!("{}.html", module_name);
        let json_file_name = format!("{}.json", module_name);
        let cbom_file_name = format!("{}.cbom.json", module_name);
        let cbom_html_file_name = format!("{}.html", module_name);

        let cdx_output = cyclonedx_dir.join(&cdx_file_name);
        let spdx_output = spdx_dir.join(&spdx_file_name);
        let html_output = html_dir.join(&html_file_name);
        let json_output = json_dir.join(&json_file_name);
        let cbom_output = cbom_dir.join(&cbom_file_name);
        let cbom_html_output = cbom_dir.join(&cbom_html_file_name);

        let mut scan_status = "Success".to_string();

        // 1. Generate CycloneDX SBOM (CERT-In standard, with vulnerabilities & licenses)
        let mut cdx_cmd = Command::new(&config.trivy_path);
        cdx_cmd.arg("fs");
        if config.offline {
            cdx_cmd.arg("--offline-scan");
        }
        cdx_cmd.args([
            "--scanners",
            "vuln,license",
            "--format",
            "cyclonedx",
            "--output",
            cdx_output.to_str().unwrap_or_default(),
            module_path.to_str().unwrap_or_default(),
        ]);
        let cdx_res = cdx_cmd.output();

        match &cdx_res {
            Ok(out) if !out.status.success() => {
                let err = extract_error(&out.stderr);
                scan_status = format!("CycloneDX Failed: {}", err);
            }
            Err(e) => {
                scan_status = format!("CycloneDX Launch Failed: {}", e);
            }
            _ => {}
        }

        // 2. Generate SPDX JSON SBOM (SPDX 2.3 standard)
        let mut spdx_cmd = Command::new(&config.trivy_path);
        spdx_cmd.arg("fs");
        if config.offline {
            spdx_cmd.arg("--offline-scan");
        }
        spdx_cmd.args([
            "--format",
            "spdx-json",
            "--output",
            spdx_output.to_str().unwrap_or_default(),
            module_path.to_str().unwrap_or_default(),
        ]);
        let spdx_res = spdx_cmd.output();

        match &spdx_res {
            Ok(out) if !out.status.success() => {
                if scan_status == "Success" {
                    let err = extract_error(&out.stderr);
                    scan_status = format!("SPDX Failed: {}", err);
                }
            }
            Err(e) => {
                if scan_status == "Success" {
                    scan_status = format!("SPDX Launch Failed: {}", e);
                }
            }
            _ => {}
        }

        // 3. Generate Human-Readable HTML report
        let mut html_cmd = Command::new(&config.trivy_path);
        html_cmd.arg("fs");
        if config.offline {
            html_cmd.arg("--offline-scan");
        }
        if let Some(ref tpl) = config.template_path {
            let tpl_arg = format!("@{}", tpl.display());
            html_cmd.args([
                "--scanners",
                "vuln",
                "--format",
                "template",
                "--template",
                &tpl_arg,
                "--output",
                html_output.to_str().unwrap_or_default(),
                module_path.to_str().unwrap_or_default(),
            ]);
        } else {
            // Fallback to table output
            let txt_output = html_dir.join(format!("{}.txt", module_name));
            html_cmd.args([
                "--scanners",
                "vuln",
                "--format",
                "table",
                "--output",
                txt_output.to_str().unwrap_or_default(),
                module_path.to_str().unwrap_or_default(),
            ]);
        }
        let html_res = html_cmd.output();

        match &html_res {
            Ok(out) if !out.status.success() => {
                if scan_status == "Success" {
                    let err = extract_error(&out.stderr);
                    scan_status = format!("HTML Failed: {}", err);
                }
            }
            Err(e) => {
                if scan_status == "Success" {
                    scan_status = format!("HTML Launch Failed: {}", e);
                }
            }
            _ => {}
        }

        // 4. Generate JSON Telemetry (for precise metric parsing and executive register)
        let mut json_cmd = Command::new(&config.trivy_path);
        json_cmd.arg("fs");
        if config.offline {
            json_cmd.arg("--offline-scan");
        }
        json_cmd.args([
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--output",
            json_output.to_str().unwrap_or_default(),
            module_path.to_str().unwrap_or_default(),
        ]);
        let json_res = json_cmd.output();

        match &json_res {
            Ok(out) if !out.status.success() => {
                if scan_status == "Success" {
                    let err = extract_error(&out.stderr);
                    scan_status = format!("JSON Failed: {}", err);
                }
            }
            Err(e) => {
                if scan_status == "Success" {
                    scan_status = format!("JSON Launch Failed: {}", e);
                }
            }
            _ => {}
        }

        // 5. Scan Cryptographic Assets (CBOM) across Java source code and Keystores
        let crypto_assets = cbom::scan_module_for_cbom(module_path, &module_name);
        let crypto_count = crypto_assets.len();
        let cdx_cbom = cbom::generate_cyclonedx_cbom(&module_name, &crypto_assets);
        if let Ok(json_str) = serde_json::to_string_pretty(&cdx_cbom) {
            let _ = fs::write(&cbom_output, json_str);
        }
        let cbom_html = cbom::generate_cbom_html_report(&module_name, &crypto_assets);
        let _ = fs::write(&cbom_html_output, cbom_html);
        all_crypto_assets.extend(crypto_assets);

        // Parse JSON output to aggregate dependency counts and unique CVE severities
        let mut unique_packages: HashSet<String> = HashSet::new();
        let mut unique_vulns: HashMap<String, String> = HashMap::new();

        if json_output.exists() {
            if let Ok(file_content) = fs::read_to_string(&json_output) {
                if let Ok(report) = serde_json::from_str::<TrivyReport>(&file_content) {
                    if let Some(results) = report.results {
                        for res in results {
                            if let Some(pkgs) = res.packages {
                                for p in pkgs {
                                    let key = match (&p.name, &p.version) {
                                        (Some(n), Some(v)) => format!("{}@{}", n, v),
                                        (Some(n), None) => n.clone(),
                                        _ => continue,
                                    };
                                    unique_packages.insert(key);
                                }
                            }
                            if let Some(vulns) = res.vulnerabilities {
                                for v in vulns {
                                    if let Some(vid) = v.id {
                                        let sev = v.severity.unwrap_or_else(|| "UNKNOWN".to_string());
                                        // Keep the highest severity if duplicate
                                        unique_vulns
                                            .entry(vid)
                                            .and_modify(|existing| {
                                                if sev == "CRITICAL" || (sev == "HIGH" && existing != "CRITICAL") {
                                                    *existing = sev.clone();
                                                }
                                            })
                                            .or_insert(sev);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for (_cve, severity) in &unique_vulns {
            match severity.to_uppercase().as_str() {
                "CRITICAL" => critical += 1,
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                "LOW" => low += 1,
                _ => {}
            }
        }

        let dep_count = unique_packages.len();
        let total_vulns = critical + high + medium + low;

        total_deps_all += dep_count;
        total_critical_all += critical;
        total_high_all += high;
        total_medium_all += medium;
        total_low_all += low;

        let elapsed = mod_start.elapsed().as_secs_f32();
        if scan_status != "Success" {
            println!(
                "FAILED ({:.1}s) | {}",
                elapsed, scan_status
            );
        } else {
            println!(
                "Done ({:.1}s) | Deps: {:<3} | Vulns: {:<3} (C:{:<2} H:{:<2} M:{:<2} L:{:<2}) | Crypto: {:<2}",
                elapsed, dep_count, total_vulns, critical, high, medium, low, crypto_count
            );
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        summary_records.push(SummaryRecord {
            module_name,
            dependencies_count: dep_count,
            critical,
            high,
            medium,
            low,
            total_vulns,
            crypto_assets_count: crypto_count,
            cyclonedx_file: format!("CycloneDX/{}", cdx_file_name),
            spdx_file: format!("SPDX/{}", spdx_file_name),
            html_file: format!("HTML/{}", html_file_name),
            json_file: format!("JSON/{}", json_file_name),
            cbom_file: format!("CBOM/{}", cbom_file_name),
            cbom_html_file: format!("CBOM/{}", cbom_html_file_name),
            timestamp,
            status: scan_status,
        });
    }

    // Export Executive CSV Summary
    let summary_csv_path = config.output_dir.join("SBOM_Executive_Summary.csv");
    let mut writer = csv::Writer::from_path(&summary_csv_path)?;
    for record in &summary_records {
        writer.serialize(record)?;
    }
    writer.flush()?;

    // Export Comprehensive CBOM Executive Register
    let cbom_csv_path = config.output_dir.join("CBOM_Executive_Register.csv");
    let mut cbom_writer = csv::Writer::from_path(&cbom_csv_path)?;
    for asset in &all_crypto_assets {
        cbom_writer.serialize(asset)?;
    }
    cbom_writer.flush()?;

    // Export Enterprise CBOM Global Dashboard HTML
    let cbom_dashboard_path = config.output_dir.join("CBOM_Executive_Dashboard.html");
    let cbom_dashboard_html =
        cbom::generate_global_cbom_dashboard(total_modules, &all_crypto_assets);
    let _ = fs::write(&cbom_dashboard_path, cbom_dashboard_html);

    let total_time = overall_start.elapsed().as_secs_f32();
    let total_all_vulns =
        total_critical_all + total_high_all + total_medium_all + total_low_all;

    // Categorize crypto statistics
    let mut pqc_vulnerable_count = 0usize;
    let mut pqc_resistant_count = 0usize;
    let mut legacy_insecure_count = 0usize;
    let mut keystore_count = 0usize;

    for asset in &all_crypto_assets {
        match asset.pqc_risk.as_str() {
            r if r.contains("Quantum-Vulnerable") => pqc_vulnerable_count += 1,
            r if r.contains("Quantum-Resistant") => pqc_resistant_count += 1,
            r if r.contains("Legacy") || r.contains("Insecure") => legacy_insecure_count += 1,
            _ => {
                if asset.primitive.contains("keystore") || asset.primitive.contains("certificate") {
                    keystore_count += 1;
                }
            }
        }
    }

    println!("\n================================================================================");
    println!("                           EXECUTIVE SCAN SUMMARY                               ");
    println!("================================================================================");
    println!(" Total Modules Scanned        : {}", total_modules);
    println!(" Total Dependencies Tracked   : {}", total_deps_all);
    println!(" Total Vulnerabilities        : {}", total_all_vulns);
    println!("   • Critical                 : {}", total_critical_all);
    println!("   • High                     : {}", total_high_all);
    println!("   • Medium                   : {}", total_medium_all);
    println!("   • Low                      : {}", total_low_all);
    println!("--------------------------------------------------------------------------------");
    println!(" Cryptographic Assets (CBOM)  : {}", all_crypto_assets.len());
    println!("   • Quantum-Resistant (AES/SHA) : {}", pqc_resistant_count);
    println!("   • Quantum-Vulnerable (RSA/ECC): {}", pqc_vulnerable_count);
    println!("   • Keystores & Certificates    : {}", keystore_count);
    println!("   • Legacy / Insecure (MD5/DES) : {}", legacy_insecure_count);
    println!(" Total Execution Time         : {:.1} seconds", total_time);
    println!("--------------------------------------------------------------------------------");
    println!(" Generated Artifacts:");
    println!("   • CycloneDX SBOMs (CERT-In)   : {}", cyclonedx_dir.display());
    println!("   • SPDX SBOMs (ISO/IEC 5230)   : {}", spdx_dir.display());
    println!("   • HTML Visual Reports         : {}", html_dir.display());
    println!("   • JSON Telemetry              : {}", json_dir.display());
    println!("   • CycloneDX 1.6 CBOMs         : {}", cbom_dir.display());
    println!("   • CBOM Visual HTML Reports    : {}", cbom_dir.display());
    println!("   • Enterprise CBOM Dashboard   : {}", cbom_dashboard_path.display());
    println!("   • CBOM Executive Register     : {}", cbom_csv_path.display());
    println!("   • SBOM Executive Summary CSV  : {}", summary_csv_path.display());
    println!("================================================================================");

    Ok(())
}
