mod cbom;

use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const EMBEDDED_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
{{- if . }}
    <style>
      * { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
      body { margin: 24px; background: #f8fafc; color: #0f172a; }
      h1 { text-align: center; font-size: 26px; margin-bottom: 24px; color: #0f172a; }
      table { border-collapse: collapse; width: 100%; max-width: 1500px; margin: 0 auto 32px auto; box-shadow: 0 1px 3px rgba(0,0,0,0.08); background: #ffffff; border-radius: 8px; overflow: hidden; }
      table, th, td { border: 1px solid #e2e8f0; }
      th { padding: 12px 14px; text-align: left; }
      td { padding: 10px 14px; }
      .group-header th { font-size: 130%; background: #0f172a; color: #ffffff; }
      .sub-header th { font-size: 100%; background: #f1f5f9; color: #334155; font-weight: 600; }
      .severity { text-align: center; font-weight: 600; color: #ffffff; border-radius: 9999px; padding: 3px 10px; display: inline-block; font-size: 11px; }
      .severity-LOW .severity { background-color: #16a34a; }
      .severity-MEDIUM .severity { background-color: #d97706; }
      .severity-HIGH .severity { background-color: #ea580c; }
      .severity-CRITICAL .severity { background-color: #dc2626; }
      .severity-UNKNOWN .severity { background-color: #64748b; }
      .severity-LOW { background-color: #f0fdf4; }
      .severity-MEDIUM { background-color: #fffbeb; }
      .severity-HIGH { background-color: #fff7ed; }
      .severity-CRITICAL { background-color: #fef2f2; }
      .severity-UNKNOWN { background-color: #f8fafc; }
      .pkg-name { font-weight: 600; }
      .links a { display: block; color: #2563eb; text-decoration: none; font-size: 11px; margin-bottom: 2px; }
      .links a:hover { text-decoration: underline; }
    </style>
    <title>{{- escapeXML ( index . 0 ).Target }} - Security & Vulnerability Assessment</title>
  </head>
  <body>
    <h1>{{- escapeXML ( index . 0 ).Target }} - Security & Vulnerability Assessment</h1>
    <table>
    {{- range . }}
      <tr class="group-header"><th colspan="6">{{ .Type | toString | escapeXML }} (Target: {{ .Target | toString | escapeXML }})</th></tr>
      {{- if (eq (len .Vulnerabilities) 0) }}
      <tr><th colspan="6" style="padding: 14px; color: #16a34a; font-weight: 500;">✓ No Known Vulnerabilities detected</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>References</th>
      </tr>
        {{- range .Vulnerabilities }}
      <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
        <td class="pkg-name">{{ escapeXML .PkgName }}</td>
        <td><strong>{{ escapeXML .VulnerabilityID }}</strong></td>
        <td><span class="severity">{{ escapeXML .Vulnerability.Severity }}</span></td>
        <td>{{ escapeXML .InstalledVersion }}</td>
        <td>{{ escapeXML .FixedVersion }}</td>
        <td class="links">
          {{- range .Vulnerability.References }}
          <a href={{ escapeXML . | printf "%q" }} target="_blank">{{ escapeXML . }}</a>
          {{- end }}
        </td>
      </tr>
        {{- end }}
      {{- end }}
      {{- if (eq (len .Misconfigurations ) 0) }}
      {{- else }}
      <tr class="sub-header">
        <th>Type</th>
        <th>Misconfig ID</th>
        <th>Title</th>
        <th>Severity</th>
        <th colspan="2">Details & Remediation</th>
      </tr>
        {{- range .Misconfigurations }}
      <tr class="severity-{{ escapeXML .Severity }}">
        <td>{{ escapeXML .Type }}</td>
        <td><strong>{{ escapeXML .ID }}</strong></td>
        <td>{{ escapeXML .Title }}</td>
        <td><span class="severity">{{ escapeXML .Severity }}</span></td>
        <td colspan="2" style="white-space: normal;">
          {{ escapeXML .Message }}
          {{- if .PrimaryURL }}
          <br><a href={{ escapeXML .PrimaryURL | printf "%q" }} target="_blank" style="color: #2563eb; font-size: 11px;">{{ escapeXML .PrimaryURL }}</a>
          {{- end }}
        </td>
      </tr>
        {{- end }}
      {{- end }}
      {{- if (eq (len .Secrets ) 0) }}
      {{- else }}
      <tr class="sub-header">
        <th>Type</th>
        <th>Rule ID</th>
        <th>Secret Finding</th>
        <th>Severity</th>
        <th colspan="2">Line Location</th>
      </tr>
        {{- range .Secrets }}
      <tr class="severity-{{ escapeXML .Severity }}">
        <td>Secret Exposure</td>
        <td><strong>{{ escapeXML .RuleID }}</strong></td>
        <td>{{ escapeXML .Title }}</td>
        <td><span class="severity">{{ escapeXML .Severity }}</span></td>
        <td colspan="2">{{ escapeXML .StartLine }}:{{ escapeXML .EndLine }}</td>
      </tr>
        {{- end }}
      {{- end }}
    {{- end }}
    </table>
{{- else }}
  </head>
  <body>
    <h1>Security Assessment: No Findings</h1>
{{- end }}
  </body>
</html>
"#;

#[derive(Debug)]
struct Config {
    source_dir: PathBuf,
    sbom_dir: PathBuf,
    cbom_dir: PathBuf,
    trivy_path: PathBuf,
    template_path: PathBuf,
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
    #[serde(rename = "Misconfigurations")]
    misconfigurations: Option<Vec<TrivyMisconfiguration>>,
    #[serde(rename = "Secrets")]
    secrets: Option<Vec<TrivySecret>>,
}

#[derive(Debug, Deserialize)]
struct TrivyPackage {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Licenses")]
    licenses: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    id: Option<String>,
    #[serde(rename = "Severity")]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrivyMisconfiguration {
    #[serde(rename = "ID")]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrivySecret {
    #[serde(rename = "RuleID")]
    rule_id: Option<String>,
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
    #[serde(rename = "Misconfigurations")]
    misconfigs_count: usize,
    #[serde(rename = "Secrets Exposed")]
    secrets_count: usize,
    #[serde(rename = "Licenses Tracked")]
    licenses_count: usize,
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

fn is_runnable(path: &Path) -> bool {
    Command::new(path)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn download_and_extract_trivy(target_exe: &Path) -> Result<(), String> {
    let parent = target_exe.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;

    let version = "0.66.0";

    #[cfg(windows)]
    {
        let url = format!(
            "https://github.com/aquasecurity/trivy/releases/download/v{}/trivy_{}_windows-64bit.zip",
            version, version
        );
        println!(" [DOWNLOAD] Fetching Trivy v{} for Windows...", version);

        let ps_cmd = format!(
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
             $zip = Join-Path $env:TEMP 'trivy_setup.zip'; \
             Invoke-WebRequest -Uri '{}' -OutFile $zip -UseBasicParsing; \
             Expand-Archive -Path $zip -DestinationPath '{}' -Force; \
             Remove-Item $zip -Force",
            url, parent.display()
        );

        let status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_cmd])
            .status()
            .map_err(|e| format!("Failed to launch PowerShell downloader: {}", e))?;

        if !status.success() {
            return Err("PowerShell failed to download and extract Trivy.".to_string());
        }
    }

    #[cfg(not(windows))]
    {
        let os_str = if cfg!(target_os = "macos") { "macOS" } else { "Linux" };
        let arch_str = if cfg!(target_arch = "aarch64") { "ARM64" } else { "64bit" };
        let url = format!(
            "https://github.com/aquasecurity/trivy/releases/download/v{}/trivy_{}_{}-{}.tar.gz",
            version, version, os_str, arch_str
        );
        println!(" [DOWNLOAD] Fetching Trivy v{} for {}...", version, os_str);

        let sh_cmd = format!(
            "curl -sSL '{}' | tar -xz -C '{}' trivy && chmod +x '{}'",
            url, parent.display(), target_exe.display()
        );

        let status = Command::new("sh")
            .args(["-c", &sh_cmd])
            .status()
            .map_err(|e| format!("Failed to launch curl/tar downloader: {}", e))?;

        if !status.success() {
            return Err("Failed to download and extract Trivy via curl/tar.".to_string());
        }
    }

    Ok(())
}

fn ensure_trivy(custom_path: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = custom_path {
        if is_runnable(&p) {
            return Ok(p);
        }
    }

    if is_runnable(Path::new("trivy")) {
        return Ok(PathBuf::from("trivy"));
    }

    if let Ok(env_val) = std::env::var("TRIVY_PATH") {
        let p = PathBuf::from(env_val);
        if is_runnable(&p) {
            return Ok(p);
        }
    }

    let known_candidates = [
        PathBuf::from("/opt/bin/trivy"),
        PathBuf::from("/usr/local/bin/trivy"),
        PathBuf::from("/usr/bin/trivy"),
        PathBuf::from(r"D:\trivy.exe"),
        PathBuf::from(r"C:\opt\bin\trivy.exe"),
        PathBuf::from(r"C:\Program Files\trivy\trivy.exe"),
        PathBuf::from(r"C:\ProgramData\chocolatey\bin\trivy.exe"),
        PathBuf::from(r"C:\trivy.exe"),
    ];
    for c in &known_candidates {
        if c.exists() && is_runnable(c) {
            return Ok(c.clone());
        }
    }

    let local_bin = if let Ok(exe) = std::env::current_exe() {
        exe.parent().unwrap_or(Path::new(".")).join("bin")
    } else {
        PathBuf::from("./bin")
    };
    let app_trivy = if cfg!(windows) {
        local_bin.join("trivy.exe")
    } else {
        local_bin.join("trivy")
    };
    if app_trivy.exists() && is_runnable(&app_trivy) {
        return Ok(app_trivy);
    }

    // Auto-download and install Trivy as part of the application
    println!("--------------------------------------------------------------------------------");
    println!(" [INFO] Trivy security engine is not detected on this system.");
    println!(" [INFO] Automatically downloading and configuring Trivy as part of the application...");

    let target_bin = if cfg!(windows) {
        let opt_bin = PathBuf::from(r"C:\opt\bin");
        if fs::create_dir_all(&opt_bin).is_ok() {
            opt_bin.join("trivy.exe")
        } else {
            let _ = fs::create_dir_all(&local_bin);
            local_bin.join("trivy.exe")
        }
    } else {
        let opt_bin = PathBuf::from("/opt/bin");
        if fs::create_dir_all(&opt_bin).is_ok() {
            opt_bin.join("trivy")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let user_bin = PathBuf::from(home).join(".local/bin");
            let _ = fs::create_dir_all(&user_bin);
            user_bin.join("trivy")
        }
    };

    download_and_extract_trivy(&target_bin)?;

    if is_runnable(&target_bin) {
        println!(" [OK] Trivy ready at: {}", target_bin.display());
        println!("--------------------------------------------------------------------------------");
        Ok(target_bin)
    } else {
        Err(format!(
            "Failed to execute Trivy after installation at '{}'",
            target_bin.display()
        ))
    }
}

fn ensure_template(custom_path: Option<PathBuf>) -> PathBuf {
    if let Some(p) = custom_path {
        if p.exists() {
            return p;
        }
    }

    let opt_tpl = PathBuf::from("/opt/html.tpl");
    if opt_tpl.exists() {
        return opt_tpl;
    }

    let candidates = [
        PathBuf::from("/opt/templates/html.tpl"),
        PathBuf::from(r"D:\html.tpl"),
        PathBuf::from("./html.tpl"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }

    // Auto-write embedded template to /opt/html.tpl
    if let Some(parent) = opt_tpl.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(&opt_tpl, EMBEDDED_HTML_TEMPLATE).is_ok() {
        return opt_tpl;
    }

    // Fallback: write to temp directory
    let temp_tpl = std::env::temp_dir().join("bom_trivy_html.tpl");
    let _ = fs::write(&temp_tpl, EMBEDDED_HTML_TEMPLATE);
    temp_tpl
}

fn default_source_dir() -> PathBuf {
    let opt_repo = PathBuf::from("/opt/repository");
    if opt_repo.exists() {
        return opt_repo;
    }
    let win_legacy = PathBuf::from(r"D:\Vulerability
    ");
    if win_legacy.exists() {
        return win_legacy;
    }
    PathBuf::from("/opt/repository")
}

fn prompt_line(label: &str, default_val: Option<&str>) -> String {
    print!("{}", label);
    if let Some(def) = default_val {
        print!(" [default: {}]", def);
    }
    print!(": ");
    let _ = io::stdout().flush();

    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_ok() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            default_val.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        default_val.unwrap_or("").to_string()
    }
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

    If run without arguments, bom-scanner launches an interactive configuration
    wizard with smart defaults (/opt/repository, /opt/bom/sbom, /opt/bom/cbom).

ARGUMENTS:
    [SOURCE_DIR]    Directory containing modules (default: /opt/repository)
    [OUTPUT_DIR]    Base directory to save reports (default: /opt/bom -> /opt/bom/sbom & /opt/bom/cbom)

OPTIONS:
    -s, --source <PATH>     Specify source directory containing project modules (default: /opt/repository)
    -o, --output <PATH>     Specify base output directory (creates <PATH>/sbom and <PATH>/cbom)
    --sbom-dir <PATH>       Specify custom directory for SBOM reports (default: /opt/bom/sbom)
    --cbom-dir <PATH>       Specify custom directory for CBOM reports (default: /opt/bom/cbom)
    -t, --trivy <PATH>      Specify path to trivy executable (auto-installed if omitted)
    --template <PATH>       Specify path to HTML report template (default: /opt/html.tpl, auto-embedded)
    --offline               Run in offline mode using local DB without remote repo queries (default)
    --online                Allow remote Maven repository queries (may trigger rate limits)
    -i, --interactive       Force interactive configuration wizard
    -y, --batch             Non-interactive batch mode (accept all defaults without prompt)
    -h, --help              Print this help information
    -v, --version           Print version information

OUTPUT DIRECTORY STRUCTURE:
    /opt/bom/
    ├── sbom/                     # Software Bill of Materials & Security Findings
    │   ├── CycloneDX/            # CycloneDX v1.7 JSON SBOMs (vuln, misconfig, secret, license)
    │   ├── SPDX/                 # SPDX-JSON SBOMs (ISO/IEC 5230 Standard)
    │   ├── HTML/                 # Visual vulnerability & assessment reports (<module>.html)
    │   ├── JSON/                 # Comprehensive Trivy telemetry (--list-all-pkgs)
    │   └── SBOM_Executive_Summary.csv # Consolidated executive register across all modules
    └── cbom/                     # Cryptographic Bill of Materials & PQC Governance
        ├── <module>.cbom.json    # CycloneDX 1.6 Cryptographic Bills of Materials
        ├── <module>.html         # Interactive visual CBOM reports
        ├── CBOM_Executive_Dashboard.html # Consolidated enterprise-wide visual CBOM dashboard
        └── CBOM_Executive_Register.csv # Comprehensive register of all algorithms, keys & PQC risks
"#
    );
}

fn parse_args() -> Result<Option<Config>, String> {
    let args: Vec<String> = std::env::args().collect();

    let mut source_opt: Option<PathBuf> = None;
    let mut output_opt: Option<PathBuf> = None;
    let mut sbom_opt: Option<PathBuf> = None;
    let mut cbom_opt: Option<PathBuf> = None;
    let mut trivy_opt: Option<PathBuf> = None;
    let mut tpl_opt: Option<PathBuf> = None;
    let mut offline = true;
    let mut force_interactive = false;
    let mut force_batch = false;

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
        } else if arg == "--sbom-dir" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --sbom-dir".to_string());
            }
            sbom_opt = Some(PathBuf::from(&args[i]));
        } else if arg == "--cbom-dir" {
            i += 1;
            if i >= args.len() {
                return Err("Missing argument for --cbom-dir".to_string());
            }
            cbom_opt = Some(PathBuf::from(&args[i]));
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
        } else if arg == "-i" || arg == "--interactive" {
            force_interactive = true;
        } else if arg == "-y" || arg == "--batch" {
            force_batch = true;
        } else if arg == "--offline" {
            offline = true;
        } else if arg == "--online" {
            offline = false;
        } else if !arg.starts_with('-') {
            positional.push(PathBuf::from(arg));
        } else {
            return Err(format!("Unknown option: {}", arg));
        }
        i += 1;
    }

    // Positional fallbacks
    if source_opt.is_none() && !positional.is_empty() {
        source_opt = Some(positional[0].clone());
    }
    if output_opt.is_none() && positional.len() > 1 {
        output_opt = Some(positional[1].clone());
    }

    let has_explicit_args = source_opt.is_some()
        || output_opt.is_some()
        || sbom_opt.is_some()
        || cbom_opt.is_some()
        || trivy_opt.is_some()
        || tpl_opt.is_some()
        || !positional.is_empty();

    let should_prompt = (force_interactive || !has_explicit_args) && !force_batch;

    if should_prompt {
        print_banner();
        println!(" Interactive Mode: Configure scan parameters");
        println!(" (Press [Enter] to accept the suggested default in brackets)\n");

        // 1. Source Directory
        let default_source = source_opt.unwrap_or_else(default_source_dir);
        let src_str = prompt_line(
            " [1/5] Source directory containing project modules",
            Some(default_source.to_str().unwrap_or("/opt/repository")),
        );
        let source_dir = PathBuf::from(src_str);

        // 2. Output Directories
        let default_sbom = sbom_opt.unwrap_or_else(|| PathBuf::from("/opt/bom/sbom"));
        let sbom_str = prompt_line(
            " [2/5] SBOM output directory",
            Some(default_sbom.to_str().unwrap_or("/opt/bom/sbom")),
        );
        let sbom_dir = PathBuf::from(sbom_str);

        let default_cbom = cbom_opt.unwrap_or_else(|| PathBuf::from("/opt/bom/cbom"));
        let cbom_str = prompt_line(
            " [3/5] CBOM output directory",
            Some(default_cbom.to_str().unwrap_or("/opt/bom/cbom")),
        );
        let cbom_dir = PathBuf::from(cbom_str);

        // 4. HTML Template
        let default_tpl = tpl_opt.unwrap_or_else(|| PathBuf::from("/opt/html.tpl"));
        let tpl_str = prompt_line(
            " [4/5] HTML report template path",
            Some(default_tpl.to_str().unwrap_or("/opt/html.tpl")),
        );
        let template_path = PathBuf::from(tpl_str);

        // 5. Scan Mode
        let offline_str = prompt_line(
            " [5/5] Run in offline mode (recommended, prevents rate limits)? [Y/n]",
            Some("Y"),
        );
        let is_offline = !offline_str.trim().eq_ignore_ascii_case("n");

        println!();

        let trivy_path = ensure_trivy(trivy_opt)?;
        let resolved_tpl = ensure_template(Some(template_path));

        return Ok(Some(Config {
            source_dir,
            sbom_dir,
            cbom_dir,
            trivy_path,
            template_path: resolved_tpl,
            offline: is_offline,
        }));
    }

    // Non-interactive (CLI flags provided or --batch specified)
    let source_dir = source_opt.unwrap_or_else(default_source_dir);

    let (sbom_dir, cbom_dir) = match (sbom_opt, cbom_opt) {
        (Some(s), Some(c)) => (s, c),
        (Some(s), None) => (s, PathBuf::from("/opt/bom/cbom")),
        (None, Some(c)) => (PathBuf::from("/opt/bom/sbom"), c),
        (None, None) => {
            if let Some(base_out) = output_opt {
                (base_out.join("sbom"), base_out.join("cbom"))
            } else {
                (PathBuf::from("/opt/bom/sbom"), PathBuf::from("/opt/bom/cbom"))
            }
        }
    };

    let trivy_path = ensure_trivy(trivy_opt)?;
    let template_path = ensure_template(tpl_opt);

    Ok(Some(Config {
        source_dir,
        sbom_dir,
        cbom_dir,
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

    if is_project_root(source_dir) {
        return Ok(vec![source_dir.to_path_buf()]);
    }

    let mut module_dirs = Vec::new();
    let entries = fs::read_dir(source_dir)?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" && name != "bin" && name != "build" {
                    module_dirs.push(path);
                }
            }
        }
    }

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
    println!("   • SBOM Directory   : {}", config.sbom_dir.display());
    println!("   • CBOM Directory   : {}", config.cbom_dir.display());
    println!("   • Trivy Engine     : {}", config.trivy_path.display());
    println!("   • HTML Template    : {}", config.template_path.display());
    println!(
        "   • Scan Mode        : {}",
        if config.offline {
            "Offline (Protects against 429 rate limits & internal 404s)"
        } else {
            "Online (Queries remote Maven repositories)"
        }
    );
    println!("--------------------------------------------------------------------------------");

    // Discover modules
    let modules = discover_modules(&config.source_dir)?;
    let total_modules = modules.len();
    println!(" [OK] Found {} module(s) to scan.\n", total_modules);

    // Setup output directories
    let cyclonedx_dir = config.sbom_dir.join("CycloneDX");
    let spdx_dir = config.sbom_dir.join("SPDX");
    let html_dir = config.sbom_dir.join("HTML");
    let json_dir = config.sbom_dir.join("JSON");

    fs::create_dir_all(&cyclonedx_dir)?;
    fs::create_dir_all(&spdx_dir)?;
    fs::create_dir_all(&html_dir)?;
    fs::create_dir_all(&json_dir)?;
    fs::create_dir_all(&config.cbom_dir)?;

    let mut summary_records: Vec<SummaryRecord> = Vec::with_capacity(total_modules);
    let mut all_crypto_assets: Vec<cbom::CryptoAsset> = Vec::new();

    let mut total_deps_all = 0usize;
    let mut total_critical_all = 0usize;
    let mut total_high_all = 0usize;
    let mut total_medium_all = 0usize;
    let mut total_low_all = 0usize;
    let mut total_misconfigs_all = 0usize;
    let mut total_secrets_all = 0usize;
    let mut total_licenses_all = 0usize;

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
        let cbom_output = config.cbom_dir.join(&cbom_file_name);
        let cbom_html_output = config.cbom_dir.join(&cbom_html_file_name);

        let mut scan_status = "Success".to_string();

        // 1. Generate CycloneDX SBOM (with all scanners & comprehensive priority)
        let mut cdx_cmd = Command::new(&config.trivy_path);
        cdx_cmd.arg("fs");
        if config.offline {
            cdx_cmd.arg("--offline-scan");
        }
        cdx_cmd.args([
            "--scanners",
            "vuln,misconfig,secret,license",
            "--detection-priority",
            "comprehensive",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--parallel",
            "0",
            "--skip-version-check",
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

        // 2. Generate SPDX JSON SBOM (ISO/IEC 5230 Standard with comprehensive scanners)
        let mut spdx_cmd = Command::new(&config.trivy_path);
        spdx_cmd.arg("fs");
        if config.offline {
            spdx_cmd.arg("--offline-scan");
        }
        spdx_cmd.args([
            "--scanners",
            "vuln,misconfig,secret,license",
            "--detection-priority",
            "comprehensive",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--parallel",
            "0",
            "--skip-version-check",
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

        // 3. Generate Human-Readable HTML report using embedded/configured template
        let mut html_cmd = Command::new(&config.trivy_path);
        html_cmd.arg("fs");
        if config.offline {
            html_cmd.arg("--offline-scan");
        }
        let tpl_arg = format!("@{}", config.template_path.display());
        html_cmd.args([
            "--scanners",
            "vuln,misconfig,secret,license",
            "--detection-priority",
            "comprehensive",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--parallel",
            "0",
            "--skip-version-check",
            "--format",
            "template",
            "--template",
            &tpl_arg,
            "--output",
            html_output.to_str().unwrap_or_default(),
            module_path.to_str().unwrap_or_default(),
        ]);
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

        // 4. Generate JSON Telemetry (with --list-all-pkgs, misconfig, secret & license discovery)
        let mut json_cmd = Command::new(&config.trivy_path);
        json_cmd.arg("fs");
        if config.offline {
            json_cmd.arg("--offline-scan");
        }
        json_cmd.args([
            "--scanners",
            "vuln,misconfig,secret,license",
            "--list-all-pkgs",
            "--detection-priority",
            "comprehensive",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--parallel",
            "0",
            "--skip-version-check",
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

        // Parse JSON output to aggregate dependency counts, CVEs, misconfigs, secrets & licenses
        let mut unique_packages: HashSet<String> = HashSet::new();
        let mut unique_vulns: HashMap<String, String> = HashMap::new();
        let mut unique_misconfigs: HashSet<String> = HashSet::new();
        let mut unique_secrets: HashSet<String> = HashSet::new();
        let mut unique_licenses: HashSet<String> = HashSet::new();

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
                                    if let Some(lics) = p.licenses {
                                        for lic in lics {
                                            unique_licenses.insert(lic);
                                        }
                                    }
                                }
                            }
                            if let Some(vulns) = res.vulnerabilities {
                                for v in vulns {
                                    if let Some(vid) = v.id {
                                        let sev = v.severity.unwrap_or_else(|| "UNKNOWN".to_string());
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
                            if let Some(misconfs) = res.misconfigurations {
                                for m in misconfs {
                                    if let Some(mid) = m.id {
                                        unique_misconfigs.insert(mid);
                                    }
                                }
                            }
                            if let Some(sec_list) = res.secrets {
                                for s in sec_list {
                                    if let Some(rule) = s.rule_id {
                                        unique_secrets.insert(rule);
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
        let misconfig_count = unique_misconfigs.len();
        let secret_count = unique_secrets.len();
        let license_count = unique_licenses.len();

        total_deps_all += dep_count;
        total_critical_all += critical;
        total_high_all += high;
        total_medium_all += medium;
        total_low_all += low;
        total_misconfigs_all += misconfig_count;
        total_secrets_all += secret_count;
        total_licenses_all += license_count;

        let elapsed = mod_start.elapsed().as_secs_f32();
        if scan_status != "Success" {
            println!(
                "FAILED ({:.1}s) | {}",
                elapsed, scan_status
            );
        } else {
            println!(
                "Done ({:.1}s) | Deps: {:<3} | Vulns: {:<3} (C:{:<2} H:{:<2} M:{:<2} L:{:<2}) | Misconf: {:<2} | Secret: {:<2} | Crypto: {:<2}",
                elapsed, dep_count, total_vulns, critical, high, medium, low, misconfig_count, secret_count, crypto_count
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
            misconfigs_count: misconfig_count,
            secrets_count: secret_count,
            licenses_count: license_count,
            crypto_assets_count: crypto_count,
            cyclonedx_file: format!("CycloneDX/{}", cdx_file_name),
            spdx_file: format!("SPDX/{}", spdx_file_name),
            html_file: format!("HTML/{}", html_file_name),
            json_file: format!("JSON/{}", json_file_name),
            cbom_file: format!("{}/{}", config.cbom_dir.display(), cbom_file_name),
            cbom_html_file: format!("{}/{}", config.cbom_dir.display(), cbom_html_file_name),
            timestamp,
            status: scan_status,
        });
    }

    // Export Executive CSV Summary in SBOM directory
    let summary_csv_path = config.sbom_dir.join("SBOM_Executive_Summary.csv");
    let mut writer = csv::Writer::from_path(&summary_csv_path)?;
    for record in &summary_records {
        writer.serialize(record)?;
    }
    writer.flush()?;

    // Export Comprehensive CBOM Executive Register in CBOM directory
    let cbom_csv_path = config.cbom_dir.join("CBOM_Executive_Register.csv");
    let mut cbom_writer = csv::Writer::from_path(&cbom_csv_path)?;
    for asset in &all_crypto_assets {
        cbom_writer.serialize(asset)?;
    }
    cbom_writer.flush()?;

    // Export Enterprise CBOM Global Dashboard HTML in CBOM directory
    let cbom_dashboard_path = config.cbom_dir.join("CBOM_Executive_Dashboard.html");
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
    println!(" Security Misconfigurations   : {}", total_misconfigs_all);
    println!(" Exposed Secrets / Keys       : {}", total_secrets_all);
    println!(" Software Licenses Tracked    : {}", total_licenses_all);
    println!("--------------------------------------------------------------------------------");
    println!(" Cryptographic Assets (CBOM)  : {}", all_crypto_assets.len());
    println!("   • Quantum-Resistant (AES/SHA) : {}", pqc_resistant_count);
    println!("   • Quantum-Vulnerable (RSA/ECC): {}", pqc_vulnerable_count);
    println!("   • Keystores & Certificates    : {}", keystore_count);
    println!("   • Legacy / Insecure (MD5/DES) : {}", legacy_insecure_count);
    println!(" Total Execution Time         : {:.1} seconds", total_time);
    println!("--------------------------------------------------------------------------------");
    println!(" Generated Artifacts:");
    println!("   • SBOM Directory              : {}", config.sbom_dir.display());
    println!("     ├── CycloneDX SBOMs         : {}", cyclonedx_dir.display());
    println!("     ├── SPDX SBOMs (ISO/IEC 5230): {}", spdx_dir.display());
    println!("     ├── HTML Visual Reports     : {}", html_dir.display());
    println!("     ├── JSON Telemetry          : {}", json_dir.display());
    println!("     └── Executive Summary CSV   : {}", summary_csv_path.display());
    println!("   • CBOM Directory              : {}", config.cbom_dir.display());
    println!("     ├── CycloneDX 1.6 CBOMs     : {}", config.cbom_dir.display());
    println!("     ├── CBOM Visual HTML Reports: {}", config.cbom_dir.display());
    println!("     ├── Executive Dashboard     : {}", cbom_dashboard_path.display());
    println!("     └── Executive Register CSV  : {}", cbom_csv_path.display());
    println!("================================================================================");

    Ok(())
}
