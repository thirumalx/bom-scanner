use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct CryptoAsset {
    #[serde(rename = "Module Name")]
    pub module_name: String,
    #[serde(rename = "Asset Name")]
    pub asset_name: String,
    #[serde(rename = "Asset Type")]
    pub asset_type: String, // algorithm, certificate, protocol, related-crypto-material
    #[serde(rename = "Primitive / Function")]
    pub primitive: String, // block-cipher, public-key-encryption, asymmetric-signature, message-digest, mac, keystore, protocol
    #[serde(rename = "Algorithm Mode")]
    pub mode: String, // CBC, GCM, ECB, etc.
    #[serde(rename = "Padding Scheme")]
    pub padding: String, // PKCS5Padding, PKCS1Padding, etc.
    #[serde(rename = "Classical Security")]
    pub classical_security: String,
    #[serde(rename = "Post-Quantum Risk (PQC)")]
    pub pqc_risk: String, // Quantum-Resistant, Quantum-Vulnerable (Shor's), Legacy / Insecure
    #[serde(rename = "Detection Source")]
    pub detection_source: String, // Source code path or Keystore file path
    #[serde(rename = "Line Number")]
    pub line_number: usize,
    #[serde(rename = "Code Snippet / Description")]
    pub snippet: String,
    #[serde(rename = "Compliance & Guidance")]
    pub guidance: String,
}

// CycloneDX 1.6 CBOM Data Structures (Fully aligned with CycloneDX 1.6 & backward-compatible)
#[derive(Debug, Serialize)]
pub struct CycloneDxCbom {
    #[serde(rename = "$schema")]
    pub schema: String,
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CbomMetadata,
    pub components: Vec<CbomComponent>,
    #[serde(rename = "dependencies", skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<CbomDependency>>,
}

#[derive(Debug, Serialize)]
pub struct CbomMetadata {
    pub timestamp: String,
    pub component: CbomRootComponent,
}

#[derive(Debug, Serialize)]
pub struct CbomRootComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub comp_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CbomComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub comp_type: String, // "cryptographic-asset"
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: CryptoProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<CbomProperty>>,
}

#[derive(Debug, Serialize)]
pub struct CbomProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct CbomDependency {
    #[serde(rename = "ref")]
    pub ref_id: String,
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: String, // "algorithm", "certificate", "protocol", "related-crypto-material"
    #[serde(rename = "algorithmProperties", skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(rename = "detectionContext")]
    pub detection_context: DetectionContext,
}

#[derive(Debug, Serialize)]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(rename = "parameterSetIdentifier", skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    #[serde(rename = "classicalSecurityLevel")]
    pub classical_security_level: u32,
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: u32,
}

#[derive(Debug, Serialize)]
pub struct DetectionContext {
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "lineNumber")]
    pub line_number: usize,
    #[serde(rename = "snippet")]
    pub snippet: String,
    #[serde(rename = "postQuantumRisk")]
    pub post_quantum_risk: String,
}

static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

fn get_patterns() -> &'static Vec<(Regex, &'static str)> {
    PATTERNS.get_or_init(|| {
        let raw = vec![
            (
                r#"(?:Cipher|javax\.crypto\.Cipher)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "Cipher",
            ),
            (
                r#"(?:Signature|java\.security\.Signature)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "Signature",
            ),
            (
                r#"(?:MessageDigest|java\.security\.MessageDigest)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "MessageDigest",
            ),
            (
                r#"(?:Mac|javax\.crypto\.Mac)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "Mac",
            ),
            (
                r#"(?:KeyGenerator|javax\.crypto\.KeyGenerator)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "KeyGenerator",
            ),
            (
                r#"(?:KeyPairGenerator|java\.security\.KeyPairGenerator)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "KeyPairGenerator",
            ),
            (
                r#"(?:SecretKeyFactory|javax\.crypto\.SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "SecretKeyFactory",
            ),
            (
                r#"(?:KeyAgreement|javax\.crypto\.KeyAgreement)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "KeyAgreement",
            ),
            (
                r#"(?:KeyStore|java\.security\.KeyStore)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "KeyStore",
            ),
            (
                r#"(?:SSLContext|javax\.net\.ssl\.SSLContext)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "SSLContext",
            ),
            (
                r#"(?:CertificateFactory|java\.security\.cert\.CertificateFactory)\s*\.\s*getInstance\s*\(\s*"([^"]+)""#,
                "CertificateFactory",
            ),
        ];

        raw.into_iter()
            .filter_map(|(pat, cat)| Regex::new(pat).ok().map(|r| (r, cat)))
            .collect()
    })
}

fn classify_crypto(
    category: &str,
    raw_algo: &str,
) -> (
    String, // primitive
    String, // mode
    String, // padding
    String, // classical_security
    String, // pqc_risk
    String, // guidance
    u32,    // classical_bits
    u32,    // nist_quantum_level (0 = vulnerable/insecure, 1-5 = quantum safe)
) {
    let parts: Vec<&str> = raw_algo.split('/').collect();
    let base = parts[0].trim();
    let mode = parts.get(1).map(|s| s.trim()).unwrap_or("None").to_string();
    let padding = parts.get(2).map(|s| s.trim()).unwrap_or("None").to_string();

    let base_upper = base.to_uppercase();

    // 1. Digital Signatures (e.g. SHA256withRSA, SHA1withRSA, SHA256withECDSA)
    if category == "Signature" || base_upper.contains("WITH") {
        let is_sha1 = base_upper.contains("SHA1") || base_upper.contains("MD5");
        let guidance = if is_sha1 {
            "CRITICAL: SHA-1 / MD5 signatures are deprecated. Upgrade signature algorithm to SHA256withRSA immediately."
        } else {
            "PQC Alert: Digital signature algorithm (RSA/ECDSA) is vulnerable to Shor's quantum algorithm. Under NeSL 8-year IU retention, plan Post-Quantum (ML-DSA) migration."
        };

        return (
            "asymmetric-signature".to_string(),
            mode,
            padding,
            "2048-bit (Standard Classical)".to_string(),
            if is_sha1 {
                "Legacy / Insecure".to_string()
            } else {
                "Quantum-Vulnerable (Shor's Algorithm)".to_string()
            },
            guidance.to_string(),
            112,
            0,
        );
    }

    // 2. Message Authentication Codes (MAC)
    if category == "Mac" || base_upper.starts_with("HMAC") {
        let is_md5_or_sha1 = base_upper.contains("MD5") || base_upper.contains("SHA1");
        return (
            "message-authentication-code".to_string(),
            mode,
            padding,
            if is_md5_or_sha1 { "Deprecated" } else { "256-bit (Strong)" }.to_string(),
            if is_md5_or_sha1 { "Legacy / Insecure" } else { "Quantum-Resistant" }.to_string(),
            if is_md5_or_sha1 {
                "HIGH RISK: Migrate HMAC to HmacSHA256 or HmacSHA512.".to_string()
            } else {
                "Compliant: HMAC is quantum-resistant under Grover's algorithm.".to_string()
            },
            128,
            3,
        );
    }

    // 3. Message Digests / Hashes
    if category == "MessageDigest" || base_upper.starts_with("SHA") || base_upper == "MD5" {
        return match base_upper.as_str() {
            "MD5" => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "Broken (<64 bits)".to_string(),
                "Legacy / Insecure".to_string(),
                "HIGH RISK: MD5 has known practical collision attacks. Deprecate immediately; migrate to SHA-256.".to_string(),
                0,
                0,
            ),
            "SHA-1" | "SHA1" => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "Deprecated (80 bits)".to_string(),
                "Legacy / Insecure".to_string(),
                "HIGH RISK: SHA-1 is retired by NIST & CERT-In. Upgrade to SHA-256 or SHA-512.".to_string(),
                80,
                0,
            ),
            "SHA-256" | "SHA256" => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "256-bit (Strong)".to_string(),
                "Quantum-Resistant".to_string(),
                "Compliant: SHA-256 is quantum-safe and accepted under CERT-In guidelines.".to_string(),
                128,
                3,
            ),
            "SHA-384" | "SHA384" => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "384-bit (High)".to_string(),
                "Quantum-Resistant".to_string(),
                "Compliant: High security, quantum-resistant hash function.".to_string(),
                192,
                4,
            ),
            "SHA-512" | "SHA512" => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "512-bit (Maximum)".to_string(),
                "Quantum-Resistant".to_string(),
                "Compliant: Maximum security, recommended for long-lived IU records.".to_string(),
                256,
                5,
            ),
            _ => (
                "message-digest".to_string(),
                "None".to_string(),
                "None".to_string(),
                "Standard Digest".to_string(),
                "Quantum-Resistant".to_string(),
                "Standard cryptographic hash function.".to_string(),
                128,
                3,
            ),
        };
    }

    // 4. Symmetric Ciphers (AES, DES, 3DES)
    if base_upper.starts_with("AES") {
        let is_ecb = mode.to_uppercase() == "ECB";
        let guidance = if is_ecb {
            "WARNING: ECB mode does not provide semantic security (patterns leak). Migrate to GCM or CBC with unique IV."
        } else {
            "Compliant: AES is NIST & CERT-In approved and quantum-resistant under Grover's algorithm."
        };
        return (
            "block-cipher".to_string(),
            mode,
            padding,
            "128/256-bit".to_string(),
            "Quantum-Resistant".to_string(),
            guidance.to_string(),
            128,
            3,
        );
    }

    if base_upper == "DES" || base_upper == "DESEDE" || base_upper.contains("TRIPLEDES") {
        return (
            "block-cipher".to_string(),
            mode,
            padding,
            "Deprecated / 56-112 bits".to_string(),
            "Legacy / Insecure".to_string(),
            "CRITICAL: DES/3DES is deprecated and vulnerable to Sweet32 / meet-in-the-middle attacks. Migrate to AES-256-GCM.".to_string(),
            0,
            0,
        );
    }

    // 5. Asymmetric Public Key Encryption & Key Pairs (RSA, DSA, EC, ECDH)
    if base_upper.contains("RSA") || category == "KeyPairGenerator" || category == "KeyAgreement" || base_upper == "EC" || base_upper == "ECDH" {
        let is_ec = base_upper == "EC" || base_upper.contains("ECD");
        let primitive = if category == "KeyAgreement" || base_upper == "ECDH" {
            "key-agreement"
        } else if is_ec {
            "elliptic-curve-keypair"
        } else {
            "public-key-encryption"
        };

        return (
            primitive.to_string(),
            mode,
            padding,
            if is_ec { "256-bit ECC (NIST P-256)" } else { "2048-bit RSA" }.to_string(),
            "Quantum-Vulnerable (Shor's Algorithm)".to_string(),
            "PQC Alert: Asymmetric keys (RSA/ECC) are vulnerable to Shor's quantum algorithm. Under NeSL 8-year IU data retention, plan Post-Quantum (ML-KEM / ML-DSA) migration.".to_string(),
            112,
            0,
        );
    }

    // 6. Keystores & Certificate Factories
    if category == "KeyStore" {
        return (
            "keystore".to_string(),
            "None".to_string(),
            "None".to_string(),
            format!("Keystore Type: {}", base),
            "Operational Asset".to_string(),
            if base_upper == "JKS" {
                "Note: Proprietary Java Keystore format. Consider migrating to standard PKCS12 (.p12).".to_string()
            } else {
                "Compliant: Standard PKCS#12 keystore format.".to_string()
            },
            128,
            2,
        );
    }

    if category == "CertificateFactory" || base_upper == "X.509" || base_upper == "X509" {
        return (
            "certificate-factory".to_string(),
            "None".to_string(),
            "None".to_string(),
            "X.509 Certificate Standard".to_string(),
            "Operational Asset".to_string(),
            "Compliant: Standard X.509 certificate parsing for digital signatures and mTLS.".to_string(),
            128,
            2,
        );
    }

    if category == "SSLContext" {
        let is_tls13 = base_upper.contains("1.3") || base_upper == "TLS";
        let is_old = base_upper.contains("1.0") || base_upper.contains("1.1") || base_upper == "SSL";
        return (
            "transport-protocol".to_string(),
            "None".to_string(),
            "None".to_string(),
            format!("Protocol: {}", base),
            if is_old {
                "Legacy / Insecure".to_string()
            } else {
                "Quantum-Vulnerable Key Exchange".to_string()
            },
            if is_old {
                "HIGH RISK: SSLv3 / TLS 1.0 / 1.1 are insecure and prohibited. Enforce TLS 1.2 or 1.3.".to_string()
            } else {
                "Compliant: Enforce TLS 1.2 minimum, preferably TLS 1.3.".to_string()
            },
            128,
            if is_tls13 { 3 } else { 1 },
        );
    }

    // Default Fallback
    (
        category.to_lowercase(),
        mode,
        padding,
        "Standard".to_string(),
        "Review Required".to_string(),
        "Review cryptographic implementation against NeSL Cryptographic Policy.".to_string(),
        112,
        1,
    )
}

/// Recursively scans a module directory for Java cryptographic calls and Keystore files.
pub fn scan_module_for_cbom(module_path: &Path, module_name: &str) -> Vec<CryptoAsset> {
    let mut assets = Vec::new();
    let patterns = get_patterns();

    // 1. Scan source code (.java files)
    scan_source_files(module_path, module_name, patterns, &mut assets);

    // 2. Scan for physical keystores, certificates, and HSM configs
    scan_keystore_files(module_path, module_name, &mut assets);

    assets
}

fn scan_source_files(
    dir: &Path,
    module_name: &str,
    patterns: &[(Regex, &'static str)],
    assets: &mut Vec<CryptoAsset>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" && name != ".git" {
                    scan_source_files(&path, module_name, patterns, assets);
                }
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("java") {
                scan_single_java_file(&path, module_name, patterns, assets);
            }
        }
    }
}

fn scan_single_java_file(
    file_path: &Path,
    module_name: &str,
    patterns: &[(Regex, &'static str)],
    assets: &mut Vec<CryptoAsset>,
) {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return, // Ignore binary or unreadable files
    };

    let display_path = file_path
        .to_str()
        .unwrap_or_default()
        .replace('\\', "/");

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        for (regex, category) in patterns {
            if let Some(caps) = regex.captures(line) {
                if let Some(algo_match) = caps.get(1) {
                    let raw_algo = algo_match.as_str().trim();
                    if raw_algo.is_empty() {
                        continue;
                    }

                    let (primitive, mode, padding, classical_sec, pqc_risk, guidance, _, _) =
                        classify_crypto(category, raw_algo);

                    assets.push(CryptoAsset {
                        module_name: module_name.to_string(),
                        asset_name: raw_algo.to_string(),
                        asset_type: "algorithm".to_string(),
                        primitive,
                        mode,
                        padding,
                        classical_security: classical_sec,
                        pqc_risk,
                        detection_source: display_path.clone(),
                        line_number: line_idx + 1,
                        snippet: trimmed.to_string(),
                        guidance,
                    });
                }
            }
        }
    }
}

fn scan_keystore_files(dir: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" && name != ".git" {
                    scan_keystore_files(&path, module_name, assets);
                }
            }
        } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = file_name.to_lowercase();
            let is_keystore = lower.ends_with(".jks")
                || lower.ends_with(".keystore")
                || lower.ends_with(".p12")
                || lower.ends_with(".pfx");
            let is_cert = lower.ends_with(".cer") || lower.ends_with(".crt") || lower.ends_with(".pem");
            let is_hsm_cfg = lower.contains("pkcs11") && lower.ends_with(".cfg");

            if is_keystore || is_cert || is_hsm_cfg {
                let display_path = path.to_str().unwrap_or_default().replace('\\', "/");
                let (asset_type, primitive, pqc, guidance) = if is_keystore {
                    (
                        "related-crypto-material".to_string(),
                        "keystore-file".to_string(),
                        "Operational Asset".to_string(),
                        "Review keystore access control, password protection, and certificate expiry.".to_string(),
                    )
                } else if is_cert {
                    (
                        "certificate".to_string(),
                        "x509-certificate".to_string(),
                        "Quantum-Vulnerable (Shor's Algorithm)".to_string(),
                        "Verify certificate validity dates, CA signature chain, and 2048-bit minimum key size.".to_string(),
                    )
                } else {
                    (
                        "related-crypto-material".to_string(),
                        "hsm-configuration".to_string(),
                        "HSM Infrastructure".to_string(),
                        "PKCS#11 HSM integration for eSign / DSC token signing partition.".to_string(),
                    )
                };

                assets.push(CryptoAsset {
                    module_name: module_name.to_string(),
                    asset_name: file_name.to_string(),
                    asset_type,
                    primitive,
                    mode: "N/A".to_string(),
                    padding: "N/A".to_string(),
                    classical_security: "Cryptographic File".to_string(),
                    pqc_risk: pqc,
                    detection_source: display_path,
                    line_number: 1,
                    snippet: format!("Cryptographic file on disk: {}", file_name),
                    guidance,
                });
            }
        }
    }
}

/// Generates a standard CycloneDX 1.6 CBOM document for a module, fully enriched for CycloneDX Sunshine and Dependency-Track.
pub fn generate_cyclonedx_cbom(
    module_name: &str,
    assets: &[CryptoAsset],
) -> CycloneDxCbom {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let serial_uuid = format!(
        "urn:uuid:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let root_ref = format!("pkg:generic/{}@1.0.0", module_name);
    let mut component_refs: Vec<String> = Vec::new();

    let components: Vec<CbomComponent> = assets
        .iter()
        .enumerate()
        .map(|(idx, a)| {
            let (_, _, _, _, _, _, classical_bits, nist_level) =
                classify_crypto(&a.primitive, &a.asset_name);

            let bom_ref = format!("{}-crypto-{}", module_name, idx + 1);
            component_refs.push(bom_ref.clone());

            let algo_props = if a.asset_type == "algorithm" {
                Some(AlgorithmProperties {
                    primitive: a.primitive.clone(),
                    parameter_set_identifier: Some(a.classical_security.clone()),
                    classical_security_level: classical_bits,
                    nist_quantum_security_level: nist_level,
                })
            } else {
                None
            };

            let properties = vec![
                CbomProperty {
                    name: "neSL:pqcRisk".to_string(),
                    value: a.pqc_risk.clone(),
                },
                CbomProperty {
                    name: "neSL:primitive".to_string(),
                    value: a.primitive.clone(),
                },
                CbomProperty {
                    name: "neSL:classicalSecurity".to_string(),
                    value: a.classical_security.clone(),
                },
                CbomProperty {
                    name: "neSL:sourceLocation".to_string(),
                    value: format!("{}:{}", a.detection_source, a.line_number),
                },
            ];

            CbomComponent {
                bom_ref,
                comp_type: "cryptographic-asset".to_string(),
                name: a.asset_name.clone(),
                version: Some(a.classical_security.clone()),
                description: Some(a.guidance.clone()),
                crypto_properties: CryptoProperties {
                    asset_type: a.asset_type.clone(),
                    algorithm_properties: algo_props,
                    detection_context: DetectionContext {
                        file_path: a.detection_source.clone(),
                        line_number: a.line_number,
                        snippet: a.snippet.clone(),
                        post_quantum_risk: a.pqc_risk.clone(),
                    },
                },
                properties: Some(properties),
            }
        })
        .collect();

    let dependencies = Some(vec![CbomDependency {
        ref_id: root_ref.clone(),
        depends_on: component_refs,
    }]);

    CycloneDxCbom {
        schema: "http://cyclonedx.org/schema/bom-1.6.schema.json".to_string(),
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.6".to_string(),
        serial_number: serial_uuid,
        version: 1,
        metadata: CbomMetadata {
            timestamp,
            component: CbomRootComponent {
                bom_ref: root_ref,
                comp_type: "application".to_string(),
                name: module_name.to_string(),
                version: Some("1.0.0".to_string()),
            },
        },
        components,
        dependencies,
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Generates a human-readable visual HTML report for a module's Cryptographic Bill of Materials (CBOM).
pub fn generate_cbom_html_report(module_name: &str, assets: &[CryptoAsset]) -> String {
    let mut quantum_resistant = 0usize;
    let mut quantum_vulnerable = 0usize;
    let mut keystores = 0usize;
    let mut legacy_insecure = 0usize;

    for a in assets {
        if a.pqc_risk.contains("Quantum-Resistant") {
            quantum_resistant += 1;
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            quantum_vulnerable += 1;
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            legacy_insecure += 1;
        } else {
            keystores += 1;
        }
    }

    let total = assets.len();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut table_rows = String::new();
    for (idx, a) in assets.iter().enumerate() {
        let (badge_class, badge_text) = if a.pqc_risk.contains("Quantum-Resistant") {
            ("badge-success", "Quantum-Resistant")
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            ("badge-danger", "Quantum-Vulnerable (Shor's)")
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            ("badge-insecure", "Legacy / Insecure")
        } else {
            ("badge-info", "Operational Asset")
        };

        let filter_tag = if a.pqc_risk.contains("Quantum-Resistant") {
            "pqc-safe"
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            "pqc-vuln"
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            "pqc-legacy"
        } else {
            "pqc-keystore"
        };

        table_rows.push_str(&format!(
            r#"<tr class="asset-row" data-tag="{tag}">
                <td style="text-align: center; color: var(--text-muted);">{num}</td>
                <td><span class="algo-name">{name}</span></td>
                <td><span class="primitive-tag">{primitive}</span></td>
                <td>{mode}</td>
                <td>{padding}</td>
                <td><strong>{security}</strong></td>
                <td><span class="badge {badge_cls}">{badge_lbl}</span></td>
                <td><div class="file-loc">{file}<span class="line-num">:{line}</span></div></td>
                <td><code class="code-snippet">{snippet}</code></td>
                <td><div class="guidance-box">{guidance}</div></td>
            </tr>"#,
            tag = filter_tag,
            num = idx + 1,
            name = escape_html(&a.asset_name),
            primitive = escape_html(&a.primitive),
            mode = escape_html(&a.mode),
            padding = escape_html(&a.padding),
            security = escape_html(&a.classical_security),
            badge_cls = badge_class,
            badge_lbl = badge_text,
            file = escape_html(&a.detection_source),
            line = a.line_number,
            snippet = escape_html(&a.snippet),
            guidance = escape_html(&a.guidance)
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBOM Report - {title}</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-bg: #eff6ff;
            --success: #16a34a;
            --success-bg: #f0fdf4;
            --warning: #d97706;
            --warning-bg: #fffbeb;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
            --insecure: #991b1b;
            --insecure-bg: #fee2e2;
            --purple: #7c3aed;
            --purple-bg: #f5f3ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: #ffffff;
            border-radius: 12px;
            padding: 28px 36px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 26px;
            letter-spacing: -0.5px;
        }}
        .header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
        }}
        .header-meta {{
            margin-top: 14px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .pill {{
            background: rgba(255,255,255,0.12);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 500;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .kpi-title {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }}
        .kpi-desc {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 6px;
        }}
        .card-primary .kpi-value {{ color: var(--primary); }}
        .card-success .kpi-value {{ color: var(--success); }}
        .card-danger .kpi-value {{ color: var(--danger); }}
        .card-insecure .kpi-value {{ color: var(--insecure); }}
        .card-purple .kpi-value {{ color: var(--purple); }}

        .toolbar {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            gap: 16px;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .filter-group {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }}
        .search-input {{
            padding: 8px 14px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 13px;
            min-width: 280px;
            outline: none;
        }}
        .search-input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
        }}

        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        thead {{
            background: #f1f5f9;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            padding: 12px 14px;
            font-weight: 600;
            color: #334155;
            white-space: nowrap;
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover td {{
            background-color: #f8fafc;
        }}
        .algo-name {{
            font-weight: 600;
            color: #0f172a;
        }}
        .primitive-tag {{
            background: #f1f5f9;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: #475569;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }}
        .badge-success {{ background: var(--success-bg); color: var(--success); border: 1px solid rgba(22,163,74,0.3); }}
        .badge-danger {{ background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(220,38,38,0.3); }}
        .badge-insecure {{ background: var(--insecure-bg); color: var(--insecure); border: 1px solid rgba(153,27,27,0.3); }}
        .badge-info {{ background: var(--purple-bg); color: var(--purple); border: 1px solid rgba(124,58,237,0.3); }}
        .file-loc {{
            font-family: monospace;
            font-size: 11px;
            color: #2563eb;
            max-width: 240px;
            word-break: break-all;
        }}
        .line-num {{
            color: #dc2626;
            font-weight: bold;
        }}
        .code-snippet {{
            font-family: Consolas, "Courier New", monospace;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 4px 8px;
            border-radius: 4px;
            display: block;
            max-width: 300px;
            overflow-x: auto;
            white-space: nowrap;
            color: #334155;
            font-size: 11px;
        }}
        .guidance-box {{
            font-size: 12px;
            color: #475569;
            max-width: 280px;
        }}
        .footer {{
            margin-top: 24px;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Cryptographic Bill of Materials (CBOM)</h1>
            <p>Module / Subsystem: <strong>{mod_name}</strong> | Generated: {time}</p>
            <div class="header-meta">
                <span class="pill">CERT-In Guidelines Aligned</span>
                <span class="pill">STPI Cryptographic Governance</span>
                <span class="pill">CycloneDX 1.6 Cryptography Standard</span>
                <span class="pill">NeSL 8-Year IU Retention Mandate</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card card-primary">
                <div class="kpi-title">Total Crypto Assets</div>
                <div class="kpi-value">{tot}</div>
                <div class="kpi-desc">Algorithms, primitives, and keystores</div>
            </div>
            <div class="kpi-card card-success">
                <div class="kpi-title">Quantum-Resistant</div>
                <div class="kpi-value">{qr}</div>
                <div class="kpi-desc">AES, SHA-256, SHA-512, HMAC</div>
            </div>
            <div class="kpi-card card-danger">
                <div class="kpi-title">Quantum-Vulnerable (PQC Alert)</div>
                <div class="kpi-value">{qv}</div>
                <div class="kpi-desc">RSA, ECC, eSign (Shor's Algorithm)</div>
            </div>
            <div class="kpi-card card-purple">
                <div class="kpi-title">Keystores & Certs</div>
                <div class="kpi-value">{ks}</div>
                <div class="kpi-desc">PKCS12, JKS, X.509 certificates</div>
            </div>
            <div class="kpi-card card-insecure">
                <div class="kpi-title">Legacy / Insecure</div>
                <div class="kpi-value">{leg}</div>
                <div class="kpi-desc">MD5, SHA-1, DES/3DES</div>
            </div>
        </div>

        <div class="toolbar">
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterTable('all')">All Assets ({tot})</button>
                <button class="filter-btn" onclick="filterTable('pqc-safe')">Quantum-Resistant ({qr})</button>
                <button class="filter-btn" onclick="filterTable('pqc-vuln')">Quantum-Vulnerable ({qv})</button>
                <button class="filter-btn" onclick="filterTable('pqc-keystore')">Keystores & Certs ({ks})</button>
                <button class="filter-btn" onclick="filterTable('pqc-legacy')">Legacy / Insecure ({leg})</button>
            </div>
            <input type="text" id="searchInput" class="search-input" placeholder="Search algorithms, files, or snippets..." onkeyup="searchTable()">
        </div>

        <div class="table-container">
            <table id="cbomTable">
                <thead>
                    <tr>
                        <th style="width: 40px; text-align: center;">#</th>
                        <th>Asset Name</th>
                        <th>Primitive</th>
                        <th>Mode</th>
                        <th>Padding</th>
                        <th>Security</th>
                        <th>Post-Quantum Status</th>
                        <th>Source Location</th>
                        <th>Code Snippet</th>
                        <th>Compliance Guidance</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            NeSL Technology & Security Directorate • Generated by NeSL Multi-Module SBOM & CBOM Automation Engine
        </div>
    </div>

    <script>
        function filterTable(tag) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const rows = document.querySelectorAll('.asset-row');
            rows.forEach(row => {{
                if (tag === 'all' || row.getAttribute('data-tag') === tag) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function searchTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.asset-row');
            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                if (text.includes(query)) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"##,
        title = escape_html(module_name),
        mod_name = escape_html(module_name),
        time = timestamp,
        tot = total,
        qr = quantum_resistant,
        qv = quantum_vulnerable,
        ks = keystores,
        leg = legacy_insecure,
        rows = table_rows
    )
}

/// Generates a consolidated organization-wide visual HTML dashboard for all cryptographic assets across all modules.
pub fn generate_global_cbom_dashboard(total_modules: usize, all_assets: &[CryptoAsset]) -> String {
    let mut quantum_resistant = 0usize;
    let mut quantum_vulnerable = 0usize;
    let mut keystores = 0usize;
    let mut legacy_insecure = 0usize;

    for a in all_assets {
        if a.pqc_risk.contains("Quantum-Resistant") {
            quantum_resistant += 1;
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            quantum_vulnerable += 1;
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            legacy_insecure += 1;
        } else {
            keystores += 1;
        }
    }

    let total = all_assets.len();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut table_rows = String::new();
    for (idx, a) in all_assets.iter().enumerate() {
        let (badge_class, badge_text) = if a.pqc_risk.contains("Quantum-Resistant") {
            ("badge-success", "Quantum-Resistant")
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            ("badge-danger", "Quantum-Vulnerable (Shor's)")
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            ("badge-insecure", "Legacy / Insecure")
        } else {
            ("badge-info", "Operational Asset")
        };

        let filter_tag = if a.pqc_risk.contains("Quantum-Resistant") {
            "pqc-safe"
        } else if a.pqc_risk.contains("Quantum-Vulnerable") {
            "pqc-vuln"
        } else if a.pqc_risk.contains("Legacy") || a.pqc_risk.contains("Insecure") {
            "pqc-legacy"
        } else {
            "pqc-keystore"
        };

        table_rows.push_str(&format!(
            r#"<tr class="asset-row" data-tag="{tag}">
                <td style="text-align: center; color: var(--text-muted);">{num}</td>
                <td><strong>{mod_name}</strong></td>
                <td><span class="algo-name">{name}</span></td>
                <td><span class="primitive-tag">{primitive}</span></td>
                <td>{mode}</td>
                <td>{padding}</td>
                <td><strong>{security}</strong></td>
                <td><span class="badge {badge_cls}">{badge_lbl}</span></td>
                <td><div class="file-loc">{file}<span class="line-num">:{line}</span></div></td>
                <td><code class="code-snippet">{snippet}</code></td>
                <td><div class="guidance-box">{guidance}</div></td>
            </tr>"#,
            tag = filter_tag,
            num = idx + 1,
            mod_name = escape_html(&a.module_name),
            name = escape_html(&a.asset_name),
            primitive = escape_html(&a.primitive),
            mode = escape_html(&a.mode),
            padding = escape_html(&a.padding),
            security = escape_html(&a.classical_security),
            badge_cls = badge_class,
            badge_lbl = badge_text,
            file = escape_html(&a.detection_source),
            line = a.line_number,
            snippet = escape_html(&a.snippet),
            guidance = escape_html(&a.guidance)
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise CBOM Executive Dashboard - NeSL</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-bg: #eff6ff;
            --success: #16a34a;
            --success-bg: #f0fdf4;
            --warning: #d97706;
            --warning-bg: #fffbeb;
            --danger: #dc2626;
            --danger-bg: #fef2f2;
            --insecure: #991b1b;
            --insecure-bg: #fee2e2;
            --purple: #7c3aed;
            --purple-bg: #f5f3ff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1500px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            color: #ffffff;
            border-radius: 12px;
            padding: 32px 40px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 28px;
            letter-spacing: -0.5px;
        }}
        .header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
        }}
        .header-meta {{
            margin-top: 16px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .pill {{
            background: rgba(255,255,255,0.12);
            padding: 5px 14px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 500;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .kpi-title {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }}
        .kpi-desc {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 6px;
        }}
        .card-primary .kpi-value {{ color: var(--primary); }}
        .card-success .kpi-value {{ color: var(--success); }}
        .card-danger .kpi-value {{ color: var(--danger); }}
        .card-insecure .kpi-value {{ color: var(--insecure); }}
        .card-purple .kpi-value {{ color: var(--purple); }}

        .toolbar {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            gap: 16px;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
        }}
        .filter-group {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }}
        .search-input {{
            padding: 8px 14px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 13px;
            min-width: 300px;
            outline: none;
        }}
        .search-input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
        }}

        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        thead {{
            background: #f1f5f9;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            padding: 12px 14px;
            font-weight: 600;
            color: #334155;
            white-space: nowrap;
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        tr:hover td {{
            background-color: #f8fafc;
        }}
        .algo-name {{
            font-weight: 600;
            color: #0f172a;
        }}
        .primitive-tag {{
            background: #f1f5f9;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: #475569;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }}
        .badge-success {{ background: var(--success-bg); color: var(--success); border: 1px solid rgba(22,163,74,0.3); }}
        .badge-danger {{ background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(220,38,38,0.3); }}
        .badge-insecure {{ background: var(--insecure-bg); color: var(--insecure); border: 1px solid rgba(153,27,27,0.3); }}
        .badge-info {{ background: var(--purple-bg); color: var(--purple); border: 1px solid rgba(124,58,237,0.3); }}
        .file-loc {{
            font-family: monospace;
            font-size: 11px;
            color: #2563eb;
            max-width: 240px;
            word-break: break-all;
        }}
        .line-num {{
            color: #dc2626;
            font-weight: bold;
        }}
        .code-snippet {{
            font-family: Consolas, "Courier New", monospace;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 4px 8px;
            border-radius: 4px;
            display: block;
            max-width: 280px;
            overflow-x: auto;
            white-space: nowrap;
            color: #334155;
            font-size: 11px;
        }}
        .guidance-box {{
            font-size: 12px;
            color: #475569;
            max-width: 260px;
        }}
        .footer {{
            margin-top: 24px;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enterprise Cryptographic Bill of Materials (CBOM) Dashboard</h1>
            <p>Consolidated register across {mods} modules | Generated: {time}</p>
            <div class="header-meta">
                <span class="pill">CERT-In Guidelines Aligned</span>
                <span class="pill">STPI Cryptographic Governance</span>
                <span class="pill">CycloneDX 1.6 Cryptography Standard</span>
                <span class="pill">NeSL 8-Year IU Statutory Mandate</span>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card card-primary">
                <div class="kpi-title">Total Crypto Assets</div>
                <div class="kpi-value">{tot}</div>
                <div class="kpi-desc">Across all {mods} scanned modules</div>
            </div>
            <div class="kpi-card card-success">
                <div class="kpi-title">Quantum-Resistant</div>
                <div class="kpi-value">{qr}</div>
                <div class="kpi-desc">AES, SHA-256, SHA-512, HMAC</div>
            </div>
            <div class="kpi-card card-danger">
                <div class="kpi-title">Quantum-Vulnerable (PQC Alert)</div>
                <div class="kpi-value">{qv}</div>
                <div class="kpi-desc">RSA, ECC, eSign (Shor's Algorithm)</div>
            </div>
            <div class="kpi-card card-purple">
                <div class="kpi-title">Keystores & Certs</div>
                <div class="kpi-value">{ks}</div>
                <div class="kpi-desc">PKCS12, JKS, X.509 certificates</div>
            </div>
            <div class="kpi-card card-insecure">
                <div class="kpi-title">Legacy / Insecure</div>
                <div class="kpi-value">{leg}</div>
                <div class="kpi-desc">MD5, SHA-1, DES/3DES</div>
            </div>
        </div>

        <div class="toolbar">
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterTable('all')">All Assets ({tot})</button>
                <button class="filter-btn" onclick="filterTable('pqc-safe')">Quantum-Resistant ({qr})</button>
                <button class="filter-btn" onclick="filterTable('pqc-vuln')">Quantum-Vulnerable ({qv})</button>
                <button class="filter-btn" onclick="filterTable('pqc-keystore')">Keystores & Certs ({ks})</button>
                <button class="filter-btn" onclick="filterTable('pqc-legacy')">Legacy / Insecure ({leg})</button>
            </div>
            <input type="text" id="searchInput" class="search-input" placeholder="Search modules, algorithms, or files..." onkeyup="searchTable()">
        </div>

        <div class="table-container">
            <table id="cbomTable">
                <thead>
                    <tr>
                        <th style="width: 40px; text-align: center;">#</th>
                        <th>Module</th>
                        <th>Asset Name</th>
                        <th>Primitive</th>
                        <th>Mode</th>
                        <th>Padding</th>
                        <th>Security</th>
                        <th>Post-Quantum Status</th>
                        <th>Source Location</th>
                        <th>Code Snippet</th>
                        <th>Compliance Guidance</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            NeSL Technology & Security Directorate • Generated by NeSL Multi-Module SBOM & CBOM Automation Engine
        </div>
    </div>

    <script>
        function filterTable(tag) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const rows = document.querySelectorAll('.asset-row');
            rows.forEach(row => {{
                if (tag === 'all' || row.getAttribute('data-tag') === tag) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function searchTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.asset-row');
            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                if (text.includes(query)) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"##,
        mods = total_modules,
        time = timestamp,
        tot = total,
        qr = quantum_resistant,
        qv = quantum_vulnerable,
        ks = keystores,
        leg = legacy_insecure,
        rows = table_rows
    )
}
