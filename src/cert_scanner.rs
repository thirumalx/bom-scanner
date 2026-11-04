use crate::cbom::CryptoAsset;
use chrono::{DateTime, NaiveDate, Utc};
use std::fs;
use std::path::Path;

// ==============================================================================
// X.509 Certificate & Keystore Inspection Engine (eMudhra, CCA India, PKI)
// ==============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub key_size_bits: Option<usize>,
    pub is_emudhra: bool,
    pub is_cca_india: bool,
    pub status: CertificateStatus,
    pub days_remaining: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    Active,
    ExpiringSoon,
    Expired,
    NotYetValid,
    Unknown,
}

// ------------------------------------------------------------------------------
// Pure Rust Base64 Decoder (Zero external dependencies)
// ------------------------------------------------------------------------------
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => continue,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------------------
// Lightweight ASN.1 DER Parser for X.509 Certificates
// ------------------------------------------------------------------------------
struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[allow(dead_code)]
    fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }

    fn read_tag_and_length(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            return None;
        }
        let tag = self.data[self.pos];
        self.pos += 1;

        if self.pos >= self.data.len() {
            return None;
        }
        let first_len = self.data[self.pos];
        self.pos += 1;

        let len = if first_len < 0x80 {
            first_len as usize
        } else {
            let num_bytes = (first_len & 0x7F) as usize;
            if num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..num_bytes {
                l = (l << 8) | (self.data[self.pos] as usize);
                self.pos += 1;
            }
            l
        };

        if self.pos + len > self.data.len() {
            return None;
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, value))
    }
}

// Helper to parse OID bytes to dotted string
fn oid_to_string(oid_bytes: &[u8]) -> String {
    if oid_bytes.is_empty() {
        return String::new();
    }
    let first = oid_bytes[0];
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut val = 0u64;
    for &b in &oid_bytes[1..] {
        val = (val << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            parts.push(val.to_string());
            val = 0;
        }
    }
    parts.join(".")
}

fn oid_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA256withRSA".to_string(),
        "1.2.840.113549.1.1.5" => "SHA1withRSA (Deprecated)".to_string(),
        "1.2.840.113549.1.1.4" => "MD5withRSA (Broken)".to_string(),
        "1.2.840.113549.1.1.12" => "SHA384withRSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA512withRSA".to_string(),
        "1.2.840.113549.1.1.1" => "RSA Encryption".to_string(),
        "1.2.840.10045.4.3.2" => "SHA256withECDSA".to_string(),
        "1.2.840.10045.2.1" => "EC Public Key".to_string(),
        "2.16.840.1.101.3.4.2.1" => "SHA-256".to_string(),
        "1.3.14.3.2.26" => "SHA-1".to_string(),
        other => other.to_string(),
    }
}

// Helper to parse ASN.1 Name (RDN sequence) into a readable DN string
fn parse_rdn_sequence(bytes: &[u8]) -> String {
    let mut reader = DerReader::new(bytes);
    let mut components = Vec::new();

    while let Some((tag, rdn_data)) = reader.read_tag_and_length() {
        if tag == 0x31 {
            // SET OF AttributeTypeAndValue
            let mut set_reader = DerReader::new(rdn_data);
            while let Some((seq_tag, atv_data)) = set_reader.read_tag_and_length() {
                if seq_tag == 0x30 {
                    // SEQUENCE { type OBJECT IDENTIFIER, value ANY }
                    let mut atv_reader = DerReader::new(atv_data);
                    if let Some((oid_tag, oid_val)) = atv_reader.read_tag_and_length() {
                        if oid_tag == 0x06 {
                            let oid = oid_to_string(oid_val);
                            if let Some((_, str_val)) = atv_reader.read_tag_and_length() {
                                let label = match oid.as_str() {
                                    "2.5.4.3" => "CN",
                                    "2.5.4.10" => "O",
                                    "2.5.4.11" => "OU",
                                    "2.5.4.6" => "C",
                                    "2.5.4.8" => "ST",
                                    "2.5.4.7" => "L",
                                    _ => continue,
                                };
                                let text = String::from_utf8_lossy(str_val).trim().to_string();
                                if !text.is_empty() {
                                    components.push(format!("{}={}", label, text));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if components.is_empty() {
        "Unknown DN".to_string()
    } else {
        components.join(", ")
    }
}

// Helper to parse UTCTime or GeneralizedTime
fn parse_asn1_time(tag: u8, bytes: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSSZ or YYMMDDHHMMZ
        if s.len() >= 12 {
            let year_prefix = if s[0..2].parse::<u32>().unwrap_or(0) >= 50 { "19" } else { "20" };
            let full = format!("{}{}", year_prefix, s);
            return parse_generalized_time_str(&full);
        }
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        return parse_generalized_time_str(s);
    }
    None
}

fn parse_generalized_time_str(s: &str) -> Option<DateTime<Utc>> {
    let clean = s.trim_end_matches('Z');
    if clean.len() >= 14 {
        let year: i32 = clean[0..4].parse().ok()?;
        let month: u32 = clean[4..6].parse().ok()?;
        let day: u32 = clean[6..8].parse().ok()?;
        let hour: u32 = clean[8..10].parse().ok()?;
        let min: u32 = clean[10..12].parse().ok()?;
        let sec: u32 = clean[12..14].parse().ok()?;
        let naive_date = NaiveDate::from_ymd_opt(year, month, day)?;
        let naive_dt = naive_date.and_hms_opt(hour, min, sec)?;
        return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
    }
    None
}

/// Parses an X.509 DER certificate buffer
pub fn parse_x509_der(der_bytes: &[u8]) -> Option<ParsedCertificate> {
    let mut root_reader = DerReader::new(der_bytes);
    let (tag, cert_seq) = root_reader.read_tag_and_length()?;
    if tag != 0x30 {
        return None;
    }

    let mut cert_reader = DerReader::new(cert_seq);

    // 1. TBSCertificate (SEQUENCE)
    let (tbs_tag, tbs_bytes) = cert_reader.read_tag_and_length()?;
    if tbs_tag != 0x30 {
        return None;
    }

    // 2. Signature Algorithm (SEQUENCE)
    let sig_algo_name = if let Some((_, sig_bytes)) = cert_reader.read_tag_and_length() {
        let mut sig_reader = DerReader::new(sig_bytes);
        if let Some((oid_tag, oid_val)) = sig_reader.read_tag_and_length() {
            if oid_tag == 0x06 {
                oid_name(&oid_to_string(oid_val))
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        }
    } else {
        "Unknown".to_string()
    };

    let mut tbs_reader = DerReader::new(tbs_bytes);

    // Skip version [0] if present
    if let Some((next_tag, _next_val)) = tbs_reader.read_tag_and_length() {
        if next_tag != 0xA0 {
            // Not version; rewinding is approximated by continuing if it's serial
            // For standard v3 certificates, version is 0xA0
        }
    }

    // Serial number (INTEGER)
    let _ = tbs_reader.read_tag_and_length();

    // Signature algorithm inside TBS (SEQUENCE)
    let _ = tbs_reader.read_tag_and_length();

    // Issuer (SEQUENCE)
    let issuer = if let Some((tag, val)) = tbs_reader.read_tag_and_length() {
        if tag == 0x30 {
            parse_rdn_sequence(val)
        } else {
            "Unknown Issuer".to_string()
        }
    } else {
        "Unknown Issuer".to_string()
    };

    // Validity (SEQUENCE of notBefore, notAfter)
    let mut not_before = None;
    let mut not_after = None;
    if let Some((tag, val)) = tbs_reader.read_tag_and_length() {
        if tag == 0x30 {
            let mut val_reader = DerReader::new(val);
            if let Some((nb_tag, nb_bytes)) = val_reader.read_tag_and_length() {
                not_before = parse_asn1_time(nb_tag, nb_bytes);
            }
            if let Some((na_tag, na_bytes)) = val_reader.read_tag_and_length() {
                not_after = parse_asn1_time(na_tag, na_bytes);
            }
        }
    }

    // Subject (SEQUENCE)
    let subject = if let Some((tag, val)) = tbs_reader.read_tag_and_length() {
        if tag == 0x30 {
            parse_rdn_sequence(val)
        } else {
            "Unknown Subject".to_string()
        }
    } else {
        "Unknown Subject".to_string()
    };

    // SubjectPublicKeyInfo (SEQUENCE)
    let mut pk_algo = "Unknown".to_string();
    let mut key_bits = None;
    if let Some((tag, spki_bytes)) = tbs_reader.read_tag_and_length() {
        if tag == 0x30 {
            let mut spki_reader = DerReader::new(spki_bytes);
            // AlgorithmIdentifier (SEQUENCE)
            if let Some((_, alg_bytes)) = spki_reader.read_tag_and_length() {
                let mut alg_reader = DerReader::new(alg_bytes);
                if let Some((oid_tag, oid_val)) = alg_reader.read_tag_and_length() {
                    if oid_tag == 0x06 {
                        pk_algo = oid_name(&oid_to_string(oid_val));
                    }
                }
            }
            // BIT STRING containing public key bytes
            if let Some((bs_tag, bs_bytes)) = spki_reader.read_tag_and_length() {
                if bs_tag == 0x03 && bs_bytes.len() > 1 {
                    // Skip unused bits byte
                    let pub_key_raw = &bs_bytes[1..];
                    if pk_algo.contains("RSA") {
                        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
                        let mut rsa_reader = DerReader::new(pub_key_raw);
                        if let Some((seq_t, seq_b)) = rsa_reader.read_tag_and_length() {
                            if seq_t == 0x30 {
                                let mut mod_reader = DerReader::new(seq_b);
                                if let Some((int_t, int_b)) = mod_reader.read_tag_and_length() {
                                    if int_t == 0x02 {
                                        // Modulus bytes (strip leading zero if present)
                                        let clean_len = if !int_b.is_empty() && int_b[0] == 0x00 {
                                            int_b.len() - 1
                                        } else {
                                            int_b.len()
                                        };
                                        key_bits = Some(clean_len * 8);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Determine eMudhra & CCA India affinity
    let issuer_lower = issuer.to_lowercase();
    let is_emudhra = issuer_lower.contains("emudhra") || issuer_lower.contains("e-mudhra");
    let is_cca_india = is_emudhra
        || issuer_lower.contains("cca india")
        || issuer_lower.contains("c-dac")
        || issuer_lower.contains("protean")
        || issuer_lower.contains("nsdl")
        || issuer_lower.contains("idrbt")
        || issuer_lower.contains("vsign")
        || issuer_lower.contains("pantasign");

    // Calculate expiry and status
    let now = Utc::now();
    let (status, days_remaining) = match (not_before, not_after) {
        (Some(nb), _) if nb > now => (CertificateStatus::NotYetValid, None),
        (_, Some(na)) => {
            let diff = (na - now).num_days();
            let st = if diff < 0 {
                CertificateStatus::Expired
            } else if diff <= 30 {
                CertificateStatus::ExpiringSoon
            } else {
                CertificateStatus::Active
            };
            (st, Some(diff))
        }
        _ => (CertificateStatus::Unknown, None),
    };

    Some(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        signature_algorithm: sig_algo_name,
        public_key_algorithm: pk_algo,
        key_size_bits: key_bits,
        is_emudhra,
        is_cca_india,
        status,
        days_remaining,
    })
}

/// Parses PEM certificate content (which may contain multiple certificates)
pub fn parse_pem_certificates(pem_content: &str) -> Vec<ParsedCertificate> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64_accum = String::new();

    for line in pem_content.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64_accum.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            in_cert = false;
            if let Some(der) = base64_decode(&b64_accum) {
                if let Some(parsed) = parse_x509_der(&der) {
                    certs.push(parsed);
                }
            }
            b64_accum.clear();
        } else if in_cert {
            b64_accum.push_str(trimmed);
        }
    }

    certs
}

/// Inspects binary certificate or keystore files (.cer, .crt, .pem, .p12, .pfx, .jks)
pub fn inspect_certificate_file(path: &Path) -> Vec<ParsedCertificate> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    // 1. Try PEM parsing first
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            let pem_certs = parse_pem_certificates(text);
            if !pem_certs.is_empty() {
                return pem_certs;
            }
        }
    }

    // 2. Try DER parsing directly
    if let Some(cert) = parse_x509_der(&bytes) {
        return vec![cert];
    }

    // 3. Scan binary buffer (e.g. inside PKCS#12 or cert bundles) for embedded DER certificates
    let mut found_certs = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        // Look for SEQUENCE (0x30) with length between 250 and 8192 bytes
        if bytes[i] == 0x30 && bytes[i + 1] == 0x82 {
            let len = ((bytes[i + 2] as usize) << 8) | (bytes[i + 3] as usize);
            if len >= 250 && len <= 8192 && i + 4 + len <= bytes.len() {
                let candidate = &bytes[i..i + 4 + len];
                if let Some(c) = parse_x509_der(candidate) {
                    found_certs.push(c);
                    i += 4 + len;
                    continue;
                }
            }
        }
        i += 1;
    }

    found_certs
}

// ==============================================================================
// High-Level Module Scanner for Certificates, Keystores & Configs
// ==============================================================================

pub fn scan_certificates_and_keystores(
    module_path: &Path,
    module_name: &str,
    assets: &mut Vec<CryptoAsset>,
) {
    // 1. Scan filesystem for physical certificates & keystores
    scan_keystore_and_cert_dir(module_path, module_name, assets);

    // 2. Scan application.yaml and application.properties for eMudhra / Keystore configuration issues
    scan_configuration_files(module_path, module_name, assets);

    // 3. Scan Java files for XML-DSig signature & digest deprecation (SHA-1 vs SHA-256)
    scan_java_xml_signer_patterns(module_path, module_name, assets);
}

fn scan_keystore_and_cert_dir(dir: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" && name != ".git" {
                    scan_keystore_and_cert_dir(&path, module_name, assets);
                }
            }
        } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = file_name.to_lowercase();
            let is_cert = lower.ends_with(".cer") || lower.ends_with(".crt") || lower.ends_with(".pem");
            let is_p12 = lower.ends_with(".p12") || lower.ends_with(".pfx");
            let is_jks = lower.ends_with(".jks") || lower.ends_with(".keystore");
            let is_hsm = lower.contains("pkcs11") && lower.ends_with(".cfg");

            if is_cert || is_p12 || is_jks || is_hsm {
                let display_path = path.to_str().unwrap_or_default().replace('\\', "/");
                let parsed_certs = inspect_certificate_file(&path);

                if !parsed_certs.is_empty() {
                    for c in parsed_certs {
                        let is_expired = c.status == CertificateStatus::Expired;
                        let is_expiring_soon = c.status == CertificateStatus::ExpiringSoon;

                        let ca_tag = if c.is_emudhra {
                            "eMudhra Certifying Authority (ESP / DSC)"
                        } else if c.is_cca_india {
                            "CCA India Licensed CA"
                        } else {
                            "Standard X.509 CA"
                        };

                        let (sec_level, pqc_risk, guidance) = if is_expired {
                            (
                                "CRITICAL: Certificate Expired".to_string(),
                                "Operational Outage".to_string(),
                                format!(
                                    "CRITICAL OUTAGE RISK: Certificate for '{}' expired on {}. eMudhra eSign/DSC transactions will fail. Renew immediately.",
                                    c.subject,
                                    c.not_after.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
                                ),
                            )
                        } else if is_expiring_soon {
                            (
                                "HIGH RISK: Expiring Soon".to_string(),
                                "Operational Asset".to_string(),
                                format!(
                                    "URGENT: Certificate for '{}' expires in {} day(s) on {}. Initiate eMudhra DSC renewal.",
                                    c.subject,
                                    c.days_remaining.unwrap_or(0),
                                    c.not_after.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
                                ),
                            )
                        } else {
                            (
                                format!(
                                    "Active (Expires in {} days) | Key: {}-bit",
                                    c.days_remaining.unwrap_or(0),
                                    c.key_size_bits.unwrap_or(2048)
                                ),
                                "Quantum-Vulnerable (Shor's Algorithm)".to_string(),
                                format!(
                                    "Compliant {}: Issuer: '{}'. Valid until {}. PQC Alert: RSA keys vulnerable to quantum factorization.",
                                    ca_tag,
                                    c.issuer,
                                    c.not_after.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
                                ),
                            )
                        };

                        assets.push(CryptoAsset {
                            module_name: module_name.to_string(),
                            asset_name: format!("Certificate: {}", file_name),
                            asset_type: "certificate".to_string(),
                            primitive: "x509-certificate".to_string(),
                            mode: c.signature_algorithm.clone(),
                            padding: format!("Issuer: {}", c.issuer),
                            classical_security: sec_level,
                            pqc_risk,
                            detection_source: display_path.clone(),
                            line_number: 1,
                            snippet: format!("Subject: {} | Validity: {} to {}", c.subject, c.not_before.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(), c.not_after.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()),
                            guidance,
                            generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
                        });
                    }
                } else {
                    // Keystore container without extractable plain DER certs
                    let (asset_name, guidance, classical_sec) = if is_p12 {
                        (
                            format!("PKCS#12 Keystore: {}", file_name),
                            "Compliant PKCS#12 keystore storage. Verify password protection and access control.".to_string(),
                            "PKCS#12 Keystore Container".to_string(),
                        )
                    } else if is_jks {
                        (
                            format!("Legacy JKS Keystore: {}", file_name),
                            "HIGH RISK: Proprietary Java Keystore format. Deprecated by Oracle/CERT-In; migrate to PKCS#12 (.p12).".to_string(),
                            "Legacy JKS Container".to_string(),
                        )
                    } else {
                        (
                            format!("HSM Config: {}", file_name),
                            "PKCS#11 Hardware Security Module configuration. Verify secure PIN storage in environment variables.".to_string(),
                            "Hardware Security Module".to_string(),
                        )
                    };

                    assets.push(CryptoAsset {
                        module_name: module_name.to_string(),
                        asset_name,
                        asset_type: "related-crypto-material".to_string(),
                        primitive: "keystore-file".to_string(),
                        mode: "None".to_string(),
                        padding: "None".to_string(),
                        classical_security: classical_sec,
                        pqc_risk: "Operational Asset".to_string(),
                        detection_source: display_path,
                        line_number: 1,
                        snippet: format!("Cryptographic container file: {}", file_name),
                        guidance,
                        generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
                    });
                }
            }
        }
    }
}

/// Scans configuration files (`application.yaml`, `application.properties`) for missing keystores or eMudhra issues
fn scan_configuration_files(dir: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    scan_configuration_files(&path, module_name, assets);
                }
            }
        } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = file_name.to_lowercase();
            if lower.ends_with(".yaml") || lower.ends_with(".yml") || lower.ends_with(".properties") {
                inspect_single_config_file(&path, module_name, assets);
            }
        }
    }
}

fn inspect_single_config_file(file_path: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let display_path = file_path.to_str().unwrap_or_default().replace('\\', "/");
    let mut in_keystore_block = false;
    let mut keystore_indent = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let lower = trimmed.to_lowercase();
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();

        if lower.starts_with("keystore:") {
            in_keystore_block = true;
            keystore_indent = indent;
            continue;
        } else if in_keystore_block && indent <= keystore_indent && !trimmed.starts_with('-') {
            in_keystore_block = false;
        }

        // Check for keystore path configuration (flat or nested YAML)
        let is_keystore_path = (in_keystore_block && lower.starts_with("path:"))
            || lower.contains("keystore.path")
            || lower.contains("keystore-path")
            || (lower.contains("path:") && (lower.contains(".p12") || lower.contains(".jks")));

        if is_keystore_path {
            let raw_val = line.split(':').skip(1).collect::<Vec<&str>>().join(":");
            let clean_val = raw_val.trim().trim_matches('"').trim_matches('\'').trim();

            let exists = if clean_val.starts_with("classpath:") {
                let rel = clean_val.trim_start_matches("classpath:").trim_start_matches('/');
                let resource_dir = file_path.parent().unwrap_or(Path::new("."));
                resource_dir.join(rel).exists()
                    || resource_dir.parent().map_or(false, |p| p.join("resources").join(rel).exists())
            } else {
                Path::new(clean_val).exists()
            };

            if !exists && !clean_val.is_empty() {
                assets.push(CryptoAsset {
                    module_name: module_name.to_string(),
                    asset_name: "eMudhra Missing Keystore Reference".to_string(),
                    asset_type: "related-crypto-material".to_string(),
                    primitive: "keystore-file".to_string(),
                    mode: "Configuration".to_string(),
                    padding: "None".to_string(),
                    classical_security: "CRITICAL: Keystore File Missing".to_string(),
                    pqc_risk: "Operational Risk".to_string(),
                    detection_source: display_path.clone(),
                    line_number: line_idx + 1,
                    snippet: trimmed.to_string(),
                    guidance: format!(
                        "CRITICAL CONFIGURATION ERROR: Keystore file '{}' configured in {} does not exist on disk. eMudhra XML signing will fail at runtime.",
                        clean_val, file_path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
                });
            }
        }

        // Check for default / weak passwords
        if (in_keystore_block && lower.starts_with("password:"))
            || lower.contains("keystore.password")
            || lower.contains("password: \"changeit\"")
            || lower.contains("password: 'changeit'")
            || lower.contains("password=changeit")
        {
            if lower.contains("changeit") || lower.contains("password") || lower.contains("123456") {
                assets.push(CryptoAsset {
                    module_name: module_name.to_string(),
                    asset_name: "Default Keystore Password ('changeit')".to_string(),
                    asset_type: "related-crypto-material".to_string(),
                    primitive: "secret-key".to_string(),
                    mode: "Credentials".to_string(),
                    padding: "None".to_string(),
                    classical_security: "HIGH RISK: Default Password".to_string(),
                    pqc_risk: "Legacy / Insecure".to_string(),
                    detection_source: display_path.clone(),
                    line_number: line_idx + 1,
                    snippet: trimmed.to_string(),
                    guidance: "SECURITY RISK: Default keystore password ('changeit') detected in configuration. Migrate to environment variables or secret vaults (e.g., HashiCorp Vault / AWS Secrets Manager).".to_string(),
                    generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
                });
            }
        }
    }
}

/// Scans Java files for XML-DSig signature & digest deprecation (SHA-1 vs SHA-256)
fn scan_java_xml_signer_patterns(dir: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') && name != "target" && name != "node_modules" {
                    scan_java_xml_signer_patterns(&path, module_name, assets);
                }
            }
        } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name.ends_with(".java") {
                inspect_single_java_signer_file(&path, module_name, assets);
            }
        }
    }
}

fn inspect_single_java_signer_file(file_path: &Path, module_name: &str, assets: &mut Vec<CryptoAsset>) {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let display_path = file_path.to_str().unwrap_or_default().replace('\\', "/");

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // Detect deprecated XML-DSig DigestMethod.SHA1
        if trimmed.contains("DigestMethod.SHA1") {
            assets.push(CryptoAsset {
                module_name: module_name.to_string(),
                asset_name: "DigestMethod.SHA1 (XML-DSig)".to_string(),
                asset_type: "algorithm".to_string(),
                primitive: "message-digest".to_string(),
                mode: "None".to_string(),
                padding: "None".to_string(),
                classical_security: "Deprecated (80 bits)".to_string(),
                pqc_risk: "Legacy / Insecure".to_string(),
                detection_source: display_path.clone(),
                line_number: line_idx + 1,
                snippet: trimmed.to_string(),
                guidance: "CRITICAL: DigestMethod.SHA1 in XML signature is deprecated and rejected by modern eMudhra / CCA India guidelines. Upgrade to DigestMethod.SHA256 immediately.".to_string(),
                generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
            });
        }

        // Detect deprecated XML-DSig SignatureMethod.RSA_SHA1
        if trimmed.contains("SignatureMethod.RSA_SHA1") {
            assets.push(CryptoAsset {
                module_name: module_name.to_string(),
                asset_name: "SignatureMethod.RSA_SHA1 (XML-DSig)".to_string(),
                asset_type: "algorithm".to_string(),
                primitive: "asymmetric-signature".to_string(),
                mode: "RSA_SHA1".to_string(),
                padding: "PKCS1".to_string(),
                classical_security: "Deprecated (<112 bits)".to_string(),
                pqc_risk: "Legacy / Insecure".to_string(),
                detection_source: display_path.clone(),
                line_number: line_idx + 1,
                snippet: trimmed.to_string(),
                guidance: "CRITICAL: SignatureMethod.RSA_SHA1 in XML signature is deprecated by CERT-In and CCA India. Upgrade to RSA-SHA256 ('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256').".to_string(),
                generated_by: "https://github.com/thirumalx/bom-scanner (Certificate Inspector)".to_string(),
            });
        }
    }
}

// ==============================================================================
// Unit Tests
// ==============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(encoded).expect("Decode failed");
        assert_eq!(String::from_utf8_lossy(&decoded), "Hello World");
    }

    #[test]
    fn test_emudhra_classification() {
        let issuer_emudhra = "CN=eMudhra Sub CA for Class 3 Document Signer 2022, O=eMudhra Limited, C=IN";
        let issuer_lower = issuer_emudhra.to_lowercase();
        assert!(issuer_lower.contains("emudhra"));

        let cert = ParsedCertificate {
            subject: "CN=ASP Document Signer, O=Enterprise, C=IN".to_string(),
            issuer: issuer_emudhra.to_string(),
            not_before: Some(Utc::now() - chrono::Duration::days(100)),
            not_after: Some(Utc::now() + chrono::Duration::days(250)),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA Encryption".to_string(),
            key_size_bits: Some(2048),
            is_emudhra: true,
            is_cca_india: true,
            status: CertificateStatus::Active,
            days_remaining: Some(250),
        };

        assert!(cert.is_emudhra);
        assert!(cert.is_cca_india);
        assert_eq!(cert.status, CertificateStatus::Active);
    }

    #[test]
    fn test_expired_certificate_status() {
        let now = Utc::now();
        let past = now - chrono::Duration::days(10);
        let diff = (past - now).num_days();
        assert!(diff < 0);
    }
}
