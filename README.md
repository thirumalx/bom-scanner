# NeSL SBOM & CBOM Automation Engine (`bom-scanner`)

A high-performance Rust automation engine designed to scan multi-module enterprise software repositories, generating compliant **Software Bills of Materials (SBOM)**, **Cryptographic Bills of Materials (CBOM)**, vulnerability assessments, and executive compliance registers.

Compliant with:
* **CERT-In Guidelines on SBOM / CBOM**
* **NeSL Third Party Risk Management Policy (`NeSL/FIN/L3/TRM/04` § 7.5)**
* **STPI Comprehensive Assessment Recommendations for NeSL IT Systems**
* **CycloneDX v1.6 (CBOM) & v1.7 (SBOM) Specifications**
* **OWASP Dependency-Track Integration Standards**

---

## Architecture & Output Layout

```
D:\Vulerability_SBOM_Reports/
├── CycloneDX/                # CycloneDX v1.7 SBOMs (*.cdx.json) with embedded CVEs & licenses
├── SPDX/                     # SPDX-JSON SBOMs (*.spdx.json) for STPI audits
├── HTML/                     # Interactive visual HTML vulnerability reports (*.html)
├── JSON/                     # Raw Trivy JSON vulnerability & package telemetry (*.json)
├── CBOM/                     # CycloneDX v1.6 Cryptographic Bills of Materials (*.cbom.json)
├── CBOM_Executive_Register.csv # Consolidated register of all algorithms, modes, keys, and PQC risks
└── SBOM_Executive_Summary.csv  # Consolidated executive register across all modules (Deps, CVEs)
```

---

## What Gets Scanned

### 1. Software Bill of Materials (SBOM) & Vulnerabilities
* Scans all Maven (`pom.xml`) and Ant (`build.xml`, `.jar`) projects.
* Runs in **offline mode (`--offline-scan`)** using Trivy's local vulnerability database to eliminate HTTP 429 rate limits from Maven Central.
* Identifies dependencies, licenses, and assigns severity ratings (Critical, High, Medium, Low).

### 2. Cryptographic Bill of Materials (CBOM)
* **Java Cryptography Architecture (JCA) Scanner**:
  * Inspects Java source code for calls to `Cipher`, `Signature`, `MessageDigest`, `Mac`, `KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory`, `KeyAgreement`, `KeyStore`, and `CertificateFactory`.
  * Extracts exact algorithms, modes, and padding schemes (e.g. `AES/CBC/PKCS7Padding`, `RSA/ECB/PKCS1Padding`, `SHA256withRSA`, `AES/GCM/NoPadding`).
* **Keystore & Certificate Discovery**:
  * Identifies on-disk keystores (`.jks`, `.p12`, `.pfx`), public certificates (`.cer`, `.crt`, `.pem`), and HSM configs (`sunpkcs11.cfg`).
* **Post-Quantum Cryptography (PQC) Risk Classification**:
  * Evaluates vulnerability against quantum attacks (Shor's / Grover's algorithms), essential for NeSL's **8-year Information Utility (IU) statutory retention rule**.
  * Catalogs whether algorithms are **Quantum-Resistant**, **Quantum-Vulnerable**, or **Legacy / Insecure** (e.g. MD5, SHA-1, DES).

---

## Quick Start

### Default Run (Scans All Modules in `D:\Vulerability`)
```cmd
cd D:\git-repo\bom-scanner
cargo run --release
```

Or run the pre-compiled binary directly:
```cmd
D:\git-repo\bom-scanner\target\release\bom-scanner.exe
```

---

## Command-Line Usage

```text
USAGE:
    bom-scanner [OPTIONS] [SOURCE_DIR] [OUTPUT_DIR]

ARGUMENTS:
    [SOURCE_DIR]    Directory containing modules (default: D:\Vulerability)
    [OUTPUT_DIR]    Directory to save reports (default: D:\Vulerability_SBOM_Reports)

OPTIONS:
    -s, --source <PATH>     Specify source directory containing project modules
    -o, --output <PATH>     Specify output directory for generated SBOMs & reports
    -t, --trivy <PATH>      Specify path to trivy.exe executable (default: D:\trivy.exe)
    --template <PATH>       Specify path to HTML report template (default: D:\html.tpl)
    --offline               Run in offline mode using local DB without remote repo queries (default)
    --online                Allow remote Maven repository queries (may trigger rate limits)
    -h, --help              Print help information
    -v, --version           Print version information
```

### Examples

#### Scan a single module directly:
```cmd
bom-scanner.exe -s "D:\Vulerability\NESL_Portal_Maven_Test" -o "D:\MyReports"
```

#### Scan all modules to custom output directory:
```cmd
bom-scanner.exe -s "D:\Vulerability" -o "D:\Vulerability_SBOM_Reports"
```

---

## Ingesting Reports into OWASP Dependency-Track

### 1. Ingesting CycloneDX SBOMs
```bash
curl -X POST "http://<dependency-track-host>:8081/api/v1/bom" \
  -H "X-Api-Key: <YOUR_API_KEY>" \
  -H "Content-Type: multipart/form-data" \
  -F "projectName=65BCertificateAPI" \
  -F "projectVersion=1.0" \
  -F "autoCreate=true" \
  -F "bom=@D:/Vulerability_SBOM_Reports/CycloneDX/65BCertificateAPI.cdx.json"
```

### 2. Ingesting CycloneDX 1.6 CBOMs
The files in `CBOM/<module>.cbom.json` conform to the CycloneDX 1.6 Cryptography Extension specification (`cryptoProperties`) and can be ingested directly into Dependency-Track or IBM CBOMkit viewers.
