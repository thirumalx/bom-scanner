# Multi-Module SBOM & CBOM Automation Engine (`bom-scanner`)

A high-performance Rust automation engine designed to scan multi-module enterprise software repositories, generating compliant **Software Bills of Materials (SBOM)**, **Cryptographic Bills of Materials (CBOM)**, comprehensive vulnerability assessments, and executive compliance registers.

Compliant with:
* **CERT-In Guidelines on SBOM / CBOM**
* **ISO/IEC 5230 (OpenChain Standard) & SPDX 2.3**
* **CycloneDX v1.6 (CBOM) & v1.7 (SBOM) Specifications**
* **NIST SP 800-161 & NIST SP 800-131A Security Requirements**
* **OWASP Dependency-Track Integration Standards**

---

## Key Features

1. **Self-Contained & Zero-Setup**:
   * **Automated Trivy Engine**: If Trivy is not detected, `bom-scanner` automatically downloads and configures the official Trivy binary for your OS and architecture. No separate download or unzipping required.
   * **Embedded HTML Template**: The visual vulnerability reporting template is embedded directly inside the binary.
2. **Comprehensive Multi-Scanner Coverage**:
   * Runs all security scanners: **Vulnerabilities (`vuln`)**, **Misconfigurations (`misconfig`)**, **Secrets Exposure (`secret`)**, and **Licenses (`license`)**.
   * Uses `--detection-priority comprehensive` and `--list-all-pkgs` for 100% complete package inventories.
3. **Structured Outputs**:
   * Separated directories for **SBOM (`/opt/bom/sbom`)** and **CBOM (`/opt/bom/cbom`)**.

---

## Output Layout

```
/opt/bom/
├── sbom/                          # Software Bill of Materials & Security Findings
│   ├── CycloneDX/                 # CycloneDX v1.7 SBOMs (*.cdx.json) with vuln, misconfig, secrets, licenses
│   ├── SPDX/                      # SPDX-JSON SBOMs (*.spdx.json) ISO/IEC 5230 compliant
│   ├── HTML/                      # Interactive visual HTML vulnerability reports (*.html, with attribution)
│   ├── JSON/                      # Comprehensive Trivy JSON telemetry (--list-all-pkgs) (*.json)
│   └── SBOM_Executive_Summary.xlsx # Formatted executive Excel workbook (with attribution)
└── cbom/                          # Cryptographic Bill of Materials & PQC Governance
    ├── Executive/                 # Consolidated enterprise-wide governance artifacts
    │   ├── CBOM_Executive_Dashboard.html # Consolidated enterprise-wide visual CBOM dashboard (with attribution)
    │   └── CBOM_Executive_Register.xlsx  # Formatted executive Excel workbook (with attribution)
    ├── <module>.cbom.json         # CycloneDX v1.6 Cryptographic Bills of Materials
    └── <module>.html              # Interactive visual CBOM reports with code snippets & remediation
```

---

## What Gets Scanned

### 1. Software Bill of Materials (SBOM) & Comprehensive Security
* Scans Maven (`pom.xml`) and Ant (`build.xml`, `.jar`) projects.
* Runs in **offline mode (`--offline-scan`)** using Trivy's local database to eliminate remote rate limits.
* Enabled scanners:
  * `--scanners vuln,misconfig,secret,license`
  * `--list-all-pkgs` (ensures 100% of dependencies are cataloged in telemetry)
  * `--detection-priority comprehensive`
  * `--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`

### 2. Cryptographic Bill of Materials (CBOM)
* **Java Cryptography Architecture (JCA) Scanner**:
  * Inspects Java source code for calls to `Cipher`, `Signature`, `MessageDigest`, `Mac`, `KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory`, `KeyAgreement`, `KeyStore`, and `CertificateFactory`.
  * Extracts exact algorithms, modes, and padding schemes (e.g. `AES/CBC/PKCS7Padding`, `RSA/ECB/PKCS1Padding`, `SHA256withRSA`, `AES/GCM/NoPadding`).
* **Keystore & Certificate Discovery**:
  * Identifies on-disk keystores (`.jks`, `.p12`, `.pfx`), public certificates (`.cer`, `.crt`, `.pem`), and HSM configs (`sunpkcs11.cfg`).
* **Post-Quantum Cryptography (PQC) Risk Classification**:
  * Evaluates vulnerability against quantum attacks (Shor's / Grover's algorithms) to plan migration to Post-Quantum Cryptography (NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA).
  * Catalogs whether algorithms are **Quantum-Resistant**, **Quantum-Vulnerable**, or **Legacy / Insecure** (e.g. MD5, SHA-1, DES).

---

## Quick Start

### Interactive Mode (Default when run without arguments)
When run without parameters, `bom-scanner` presents a guided configuration wizard pre-populated with `/opt` defaults:
```cmd
D:\git-repo\bom-scanner\target\release\bom-scanner.exe
```
*(Press **Enter** to accept each suggested default, or type a custom path.)*

---

## Command-Line Usage

```text
USAGE:
    bom-scanner [OPTIONS] [SOURCE_DIR] [OUTPUT_DIR]

ARGUMENTS:
    [SOURCE_DIR]    Directory containing modules (default: /opt/repository)
    [OUTPUT_DIR]    Base directory to save reports (default: /opt/bom -> /opt/bom/sbom & /opt/bom/cbom)

OPTIONS:
    -s, --source <PATH>     Specify source directory containing project modules (default: /opt/repository)
    -m, --module <NAME>     Scan only the specified module by name or directory
    -o, --output <PATH>     Specify base output directory (creates <PATH>/sbom and <PATH>/cbom)
    --sbom-only             Generate only Software Bill of Materials (SBOM) & CVE assessments
    --cbom-only             Generate only Cryptographic Bill of Materials (CBOM) & PQC analysis
    --bom <TYPE>            Specify BOM generation type: sbom, cbom, or all (default: all)
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
```

### Examples

#### 1. Interactive setup (Guided Wizard):
```cmd
bom-scanner.exe
```
Prompts for module selection (or 'all') and target BOM type (`all`, `sbom`, or `cbom`).

#### 2. Scan only a single module from a multi-module repository:
```bash
# Scan a specific module for both SBOM & CBOM
bom-scanner -s /opt/repository -m PaymentService -o /opt/bom

# Or point directly to the module directory as source:
bom-scanner -s /opt/repository/PaymentService -o /opt/bom
```

#### 3. Scan only CBOM (Cryptographic Bill of Materials & PQC):
Runs purely using the internal Rust regex & keystore discovery engine in milliseconds (bypasses Trivy download & scans completely):
```bash
# All modules, CBOM only
bom-scanner -s /opt/repository --cbom-only -o /opt/bom

# Single module, CBOM only (lightning-fast)
bom-scanner -s /opt/repository -m PaymentService --cbom-only -o /opt/bom
```

#### 4. Scan only SBOM (Software Bill of Materials & Security Findings):
```bash
# All modules, SBOM only
bom-scanner -s /opt/repository --sbom-only -o /opt/bom

# Single module, SBOM only
bom-scanner -s /opt/repository -m PaymentService --sbom-only -o /opt/bom
```

#### 5. Default run with `/opt` defaults in batch mode:
```bash
bom-scanner -y
```

#### 6. Custom paths:
```bash
bom-scanner -s "/path/to/source" -o "/path/to/output"
```
*(Automatically creates `/path/to/output/sbom` and `/path/to/output/cbom`.)*

---

## SBOM visualization tool

* Upload `\opt\bom\sbom\CycloneDX\xxxx.cdx` to visualize tool [sunshine](https://cyclonedx.github.io/Sunshine/)

## Ingesting Reports into OWASP Dependency-Track

### 1. Ingesting CycloneDX SBOMs
```bash
curl -X POST "http://<dependency-track-host>:8081/api/v1/bom" \
  -H "X-Api-Key: <YOUR_API_KEY>" \
  -H "Content-Type: multipart/form-data" \
  -F "projectName=SampleModule" \
  -F "projectVersion=1.0" \
  -F "autoCreate=true" \
  -F "bom=@/opt/bom/sbom/CycloneDX/SampleModule.cdx.json"
```

### 2. Ingesting CycloneDX 1.6 CBOMs
The files in `/opt/bom/cbom/<module>.cbom.json` conform to the CycloneDX 1.6 Cryptography Extension specification (`cryptoProperties`) and can be ingested directly into Dependency-Track or IBM CBOMkit viewers.


## Sample Output

[sample-output](sample-output/)
  [sample-output/cbom/](sample-output/cbom/)
      [sample-output/cbom/oauth-authorization-server.html](sample-output/cbom/oauth-authorization-server.html)
      [](sample-output/cbom/oauth-authorization-server.cbom.json)
      [](sample-output/cbom/Executive/)
        [](sample-output/cbom/Executive/CBOM_Executive_Dashboard.html)
        [](sample-output/cbom/Executive/CBOM_Executive_Register.xlsx)
  [](sample-output/sbom/)
    [](sample-output/sbom/CycloneDX/oauth-authorization-server.cdx.json)
    [](sample-output/sbom/HTML/oauth-authorization-server.html)
    [](sample-output/sbom/JSON/oauth-authorization-server.json)
    [](sample-output/sbom/SBOM_Executive_Summary.xlsx)
    [](sample-output/sbom/SPDX/oauth-authorization-server.spdx.json) 
