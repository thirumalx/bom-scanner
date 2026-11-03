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
│   ├── CERT-In/                   # CERT-In 21-Field Compliant SBOM Reports & Executive Dashboard
│   │   ├── CERT-In_Executive_SBOM.html # Consolidated enterprise-wide visual CERT-In dashboard
│   │   └── <module>.cert-in.html       # Interactive 21-field visual SBOM report & CSV export
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


## CERT-In 21-Field SBOM Compliance

`bom-scanner` automatically generates CERT-In compliant visual HTML reports and audit-ready CSV exports populated with all **21 mandatory fields** mandated by the **Indian Computer Emergency Response Team (CERT-In)** for software supply chain security:

| Sl.No | Field Name | Description & Regulatory Purpose | Source Mapping in `bom-scanner` |
|:-----:|:-----------|:---------------------------------|:--------------------------------|
| **1** | **Component Name** | The name of the software component or library included in the SBOM. | Extracted from `component.name` (Maven artifactId, NPM package name). |
| **2** | **Component Version** | The version number or identifier of the software component. | Extracted from `component.version` (Semantic version / snapshot). |
| **3** | **Component Description** | A brief description or summary of the functionality and purpose of the software component. | Extracted from `component.description` or contextual framework descriptor. |
| **4** | **Component Supplier** | The entity or organization that supplied the software component (vendor, supplier, or OSS project). | Mapped from `supplier.name`, `component.group`, or verified upstream ecosystem. |
| **5** | **Component License** | The license under which the software component is distributed (license type, terms, restrictions). | Resolved from `component.licenses[]` (e.g. Apache-2.0, MIT, BSD-3-Clause, EPL-2.0). |
| **6** | **Component Origin** | Source or origin (proprietary, in-house, open-source, or third-party vendor). | Evaluated via Package URL ecosystem (`pkg:maven`, `pkg:npm`, internal group). |
| **7** | **Component Dependencies** | Software components or libraries that the current component depends on (names & versions). | Extracted from CycloneDX `dependencies[].dependsOn` dependency tree mapping. |
| **8** | **Vulnerabilities** | Known security vulnerabilities or weaknesses (CVE ID, severity, CVSS scores, advisories). | Correlated from Trivy vulnerability engine (`vulnerabilities[]` & NVD/GHSA). |
| **9** | **Patch Status** | Update status of the software component, indicating whether patches are available to address known issues. | Computed from `vulnerability.recommendation` and fixed version catalogs. |
| **10** | **Release Date** | The date when the software component was released or made available for use. | Derived from component release baseline version & registry metadata. |
| **11** | **End-of-Life (EOL) Date** | Date when support or maintenance is scheduled to end, indicating the end of lifecycle. | Tracked via upstream maintenance lifecycle status (`Active / Maintained`). |
| **12** | **Criticality** | Importance to the overall functionality or security of the application (Critical, High, Medium, Low). | Risk-scored based on CVSS severity, runtime exploitability, and core vs transitive role. |
| **13** | **Usage Restrictions** | Restrictions or limitations (e.g., reciprocal copyleft terms, commercial constraints, export controls). | Automatically classified based on license category (Permissive vs Reciprocal Copyleft). |
| **14** | **Checksums or Hashes** | Cryptographic checksums or hashes of software component files for integrity and authenticity. | Extracted from `component.hashes[]` (SHA-256 / SHA-1) or package registry digest. |
| **15** | **Comments or Notes** | Additional comments, notes, or annotations relevant to the software component. | Contextual scanner auditing notes, package manager, and scan scope. |
| **16** | **Author of SBOM Data** | The name of the entity that creates the SBOM data for this component. | Standardized as `Aqua Security Trivy & bom-scanner Engine (thirumalx/bom-scanner)`. |
| **17** | **Timestamp** | Record of the date and time of the SBOM data assembly. | ISO 8601 assembly timestamp recorded at time of SBOM compilation. |
| **18** | **Executable Property** | Attributes indicating whether a component within an SBOM can be executed. | Categorized by execution model (Standalone Executable, JVM Bytecode, Node.js). |
| **19** | **Archive Property** | Characteristics denoting if a component is stored as an archive or compressed file. | Categorized by packaging structure (JAR/WAR Archive, TGZ Tarball, Flat Manifest). |
| **20** | **Structured Property** | Descriptors defining the organized format of data within a component listed in an SBOM. | Structural format descriptors (JVM Bytecode Archive, Node.js Module, XML POM). |
| **21** | **Unique Identifier** | Distinct code assigned to each software component ensuring accurate tracking and management. | Standard Package URL (`purl`, e.g., `pkg:maven/group/artifact@version`) or `bom-ref`. |

### Generated CERT-In HTML Artifacts
1. **Module Reports (`/opt/bom/sbom/CERT-In/<module>.cert-in.html`)**:
   * Interactive 21-column data table with sticky headers.
   * Executive KPI metric cards (Total Components, Clean vs Vulnerable, Critical/High CVEs, Open Source vs Proprietary).
   * Real-time search and filter controls (All, Vulnerable Only, Critical & High, Clean).
   * **1-Click RFC-4180 CSV Export**: Generates a standard `.csv` spreadsheet with all 21 CERT-In fields for regulatory submission.
   * Print-ready stylesheet for PDF generation.
2. **Executive Consolidated Dashboard (`/opt/bom/sbom/CERT-In/CERT-In_Executive_SBOM.html`)**:
   * Enterprise-wide roll-up across all scanned modules.
   * Portfolio compliance statistics and vulnerability matrix.
   * 1-Click export of the entire enterprise portfolio into a unified 21-field CSV.

---

## Sample Output Structure

- [`sample-output/`](sample-output/)
  - [`cbom/`](sample-output/cbom/)
    - [`oauth-authorization-server.html`](sample-output/cbom/oauth-authorization-server.html)
    - [`oauth-authorization-server.cbom.json`](sample-output/cbom/oauth-authorization-server.cbom.json)
    - `Executive/`
      - [`CBOM_Executive_Dashboard.html`](sample-output/cbom/Executive/CBOM_Executive_Dashboard.html)
      - [`CBOM_Executive_Register.xlsx`](sample-output/cbom/Executive/CBOM_Executive_Register.xlsx)
  - `sbom/`
    - `CERT-In/`
      - [`CERT-In_Executive_SBOM.html`](sample-output/sbom/CERT-In/CERT-In_Executive_SBOM.html)
      - [`oauth-authorization-server.cert-in.html`](sample-output/sbom/CERT-In/oauth-authorization-server.cert-in.html)
    - `CycloneDX/`
      - [`oauth-authorization-server.cdx.json`](sample-output/sbom/CycloneDX/oauth-authorization-server.cdx.json)
    - `HTML/`
      - [`oauth-authorization-server.html`](sample-output/sbom/HTML/oauth-authorization-server.html)
    - `JSON/`
      - [`oauth-authorization-server.json`](sample-output/sbom/JSON/oauth-authorization-server.json)
    - [`SBOM_Executive_Summary.xlsx`](sample-output/sbom/SBOM_Executive_Summary.xlsx)
    - `SPDX/`
      - [`oauth-authorization-server.spdx.json`](sample-output/sbom/SPDX/oauth-authorization-server.spdx.json)
