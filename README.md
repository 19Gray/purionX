<div align="center">

```
 ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗
██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██║ █╗ ██║███████║███████╗██████╔╝
██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝
╚██████╔╝╚███╔███╔╝██║  ██║███████║██║
 ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**A fast, zero-dependency static analysis tool written in Rust**
**that scans your codebase for OWASP Top 10 vulnerabilities**

[![CI](https://github.com/19Gray/owasp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/19Gray/owasp-scanner/actions)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-red.svg)](https://owasp.org/Top10/)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Covered Vulnerabilities](#covered-vulnerabilities)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output Examples](#output-examples)
- [CI/CD Integration](#cicd-integration)
- [Severity Levels](#severity-levels)
- [Detection Rules](#detection-rules)
- [Supported File Types](#supported-file-types)
- [Exit Codes](#exit-codes)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

---

## Overview

**OWASP Scanner** is a static analysis CLI tool built in Rust that detects security vulnerabilities in source code and configuration files — before they reach production.

It scans your entire codebase in seconds with no external services, no API keys, and no cloud uploads. Every analysis runs entirely on your machine.

### Why OWASP Scanner?

Most security tools are slow, expensive, or cloud-dependent. OWASP Scanner is:

- **Fast** — compiled Rust with parallel file walking; scans thousands of files in under a second
- **Offline** — zero network calls, runs in air-gapped environments
- **CI-native** — exits with code `1` on HIGH/CRITICAL findings to block insecure merges
- **Multi-format** — Console, JSON, SARIF (GitHub Security tab), and HTML reports
- **Extensible** — adding new detection rules is a one-liner in the relevant `rules/aXX.rs` file

---

## Covered Vulnerabilities

| ID      | Category                                                                                                 | Patterns Detected                                                                                                       |
| ------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **A01** | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)                         | chmod 777, bypass-auth flags, unguarded routes, IDOR in queries, path traversal, client-supplied roles                  |
| **A02** | [Security Misconfiguration](https://owasp.org/Top10/A02_2021-Security_Misconfiguration/)                 | DEBUG=true, weak secret keys, wildcard CORS, disabled TLS verify, empty passwords, default credentials, 0.0.0.0 binding |
| **A03** | [Software Supply Chain Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) | Unpinned Cargo deps, known-CVE crates, dynamic library loading, eval/exec abuse, shell injection patterns               |
| **A04** | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)                       | MD5/SHA-1, DES/RC4/ECB, hardcoded keys/IVs, non-crypto RNG, deprecated TLS versions, timing attacks, short key sizes    |

---

## Architecture

This project is a **Cargo workspace** with three crates, each with a single responsibility:

```
owasp-scanner/
├── Cargo.toml                        ← Workspace root (shared dependencies)
├── Cargo.lock                        ← Lock file (commit this!)
├── .github/
│   └── workflows/
│       └── ci.yml                    ← CI pipeline (test + self-scan + cross-platform build)
└── crates/
    ├── scanner-core/                 ← Detection engine (pure library, no I/O)
    │   └── src/
    │       ├── lib.rs                ← Public API re-exports
    │       ├── finding.rs            ← Finding, Severity, ScanResult, OwaspCategory types
    │       ├── scanner.rs            ← File walker and scan orchestrator
    │       └── rules/
    │           ├── mod.rs            ← Rule struct and apply_rules() engine
    │           ├── a01.rs            ← Broken Access Control rules
    │           ├── a02.rs            ← Security Misconfiguration rules
    │           ├── a03.rs            ← Supply Chain Failures rules
    │           └── a04.rs            ← Cryptographic Failures rules
    ├── scanner-report/               ← Output formatters (depends on scanner-core)
    │   └── src/
    │       ├── lib.rs                ← OutputFormat enum and write_report()
    │       ├── console.rs            ← ANSI colored terminal output
    │       ├── json.rs               ← Structured JSON output
    │       ├── sarif.rs              ← SARIF 2.1.0 for GitHub Code Scanning
    │       └── html.rs               ← Self-contained HTML dashboard
    └── scanner-cli/                  ← Binary entry point (depends on both above)
        └── src/
            └── main.rs               ← Clap CLI, argument parsing, exit codes
```

### Data Flow

```
Target path
    │
    ▼
scanner.rs ──► walks files ──► filters by extension / name
    │
    ▼
For each file:
  a01::scan()  ──►  apply_rules()  ──►  regex match per line  ──►  Vec<Finding>
  a02::scan()  ──┘
  a03::scan()  ──┘   (Cargo.toml gets special CVE-lookup logic)
  a04::scan()  ──┘
    │
    ▼
Assign sequential IDs  ──►  filter by --min-severity
    │
    ▼
ScanResult { target, scanned_at, findings }
    │
    ▼
write_report()  ──►  Console | JSON | SARIF | HTML
    │
    ▼
Exit code 0 (clean)  or  1 (HIGH / CRITICAL found)
```

---

## Prerequisites

- **Rust 1.75+** — install via [rustup](https://rustup.rs)
- No other system dependencies required

```bash
# Install Rust if you haven't already
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version   # should print 1.75.0 or higher
```

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/19Gray/owasp-scanner.git
cd owasp-scanner

# Build the release binary
cargo build --release -p scanner-cli

# The binary is now at:
./target/release/owasp-scan --help

# Optionally install it globally
cargo install --path crates/scanner-cli
owasp-scan --help
```

### Setting Up from the Zip

If you received this as a zip or are migrating from a `cargo new` single-crate project:

```bash
# 1. Unzip into your project root
unzip owasp_workspace.zip
cp -r owasp_workspace/* ./OWASP_SCANNER/

# 2. Remove the old single-crate src/ folder
cd OWASP_SCANNER
rm -rf src/

# 3. Verify the workspace compiles
cargo check --workspace

# 4. Build the release binary
cargo build --release

# 5. Run it
./target/release/owasp-scan . --format console
```

---

## Usage

### Basic Scanning

```bash
# Scan a single file
owasp-scan path/to/main.rs

# Scan an entire project directory
owasp-scan ./my_project

# Scan the current directory
owasp-scan .
```

### Output Formats

```bash
# Colored terminal output (default)
owasp-scan . --format console

# JSON report saved to file
owasp-scan . --format json --out report.json

# SARIF 2.1.0 (for GitHub Code Scanning / Security tab)
owasp-scan . --format sarif --out results.sarif

# Self-contained HTML dashboard
owasp-scan . --format html --out report.html
```

### Filtering by Severity

```bash
# Only show HIGH and CRITICAL (recommended for CI gate)
owasp-scan . --min-severity high

# Only show CRITICAL
owasp-scan . --min-severity critical

# Show everything including INFO hints
owasp-scan . --min-severity info
```

### Scan Without Failing the Pipeline

```bash
# Always exit 0 — useful for reporting without blocking
owasp-scan . --no-fail --format json --out report.json
```

### Full CLI Reference

```
USAGE:
    owasp-scan [OPTIONS] <TARGET>

ARGUMENTS:
    <TARGET>    File or directory to scan

OPTIONS:
    -f, --format <FORMAT>
            Output format [default: console]
            [possible values: console, json, sarif, html]

    -o, --out <FILE>
            Write output to FILE instead of stdout
            (applies to json, sarif, and html formats)

    -m, --min-severity <MIN_SEVERITY>
            Only report findings at or above this level [default: info]
            [possible values: info, low, medium, high, critical]

        --no-fail
            Exit with code 0 even when HIGH or CRITICAL findings are present

    -h, --help
            Print help information

    -V, --version
            Print version information
```

---

## Output Examples

### Console Output

```
======================================================================
  OWASP Vulnerability Scanner - Report
  Target   : ./my_project
  Scanned  : 2026-03-05T12:00:00+00:00
  Findings : 4
  Summary  : CRITICAL:1  HIGH:2  MEDIUM:1  LOW:0  INFO:0
======================================================================

  [0001] [CRITICAL]  A01 - Broken Access Control
         Title   : Role or privilege derived directly from user-supplied request data
         File    : src/handlers/auth.rs:42
         Snippet : let is_admin = req.params["is_admin"];
         Fix     : Never trust client-supplied role data; read from server-side session or JWT claims.

  [0002] [HIGH]  A04 - Cryptographic Failures
         Title   : Use of MD5 hash - cryptographically broken
         File    : src/utils/hash.rs:17
         Snippet : let digest = md5::compute(data);
         Fix     : Replace MD5 with SHA-256 or SHA-3; use Argon2 for passwords.

  [0003] [HIGH]  A02 - Security Misconfiguration
         Title   : SSL/TLS certificate verification disabled
         File    : src/client.rs:33
         Snippet : .danger_accept_invalid_certs(true)
         Fix     : Never disable TLS verification; use a trusted CA bundle.

  [0004] [MEDIUM]  A03 - Software Supply Chain Failures
         Title   : Unpinned or wildcard dependency version
         File    : Cargo.toml:18
         Snippet : some-crate = "*"
         Fix     : Pin every dependency to an exact version and commit Cargo.lock to VCS.
```

### JSON Output

```json
{
  "target": "./my_project",
  "scanned_at": "2026-03-05T12:00:00+00:00",
  "findings": [
    {
      "id": 1,
      "category": "A01BrokenAccessControl",
      "title": "Role or privilege derived directly from user-supplied request data",
      "severity": "CRITICAL",
      "file": "src/handlers/auth.rs",
      "line": 42,
      "snippet": "let is_admin = req.params[\"is_admin\"];",
      "recommendation": "Never trust client-supplied role data; read from server-side session or JWT claims."
    }
  ]
}
```

### SARIF Output

SARIF 2.1.0 format, compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-aware tool.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "owasp-scanner",
        "version": "1.0.0",
        "rules": [ ... ]
      }
    },
    "results": [{
      "ruleId": "A01-Broken-Access-Control",
      "level": "error",
      "message": { "text": "Role derived from user input - fix: read from session." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/handlers/auth.rs" },
          "region": { "startLine": 42 }
        }
      }]
    }]
  }]
}
```

### HTML Report

The HTML report is a fully self-contained single-file dashboard with:

- Color-coded severity summary cards at the top
- Sortable findings table with inline code snippets
- Per-finding remediation guidance
- No external dependencies — works fully offline, shareable as a single file

```bash
owasp-scan . --format html --out report.html
open report.html   # macOS
xdg-open report.html   # Linux
start report.html   # Windows
```

---

## CI/CD Integration

### GitHub Actions

The included workflow at `.github/workflows/ci.yml` does three things automatically on every push and pull request:

**1. Build & Test** — runs `cargo fmt`, `cargo clippy`, and `cargo test` across the entire workspace.

**2. Self-Scan** — runs the scanner against its own source code and uploads SARIF to GitHub's Security tab.

**3. Cross-platform release builds** — compiles binaries for Linux, Windows, and macOS, uploaded as artifacts.

```yaml
# Key security scan step (from ci.yml)
- name: Run OWASP scan to SARIF
  run: |
    ./target/release/owasp-scan . \
      --format sarif \
      --out results.sarif \
      --min-severity medium \
      --no-fail

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Fail build on HIGH+ findings
  run: ./target/release/owasp-scan . --min-severity high
```

After the SARIF upload, findings appear under **Security → Code scanning alerts** in your repository.

### GitLab CI

```yaml
owasp-scan:
  image: rust:latest
  stage: security
  script:
    - cargo build --release -p scanner-cli
    - ./target/release/owasp-scan . --format sarif --out gl-sast-report.sarif --no-fail
    - ./target/release/owasp-scan . --min-severity high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - gl-sast-report.sarif
    when: always
```

### Pre-commit Hook

Block commits that introduce HIGH or CRITICAL vulnerabilities:

```bash
# Create the hook file
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
owasp-scan . --min-severity high --no-color
if [ $? -ne 0 ]; then
  echo ""
  echo "OWASP scan found HIGH or CRITICAL issues. Fix them before committing."
  exit 1
fi
EOF

chmod +x .git/hooks/pre-commit
```

---

## Severity Levels

| Level      | Color      | Description                                                  | Blocks CI? |
| ---------- | ---------- | ------------------------------------------------------------ | ---------- |
| `CRITICAL` | Red (bold) | Exploitable with immediate impact — must fix before shipping | Yes        |
| `HIGH`     | Red        | Significant risk — fix before merging to main                | Yes        |
| `MEDIUM`   | Yellow     | Notable weakness — schedule fix in current sprint            | No         |
| `LOW`      | Cyan       | Minor issue or defence-in-depth improvement                  | No         |
| `INFO`     | White      | Best-practice suggestion                                     | No         |

The scanner exits with code `1` if any **HIGH or CRITICAL** finding is present. Use `--no-fail` to override this for reporting-only workflows.

---

## Detection Rules

### A01 — Broken Access Control

Broken access control means a user can act outside their intended permissions. The scanner looks for patterns where access decisions are made incorrectly or bypassed.

| Severity | Rule                          | Example                               |
| -------- | ----------------------------- | ------------------------------------- |
| CRITICAL | Bypass-auth flag enabled      | `bypass_auth = true`                  |
| CRITICAL | Role derived from request     | `is_admin = req.params["is_admin"]`   |
| HIGH     | World-writable permissions    | `chmod(path, 0o777)`                  |
| HIGH     | IDOR in SQL query             | `SELECT * WHERE id = $user_input`     |
| HIGH     | Path traversal in file access | `File::open("../../etc/passwd")`      |
| MEDIUM   | Route without auth guard      | `#[get("/admin")]` without middleware |

### A02 — Security Misconfiguration

Misconfiguration is the most common vulnerability category. It includes insecure default settings, incomplete configurations, and overly permissive values.

| Severity | Rule                            | Example                              |
| -------- | ------------------------------- | ------------------------------------ |
| CRITICAL | Short hard-coded secret key     | `SECRET_KEY = "abc123"`              |
| CRITICAL | Empty password in source        | `password = ""`                      |
| HIGH     | Debug mode on                   | `DEBUG = true`                       |
| HIGH     | TLS verification disabled       | `.danger_accept_invalid_certs(true)` |
| HIGH     | Default / known-weak credential | `password = "admin"`                 |
| MEDIUM   | Wildcard CORS                   | `Access-Control-Allow-Origin: *`     |
| MEDIUM   | Bind all interfaces             | `host = "0.0.0.0"`                   |
| MEDIUM   | Clickjacking header             | `X-Frame-Options: ALLOWALL`          |

### A03 — Software Supply Chain Failures

Supply chain attacks target the integrity of software components, build tools, and update mechanisms. The scanner checks both `Cargo.toml` dependency declarations and source-level dynamic loading patterns.

| Severity | Rule                     | Example                                       |
| -------- | ------------------------ | --------------------------------------------- |
| HIGH     | Dynamic library loading  | `libloading::Library::new(name)`              |
| HIGH     | eval / exec call         | `eval(user_input)`                            |
| HIGH     | Shell with string concat | `Command::new(base + arg)`                    |
| HIGH     | Known-CVE crate version  | `openssl = "0.9.1"`                           |
| MEDIUM   | Runtime script fetch     | `reqwest.get("https://example.com/setup.sh")` |
| MEDIUM   | Unpinned dependency      | `some-crate = "*"`                            |

**Known vulnerable crates currently tracked:**

| Crate       | Affected Version | Advisory Summary                      |
| ----------- | ---------------- | ------------------------------------- |
| `openssl`   | 0.9.x            | Multiple memory-safety CVEs           |
| `openssl`   | 0.10.24          | CVE-2021-3711 buffer overflow         |
| `actix-web` | 1.x              | End-of-life, no security patches      |
| `tokio`     | 1.0.0            | CVE-2021-45710 data race              |
| `ring`      | 0.16.11          | ECDSA side-channel attack             |
| `hyper`     | 0.14.1           | Header injection risk                 |
| `diesel`    | 1.x              | End-of-life, missing security patches |
| `reqwest`   | 0.10.0           | TLS downgrade possible                |

### A04 — Cryptographic Failures

Cryptographic failures occur when sensitive data is inadequately protected due to broken algorithms, weak keys, or poor implementation choices.

| Severity | Rule                   | Example                          |
| -------- | ---------------------- | -------------------------------- |
| CRITICAL | Deprecated cipher      | `DES::new(key)`, `Rc4::new(key)` |
| CRITICAL | Hardcoded key or IV    | `let key = b"deadbeefdeadbeef"`  |
| HIGH     | MD5 hash               | `md5::compute(data)`             |
| HIGH     | SHA-1 hash             | `sha1::Sha1::new()`              |
| HIGH     | AES in ECB mode        | `Aes256Ecb::new(...)`            |
| HIGH     | Deprecated TLS version | `TlsV1_0`, `SslV3` constants     |
| HIGH     | Short key size         | `key_size = 1024`                |
| MEDIUM   | Non-cryptographic RNG  | `thread_rng().gen()` for tokens  |
| MEDIUM   | Timing attack via ==   | `if token == user_token`         |
| MEDIUM   | Base64 as encryption   | `base64::encode(password)`       |

---

## Supported File Types

The scanner automatically identifies files by extension or well-known name:

| Source Extensions                           | Config / Manifest Names        |
| ------------------------------------------- | ------------------------------ |
| `.rs` `.py` `.go`                           | `Cargo.toml` / `Cargo.lock`    |
| `.js` `.ts` `.java` `.kt`                   | `requirements.txt` / `Pipfile` |
| `.toml` `.yaml` `.yml`                      | `package.json` / `go.mod`      |
| `.json` `.env` `.cfg` `.ini` `.conf` `.txt` | `.env`                         |

The following directories are skipped automatically: `.git`, `target`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `dist`.

---

## Exit Codes

| Code | When                                           |
| ---- | ---------------------------------------------- |
| `0`  | Scan completed — no HIGH or CRITICAL findings  |
| `0`  | Scan completed with `--no-fail` flag           |
| `1`  | One or more HIGH or CRITICAL findings detected |
| `1`  | Scanner error (target not found, I/O failure)  |

---

## Contributing

Contributions are welcome. Here's how to get involved:

### Adding a New Detection Rule

Open the relevant rule file under `crates/scanner-core/src/rules/` and add a new entry to the `RULES` static vector:

```rust
Rule {
    category:       OwaspCategory::A01BrokenAccessControl,
    title:          "Your descriptive rule title",
    severity:       Severity::High,
    recommendation: "Concrete, actionable remediation guidance.",
    pattern: Regex::new(r"(?i)your_regex_pattern").unwrap(),
},
```

### Development Workflow

```bash
# Run all tests
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run Clippy lints
cargo clippy --all-targets --all-features -- -D warnings

# Build and self-scan
cargo build --release -p scanner-cli
./target/release/owasp-scan . --min-severity medium
```

### Reporting Issues

Open a GitHub issue with the following details:

- File type and language where the issue occurred
- The offending or missed line of code (anonymize if needed)
- Whether it is a **false positive** (incorrectly flagged) or **false negative** (missed vulnerability)
- The OWASP category it relates to (A01–A04)

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [A02:2021 Security Misconfiguration](https://owasp.org/Top10/A02_2021-Security_Misconfiguration/)
- [A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Code Scanning — SARIF Upload](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)
- [RustSec Advisory Database](https://rustsec.org/)
- [Rust Secure Coding Guidelines](https://anssi-fr.github.io/rust-guide/)

---

## License

MIT License — see [LICENSE](LICENSE) for full terms.

---

<div align="center">
Built with Rust — fast, safe, and fearless.
</div>
