# CLI Usage Guide: lh-container-auditor

An enterprise container security posture & dockerfile auditor developed by **Logihertz Systems (OPC) Private Limited**.

`lh-container-auditor` provides a high-performance command-line interface accessible via `lh-container` (and alias `lh-container`, `lh-container-auditor`).

---

## 1. Installation

### Using `uv` (Recommended)

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## 2. Command Reference

### Primary Invocation

```bash
# Basic inspection of target file or directory
lh-container scan <path>

# Output machine-readable JSON
lh-container scan <path> --format json

# Export OASIS SARIF v2.1.0 to a file
lh-container scan <path> --format sarif --output audit-results.sarif

# List all registered detection rules
lh-container rules
```

---

## 3. Options & Flags

| Flag | Type | Default | Description |
|:---|:---:|:---:|:---|
| `--format` | `table\|json\|sarif` | `table` | Output presentation format. |
| `--output`, `-o` | `PATH` | `stdout` | Write output report to specified file path. |
| `--min-severity` | `CRITICAL\|HIGH\|MEDIUM\|LOW` | `LOW` | Filter out findings with severity below this threshold. |
| `--fail-on` | `CRITICAL\|HIGH\|MEDIUM\|LOW` | `None` | Trigger exit code 1 if any finding meets or exceeds threshold. |

---

## 4. Exit Codes

`lh-container-auditor` returns standardized exit codes for CI/CD pipeline automation:

| Exit Code | Meaning | Action in CI/CD |
|:---:|:---|:---|
| `0` | All audits passed; no matching policy violations detected. | Build proceeds successfully. |
| `1` | One or more security findings or policy violations detected. | Build fails or flags review required. |
| `2` | Execution error (invalid arguments, file not found, parse failure). | Check CLI syntax and input paths. |

---

## 5. CI/CD Integration Examples

### GitHub Actions (OASIS SARIF v2.1.0 Upload)

Integrate directly into the GitHub Advanced Security Code Scanning tab:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    name: lh-container-auditor Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: "latest"

      - name: Set up Python
        run: uv python install 3.11

      - name: Install Tool
        run: uv pip install .

      - name: Run Security Audit
        run: |
          lh-container scan . --format sarif --output lh-container-auditor-results.sarif --fail-on CRITICAL
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: lh-container-auditor-results.sarif
          category: lh-container-auditor
```

---

### UNIX Shell & JSON Pipeline (`jq`)

Pipe structured JSON reports directly into command-line utilities:

```bash
# Extract high and critical finding titles
lh-container scan . --format json | jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH") | .title'

# Assert zero critical findings in CI shell script
CRIT_COUNT=$(lh-container scan . --format json | jq '.statistics.critical')
if [ "$CRIT_COUNT" -gt 0 ]; then
  echo "CRITICAL findings detected: $CRIT_COUNT"
  exit 1
fi
```
