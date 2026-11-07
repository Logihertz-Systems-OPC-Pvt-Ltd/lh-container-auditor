# lh-container-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise container & oci image security developed by **Logihertz Systems (OPC) Private Limited**.

Inspects Dockerfiles, Docker Compose stacks, and OCI image configuration manifests for root user execution, privileged containers, dangerous Linux capabilities, unpinned :latest tags, and leaked build-arg secrets.

---

## Key Features

- **Dockerfile AST Parsing**: Evaluates container build instructions (`USER`, `FROM`, `ENV`, `ADD`, `RUN`, `HEALTHCHECK`) for security best practices.
- **Docker Compose Multi-Service Auditing**: Inspects multi-container specifications for privileged mode, host networking, dangerous volume mounts, and secret exposures.
- **Root Execution & Least Privilege**: Flags containers lacking non-root `USER` declarations or explicitly running as root UID 0.
- **Supply Chain Pinning**: Flags mutable `:latest` tags and unpinned base images vulnerable to upstream supply chain attacks.
- **Secret Exposure Scanning**: Detects embedded credentials in `ENV` and `ARG` directives using high-entropy regex pattern matching.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-CONT-001` | `CRITICAL` | Container running as root (missing explicit non-root USER instruction or USER 0) |
| `LH-CONT-002` | `HIGH` | Base image tag is mutable (:latest or unpinned tag vulnerable to supply chain drift) |
| `LH-CONT-003` | `CRITICAL` | Hardcoded secrets, passwords, or tokens declared in ENV or ARG instructions |
| `LH-CONT-004` | `HIGH` | Privileged container execution (privileged: true or CAP_SYS_ADMIN enabled) |
| `LH-CONT-005` | `CRITICAL` | Dangerous host volume mount (/var/run/docker.sock, /etc, or host root / mounted) |
| `LH-CONT-006` | `HIGH` | Host namespace sharing enabled (hostNetwork: true or hostPID: true) |
| `LH-CONT-007` | `MEDIUM` | Container missing HEALTHCHECK instruction for runtime liveness monitoring |
| `LH-CONT-008` | `MEDIUM` | Use of dangerous ADD instruction fetching remote tarballs instead of COPY |
| `LH-CONT-009` | `HIGH` | Insecure package manager invocation (missing --no-cache or untrusted apt flags) |
| `LH-CONT-010` | `LOW` | Missing container metadata labels, version tags, or security maintainer declaration |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor.git
cd lh-container-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-container` (also accessible via `lh-container`, `lh-container-auditor`).

```bash
# Audit a Dockerfile for security misconfigurations
lh-container scan Dockerfile

# Audit a Docker Compose manifest
lh-container scan docker-compose.yml --format json

# Export findings to OASIS SARIF v2.1.0
lh-container scan ./containers/ --format sarif --output container-results.sarif

# Filter findings by minimum severity
lh-container scan ./containers/ --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
