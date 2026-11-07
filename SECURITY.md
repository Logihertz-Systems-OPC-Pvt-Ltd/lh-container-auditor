# Security Policy

## Overview

`lh-container-auditor` is an open-source security tool developed by **Logihertz Systems (OPC) Private Limited**.
Because security tools must maintain the highest standards of safety and integrity, `lh-container-auditor`
is engineered with a zero-daemon, clean-room design that operates entirely offline. It does not
transmit telemetry, execute external network calls, or require persistent background daemons.

---

## Supported Versions

Only the latest active minor release of `lh-container-auditor` receives security updates and bug fixes.

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability, parser flaw, or denial-of-service issue in `lh-container-auditor`,
please report it responsibly through our security response channel.
**Do not create a public GitHub issue for security vulnerabilities.**

### Vulnerability Reporting Process

1. **Email Details**: Send an advisory email to:
   **ops@logihertz.com**
2. **Include Key Information**:
   - Component / module name affected
   - Specific version of `lh-container-auditor`
   - Clear description of the vulnerability and potential security impact
   - Minimal reproduction snippet, proof-of-concept payload, or configuration manifest
3. **Response Timeline**:
   - **Acknowledgment**: Within **48 hours** of receiving your report.
   - **Triage & Status**: Within **3 business days** with preliminary assessment and reproduction verification.
   - **Remediation & Patch**: We aim to release a verified patch within **5 business days** for high or critical severity issues.

---

## Security Engineering Standards

`lh-container-auditor` enforces rigorous internal engineering controls:
- **100% Offline Static Analysis**: All inspection and parsing occurs locally in memory without remote calls.
- **Automated SAST**: Automated static analysis security testing via Bandit on every commit and pull request.
- **Linting & Code Quality**: Strict formatting and linting via Ruff with a 100-character line length limit.
- **Strict Typing**: Type annotations enforced across all source modules with `from __future__ import annotations`.
