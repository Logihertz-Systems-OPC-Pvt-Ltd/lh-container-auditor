# Architecture: lh-container-auditor

An enterprise container security posture & dockerfile auditor developed by **Logihertz Systems (OPC) Private Limited**.

---

## 1. Design Philosophy

`lh-container-auditor` is engineered around four core tenets:

1. **Zero-Daemon Execution**: Operates entirely as a standalone, deterministic CLI tool. No background services, socket listeners, or persistent daemons are required.
2. **Clean-Room & Offline Static Analysis**: Parses files locally in memory using standard library structures. Requires zero outbound network connectivity and zero external cloud credentials.
3. **Strongly Typed Domain Model**: Built on Python 3.11+ dataclasses with strict typing (`from __future__ import annotations`) and explicit enums.
4. **Universal Multi-Format Export**: Implements decoupled presentation layers supporting human-readable Rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0 for GitHub Code Scanning integration.

---

## 2. Component Breakdown

The package source is organized under `src/lh_container_auditor/`:

```
src/lh_container_auditor/
├── __init__.py           # Package version and public exports
├── models.py             # Strongly-typed domain models, enums, finding schemas
├── cli.py                # Command-line interface, argument parsing, exit codes
├── exporters.py          # Terminal Rich tables, JSON serializer, SARIF v2.1.0 builder
```

### Module Responsibilities

| Module | Role & Responsibility |
|:---|:---|
| **`models.py`** | Defines `FindingSeverity`, `FindingFormat`, `AuditFinding`, `AuditRuleDefinition`, and `AuditReport` data structures. Encapsulates finding serialization and severity filtering. |
| **Parsers** (`dockerfile_scanner.py`, `compose_scanner.py`, `oci_scanner.py` (parses Dockerfiles, Compose YAML, and OCI manifests)) | Ingests raw configurations, manifests, or log streams, validating input syntax and translating raw entries into structured in-memory representations. |
| **Analyzers** (Unified container posture evaluator checking user contexts, capabilities, mounts, and tags) | Evaluates the 10 core detection rules against parsed models, calculating severity ratings, risk scores, and remediation recommendations. |
| **`exporters.py`** | Serializes `AuditReport` instances into terminal tables via `rich`, structured JSON for SIEM ingestion, and OASIS SARIF v2.1.0 schemas. |
| **`cli.py`** | Configures executable entrypoint `lh-container`, handles CLI flags (`--format`, `--output`, `--min-severity`, `--fail-on`), and manages standard exit codes. |

---

## 3. Data Processing Pipeline

```
┌─────────────────────────────────┐
│ Input Manifests / Logs / Configs│
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Parser Module (lh_container_auditor)           │
│ - Lexical parsing & validation  │
│ - Normalization into Models     │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Analyzer Engine                 │
│ - 10-Rule Security Evaluation   │
│ - Threat Context Analysis       │
│ - Remediation Mapping           │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ AuditReport Data Structure      │
│ - Findings list & statistics    │
│ - 0-100 Consolidated Risk Score │
└────────────────┬────────────────┘
                 │
      ┌──────────┼──────────┐
      ▼          ▼          ▼
┌──────────┐┌──────────┐┌──────────────┐
│  Rich    ││  JSON    ││ OASIS SARIF  │
│  Table   ││  Stream  ││   v2.1.0     │
└──────────┘└──────────┘└──────────────┘
```

---

## 4. Risk Score Calculation Formula

`lh-container-auditor` calculates a consolidated Risk Score on an objective **0 to 100** numerical scale:

$$\text{raw\_score} = (\text{CRITICAL} \times 25) + (\text{HIGH} \times 15) + (\text{MEDIUM} \times 5) + (\text{LOW} \times 2)$$

$$\text{Risk Score} = \min(100, \text{raw\_score})$$

### Severity Weights

| Finding Severity | Weight Penalty | Impact Description |
|:---|:---:|:---|
| **CRITICAL** | `+25` | Immediate exploitation vector, complete bypass, or critical data compromise |
| **HIGH** | `+15` | High-risk vulnerability, permissive access control, or significant exposure |
| **MEDIUM** | `+5` | Security hygiene deficit, weak configuration, or missing defense-in-depth |
| **LOW** | `+2` | Informational finding, minor deviation from best practices, or telemetry gap |

### Risk Tiers

| Score Range | Risk Classification | Recommended Action |
|:---:|:---|:---|
| **0 – 25** | **LOW RISK** | Baseline compliant. Address minor findings in regular sprint cycles. |
| **26 – 50** | **MEDIUM RISK** | Security deficits identified. Plan remediation within 30 days. |
| **51 – 75** | **HIGH RISK** | High-severity findings detected. Prioritize patching within 14 days. |
| **76 – 100** | **CRITICAL RISK** | Active compromise risk. Immediate remediation required (24-48 hours). |
