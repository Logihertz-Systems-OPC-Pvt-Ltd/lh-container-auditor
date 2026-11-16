# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-007`  
**Repository**: `lh-container-auditor`  
**CLI Executable**: `lh-container`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-007` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-container-auditor` (`lh-container`) |
| **Target Language / Platform** | `Python` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-container` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `Python`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: Container Isolation & Namespace Escape Risk Probability

The underlying computational core of `lh-container-auditor` is formally governed by the following mathematical and algorithmic formulations:

$$P_{\text{escape}} = 1 - \prod_{i=1}^{k} \left(1 - r_i(\text{CapLeak}, \\; \text{HostPID}, \\; \text{Privileged})\right)$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-CONT-001` | `CRITICAL` | `25` | `CWE-284` | Missing access control or unauthenticated privileged execution permitted | Enforce strict zero-trust authentication and least-privilege role bounds |
| `LH-CONT-002` | `CRITICAL` | `25` | `CWE-327` | Use of unvetted, deprecated, or broken cryptographic algorithm | Mandate modern authenticated cryptographic standards (FIPS / RFC approved) |
| `LH-CONT-003` | `CRITICAL` | `25` | `CWE-306` | Critical administrative endpoints accessible without authentication | Implement mutual TLS or cryptographic token verification |
| `LH-CONT-004` | `HIGH` | `10` | `CWE-345` | Data ingested without cryptographic signature or CRC verification | Enforce HMAC-SHA256, Ed25519, or CRC integrity checks on all streams |
| `LH-CONT-005` | `HIGH` | `10` | `CWE-324` | Key rotation interval exceeded or legacy version allowed | Automate regular key rotation and enforce strict validity limits |
| `LH-CONT-006` | `HIGH` | `10` | `CWE-226` | Transient keys and credentials not zeroized post-execution | Enforce explicit zeroization and memory-locking primitives |
| `LH-CONT-007` | `HIGH` | `10` | `CWE-330` | PRNG unseeded or failing continuous statistical health tests | Incorporate NIST SP 800-90B continuous entropy health testing |
| `LH-CONT-008` | `MEDIUM` | `4` | `CWE-285` | Coarse-grained permissions allowing lateral privilege escalation | Implement fine-grained RBAC and granular authorization checks |
| `LH-CONT-009` | `MEDIUM` | `4` | `CWE-400` | Missing rate limits or burst quotas on expensive operations | Configure token-bucket throttling and bounded allocation caps |
| `LH-CONT-010` | `LOW` | `1` | `CWE-778` | Security events not recorded to a tamper-evident audit log | Enable structured hash-chained audit logging to /var/log/struct-os.log |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-container` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-container <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-CONT-001` .. `LH-CONT-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## Section 6: Future Development Roadmap & Extension Architecture

### Milestone v0.2.0: Modular Extensions & Telemetry Streaming
- **Policy Pack Plugin Hooks**: Enable external declarative YAML/JSON rule-pack loading without source modification.
- **Hardware Telemetry Streaming**: Real-time integration with SPI, I2C, UART, CAN, and eBPF kernel event rings.
- **Configurable Severity Weights**: Support custom industrial profiles (e.g. Nuclear/Medical safety vs. Commercial IoT).

### Milestone v0.5.0: Native STRUCT OS Integration & Daemonless IPC
- **STRUCT OS Security Bus**: Native zero-copy shared memory integration with the STRUCT OS Security Command Center.
- **Automated Remediation Synthesis**: Direct IPC bridge with `lh-auto-remediation` for automatic synthesizing of verified unified diffs.
- **Hardware Root-of-Trust Attestation**: Cryptographic sealing of telemetry reports via TPM 2.0 PCR-bound quotes.

### Milestone v1.0.0: High-Assurance Certification & Hardening
- **FIPS 140-3 Validation**: Cryptographic module boundary verification and NIST CAVP compliance testing.
- **Common Criteria EAL4+ Alignment**: Formal verification of deterministic security targets and functional invariants.
- **Automotive & Industrial Compliance**: Formal baseline compliance with ISO 21434 (Automotive Cybersecurity) and IEC 62443 (Industrial Automation & Control Systems).
- **Signed Binary Attestation**: In-toto attestation and Cosign cryptographic signing across all release artifacts.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
