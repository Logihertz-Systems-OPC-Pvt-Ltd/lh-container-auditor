# Security Rules Reference: lh-container-auditor

An enterprise container security posture & dockerfile auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-container-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-CONT-001` | `CRITICAL` | Least Privilege | Container Running as Root |
| `LH-CONT-002` | `HIGH` | Supply Chain | Base Image Tag is Mutable (:latest or Unpinned) |
| `LH-CONT-003` | `CRITICAL` | Secret Hygiene | Hardcoded Secrets Declared in ENV or ARG Instructions |
| `LH-CONT-004` | `HIGH` | Privilege Escalation | Privileged Container Execution Enabled |
| `LH-CONT-005` | `CRITICAL` | Filesystem Isolation | Dangerous Host Volume Mount Exposed |
| `LH-CONT-006` | `HIGH` | Namespace Isolation | Host Namespace Sharing Enabled |
| `LH-CONT-007` | `MEDIUM` | Resilience | Container Missing HEALTHCHECK Instruction |
| `LH-CONT-008` | `MEDIUM` | Build Hygiene | Use of Dangerous ADD Instruction Fetching Remote Tarballs |
| `LH-CONT-009` | `HIGH` | Build Hygiene | Insecure Package Manager Invocation Without Cache Cleanup |
| `LH-CONT-010` | `LOW` | Governance | Missing Container Metadata Labels or Version Declaration |

---

## Granular Rule Specifications

### `LH-CONT-001`: Container Running as Root

- **Severity**: `CRITICAL`
- **Category**: `Least Privilege`
- **Description**: Container missing explicit non-root USER instruction or executing with USER 0.
- **Remediation**: Add dedicated user creation and specify USER <uid> in the Dockerfile.

---

### `LH-CONT-002`: Base Image Tag is Mutable (:latest or Unpinned)

- **Severity**: `HIGH`
- **Category**: `Supply Chain`
- **Description**: Base image specifies mutable :latest tag or floating version susceptible to supply-chain drift.
- **Remediation**: Pin base image tags to specific version numbers or immutable sha256 digests.

---

### `LH-CONT-003`: Hardcoded Secrets Declared in ENV or ARG Instructions

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Plaintext passwords, tokens, or private keys exposed in container build instructions.
- **Remediation**: Externalize secrets using BuildKit secret mounts (--mount=type=secret) or runtime injection.

---

### `LH-CONT-004`: Privileged Container Execution Enabled

- **Severity**: `HIGH`
- **Category**: `Privilege Escalation`
- **Description**: Container configured with privileged: true or granting CAP_SYS_ADMIN capabilities.
- **Remediation**: Drop all Linux capabilities (cap_drop: [ALL]) and add only required capabilities.

---

### `LH-CONT-005`: Dangerous Host Volume Mount Exposed

- **Severity**: `CRITICAL`
- **Category**: `Filesystem Isolation`
- **Description**: Host filesystem root, /etc, or /var/run/docker.sock mounted inside container.
- **Remediation**: Avoid mounting sensitive host paths or Docker socket inside container workloads.

---

### `LH-CONT-006`: Host Namespace Sharing Enabled

- **Severity**: `HIGH`
- **Category**: `Namespace Isolation`
- **Description**: Container configured with hostNetwork: true, hostPID: true, or hostIPC: true.
- **Remediation**: Isolate network and process namespaces by removing host namespace configurations.

---

### `LH-CONT-007`: Container Missing HEALTHCHECK Instruction

- **Severity**: `MEDIUM`
- **Category**: `Resilience`
- **Description**: Dockerfile lacks HEALTHCHECK instruction for orchestrator liveness monitoring.
- **Remediation**: Define HEALTHCHECK instruction verifying application response via curl or local probe.

---

### `LH-CONT-008`: Use of Dangerous ADD Instruction Fetching Remote Tarballs

- **Severity**: `MEDIUM`
- **Category**: `Build Hygiene`
- **Description**: ADD instruction used to download remote URLs instead of deterministic COPY.
- **Remediation**: Replace ADD with COPY for local files or download remote dependencies via curl with checksums.

---

### `LH-CONT-009`: Insecure Package Manager Invocation Without Cache Cleanup

- **Severity**: `HIGH`
- **Category**: `Build Hygiene`
- **Description**: apt-get or apk invoked without cleanup or using unsafe flags.
- **Remediation**: Combine update and install in single RUN with --no-install-recommends and rm -rf /var/lib/apt/lists/*.

---

### `LH-CONT-010`: Missing Container Metadata Labels or Version Declaration

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Container missing vendor, version, or security maintainer metadata labels.
- **Remediation**: Add standard OCI labels (org.opencontainers.image.title, version, authors) via LABEL.

---
