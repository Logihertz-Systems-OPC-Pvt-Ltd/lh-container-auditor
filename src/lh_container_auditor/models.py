# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-container-auditor.

Provides structured types for container scan targets, security findings,
severity levels, detection rules registry, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity levels for audit findings, ordered from highest to lowest."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level_rank(self) -> int:
        """Numeric rank for severity comparison (higher means more severe)."""
        ranks = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity is greater than or equal to threshold."""
        return self.level_rank >= threshold.level_rank


class FindingCategory(StrEnum):
    """Categorization of container audit findings."""

    IMAGE_BASE = "IMAGE_BASE"
    USER_PRIVILEGE = "USER_PRIVILEGE"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"  # nosec B105
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    FILE_OPERATION = "FILE_OPERATION"
    CONTAINER_CAPABILITY = "CONTAINER_CAPABILITY"
    PACKAGE_MANAGEMENT = "PACKAGE_MANAGEMENT"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    HEALTHCHECK = "HEALTHCHECK"
    PERMISSION_CONFIG = "PERMISSION_CONFIG"


class TargetType(StrEnum):
    """Type of container artifact analyzed."""

    DOCKERFILE = "DOCKERFILE"
    COMPOSE = "COMPOSE"
    OCI_IMAGE = "OCI_IMAGE"
    OCI_CONFIG = "OCI_CONFIG"


@dataclass(frozen=True)
class RuleDefinition:
    """Specification of an audit detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    remediation: str
    target_types: list[TargetType]

    def to_dict(self) -> dict[str, Any]:
        """Convert rule definition to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "remediation": self.remediation,
            "target_types": [t.value for t in self.target_types],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-CONT-001": RuleDefinition(
        rule_id="LH-CONT-001",
        title="Unpinned or :latest base image in FROM",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.IMAGE_BASE,
        description=(
            "Base image tag is omitted, uses :latest, or is not pinned to an explicit "
            "version or immutable digest."
        ),
        remediation=(
            "Pin base image by explicit version tag or immutable digest (e.g. alpine:3.19 "
            "or image@sha256:...)."
        ),
        target_types=[TargetType.DOCKERFILE],
    ),
    "LH-CONT-002": RuleDefinition(
        rule_id="LH-CONT-002",
        title="Missing non-root USER or explicit USER root / 0",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.USER_PRIVILEGE,
        description=(
            "Container runs as root user due to missing USER instruction or explicit assignment "
            "to root (UID 0)."
        ),
        remediation=(
            "Create a dedicated unprivileged user and declare 'USER <username>' before "
            "runtime instructions."
        ),
        target_types=[
            TargetType.DOCKERFILE,
            TargetType.COMPOSE,
            TargetType.OCI_IMAGE,
            TargetType.OCI_CONFIG,
        ],
    ),
    "LH-CONT-003": RuleDefinition(
        rule_id="LH-CONT-003",
        title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        description=(
            "Hardcoded credential, token, password, or private key detected in container "
            "instructions or environment configuration."
        ),
        remediation=(
            "Remove hardcoded credentials. Use BuildKit secret mounts (--mount=type=secret) "
            "or runtime secret managers."
        ),
        target_types=[
            TargetType.DOCKERFILE,
            TargetType.COMPOSE,
            TargetType.OCI_IMAGE,
            TargetType.OCI_CONFIG,
        ],
    ),
    "LH-CONT-004": RuleDefinition(
        rule_id="LH-CONT-004",
        title="Remote script pipe-to-shell (curl/wget | sh/bash) in RUN",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.COMMAND_EXECUTION,
        description=(
            "Fetching remote scripts and piping directly into a shell interpreter without "
            "prior cryptographic verification."
        ),
        remediation=(
            "Download remote scripts, verify cryptographic hash/signature, and execute in "
            "distinct steps."
        ),
        target_types=[TargetType.DOCKERFILE],
    ),
    "LH-CONT-005": RuleDefinition(
        rule_id="LH-CONT-005",
        title="Unsafe ADD instruction instead of COPY",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.FILE_OPERATION,
        description=(
            "Using ADD for local file copies or fetching remote URLs. ADD can trigger "
            "unexpected archive extractions or unverified asset downloads."
        ),
        remediation=(
            "Use COPY for local file transfers. Use curl/wget with checksum verification "
            "for remote downloads."
        ),
        target_types=[TargetType.DOCKERFILE],
    ),
    "LH-CONT-006": RuleDefinition(
        rule_id="LH-CONT-006",
        title="Compose privileged: true, host namespaces, or docker.sock mount",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.CONTAINER_CAPABILITY,
        description=(
            "Compose service configured with privileged: true, host namespaces (network, ipc), "
            "or mounting the Docker daemon socket."
        ),
        remediation=(
            "Disable privileged mode, remove host namespace sharing, and avoid mounting "
            "/var/run/docker.sock."
        ),
        target_types=[TargetType.COMPOSE],
    ),
    "LH-CONT-007": RuleDefinition(
        rule_id="LH-CONT-007",
        title="Unpurged package manager cache in RUN",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.PACKAGE_MANAGEMENT,
        description=(
            "Package manager invoked without purging repository caches in the same RUN layer, "
            "bloating image size and retaining stale vulnerability metadata."
        ),
        remediation=(
            "Clean package manager cache in the same RUN step (e.g. apt-get clean && "
            "rm -rf /var/lib/apt/lists/* or apk add --no-cache)."
        ),
        target_types=[TargetType.DOCKERFILE],
    ),
    "LH-CONT-008": RuleDefinition(
        rule_id="LH-CONT-008",
        title="Exposed sensitive ports (22, 23, 2375, 3389)",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.NETWORK_SECURITY,
        description=(
            "Container exposes sensitive administrative or unencrypted management ports "
            "(22/SSH, 23/Telnet, 2375/Docker daemon, 3389/RDP)."
        ),
        remediation=(
            "Remove exposed sensitive ports. Use container orchestration/exec rather than "
            "running management daemons inside containers."
        ),
        target_types=[
            TargetType.DOCKERFILE,
            TargetType.COMPOSE,
            TargetType.OCI_IMAGE,
            TargetType.OCI_CONFIG,
        ],
    ),
    "LH-CONT-009": RuleDefinition(
        rule_id="LH-CONT-009",
        title="Missing HEALTHCHECK in final stage",
        severity=FindingSeverity.LOW,
        category=FindingCategory.HEALTHCHECK,
        description=(
            "Container lacks a HEALTHCHECK instruction, preventing orchestration platforms "
            "from detecting runtime service failures."
        ),
        remediation=(
            "Define a HEALTHCHECK instruction with interval, timeout, and a test command "
            "(e.g. HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1)."
        ),
        target_types=[
            TargetType.DOCKERFILE,
            TargetType.COMPOSE,
            TargetType.OCI_IMAGE,
            TargetType.OCI_CONFIG,
        ],
    ),
    "LH-CONT-010": RuleDefinition(
        rule_id="LH-CONT-010",
        title="Sudoers NOPASSWD or SUID/SGID chmod in RUN",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PERMISSION_CONFIG,
        description=(
            "Privilege escalation risk introduced via passwordless sudo configuration or "
            "setting SUID/SGID bits in RUN instructions."
        ),
        remediation=(
            "Avoid granting NOPASSWD sudo privileges or setting SUID/SGID bits (+s, 4xxx, 2xxx) "
            "inside container images."
        ),
        target_types=[TargetType.DOCKERFILE],
    ),
}


@dataclass(frozen=True)
class Finding:
    """Represents an individual container security finding.

    Attributes:
        rule_id: Unique rule identifier (e.g. LH-CONT-001).
        title: Short title summarizing the issue.
        category: Category of the finding.
        severity: Severity level.
        target: Affected target artifact (file path or image name).
        message: Detailed explanation of the finding.
        line_number: Line number where issue occurred, if applicable.
        details: Additional context or technical parameters.
    """

    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    target: str
    message: str
    line_number: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "line_number": self.line_number,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanTargetResult:
    """Audit result for a single container file or image target.

    Attributes:
        target: Target path or identifier.
        target_type: Type of artifact analyzed.
        findings: List of security findings.
        error_message: Error string if scan failed.
    """

    target: str
    target_type: TargetType
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert scan target result to dictionary representation."""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class AuditReport:
    """Top-level report containing all audit results and execution parameters.

    Attributes:
        report_type: Type of audit (container_audit).
        generated_at: Timestamp when report was produced (UTC).
        parameters: Scan parameters used during execution.
        results: List of scan target results.
        summary: Aggregated summary statistics.
    """

    report_type: str = "container_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Calculate and store summary statistics."""
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        all_findings: list[Finding] = []
        for r in self.results:
            all_findings.extend(r.findings)

        for f in all_findings:
            if f.severity == FindingSeverity.CRITICAL:
                critical_count += 1
            elif f.severity == FindingSeverity.HIGH:
                high_count += 1
            elif f.severity == FindingSeverity.MEDIUM:
                medium_count += 1
            elif f.severity == FindingSeverity.LOW:
                low_count += 1
            elif f.severity == FindingSeverity.INFO:
                info_count += 1

        self.summary = {
            "total_targets": len(self.results),
            "total_findings": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        }

    def filter_min_severity(self, min_severity: FindingSeverity | None) -> None:
        """Filter out findings with severity lower than min_severity."""
        if min_severity is None:
            return
        for r in self.results:
            r.findings = [f for f in r.findings if f.severity.meets_threshold(min_severity)]
        self.compute_summary()

    def has_failures(self, fail_on: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the fail_on threshold."""
        if fail_on is None:
            return False
        for r in self.results:
            if r.error_message:
                return True
            for f in r.findings:
                if f.severity.meets_threshold(fail_on):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }
