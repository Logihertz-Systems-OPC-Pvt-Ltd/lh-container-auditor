# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.dockerfile_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Dockerfile static analysis scanner for lh-container-auditor.

Inspects Dockerfile instructions for supply chain risks, privilege escalation,
hardcoded secrets, unpurged caches, missing healthchecks, and insecure commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from lh_container_auditor.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)

SENSITIVE_PORTS = {22, 23, 2375, 2376, 3389}

SECRET_KEY_REGEX = re.compile(
    r"(?i)(?:secret|token|password|passwd|api_?key|auth_?token|private_?key|access_?key|credential)"
)
PLACEHOLDER_REGEX = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z0-9_]+|\"\"|''|<[^>]+>|dummy|placeholder|changeme|test|default|none|null)?$",
    re.IGNORECASE,
)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----")
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{30,})\b")
SLACK_TOKEN_REGEX = re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,})\b")

PIPE_SHELL_REGEX = re.compile(
    r"(?i)\b(curl|wget|fetch)\b[^|;&\n]*\|\s*(sh|bash|zsh|ash|/bin/sh|/bin/bash|sudo\s+sh|sudo\s+bash)"
)
NOPASSWD_REGEX = re.compile(r"(?i)\bNOPASSWD\s*:\s*ALL\b|\bNOPASSWD\s*:")
SUID_OCTAL_REGEX = re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*([0-7]*[246][0-7]{3})\b")
SUID_SYMBOLIC_REGEX = re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9,]*[ug\+]?\+s\b")

ARCHIVE_EXTENSIONS = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)


@dataclass
class DockerfileInstruction:
    """Parsed representation of a Dockerfile instruction."""

    instruction: str
    arguments: str
    raw_text: str
    start_line: int
    end_line: int


@dataclass
class StageInfo:
    """Metadata for a build stage within a multi-stage Dockerfile."""

    index: int
    name: str | None
    base_image: str
    from_line: int
    last_user: str | None = None
    last_user_line: int | None = None
    has_healthcheck: bool = False
    healthcheck_line: int | None = None


class DockerfileScanner:
    """Scanner for analyzing Dockerfile security configurations."""

    def __init__(self, content: str, target_path: str = "Dockerfile") -> None:
        """Initialize DockerfileScanner with file contents.

        Args:
            content: Raw Dockerfile content as string.
            target_path: Path or filename for reporting.
        """
        self.content = content
        self.target_path = target_path
        self.instructions: list[DockerfileInstruction] = []
        self.stages: list[StageInfo] = []

    def _parse(self) -> None:
        """Parse raw Dockerfile into structured instructions and build stages."""
        lines = self.content.splitlines()
        current_instruction = ""
        current_arguments: list[str] = []
        current_raw: list[str] = []
        start_line = 0

        i = 0
        while i < len(lines):
            line_num = i + 1
            line = lines[i]
            stripped = line.strip()

            # Handle comments and empty lines outside multiline continuation
            if not current_instruction:
                if not stripped or stripped.startswith("#"):
                    i += 1
                    continue

                # Match beginning of new instruction
                match = re.match(r"^([A-Za-z]+)\s*(.*)$", stripped)
                if match:
                    current_instruction = match.group(1).upper()
                    start_line = line_num
                    remainder = match.group(2)
                    current_raw.append(line)

                    if remainder.endswith("\\"):
                        current_arguments.append(remainder[:-1].strip())
                    else:
                        current_arguments.append(remainder.strip())
                        self.instructions.append(
                            DockerfileInstruction(
                                instruction=current_instruction,
                                arguments=" ".join(current_arguments).strip(),
                                raw_text="\n".join(current_raw),
                                start_line=start_line,
                                end_line=line_num,
                            )
                        )
                        current_instruction = ""
                        current_arguments = []
                        current_raw = []
                i += 1
                continue

            # In continuation line
            current_raw.append(line)
            if stripped.endswith("\\"):
                current_arguments.append(stripped[:-1].strip())
            else:
                current_arguments.append(stripped)
                self.instructions.append(
                    DockerfileInstruction(
                        instruction=current_instruction,
                        arguments=" ".join(current_arguments).strip(),
                        raw_text="\n".join(current_raw),
                        start_line=start_line,
                        end_line=line_num,
                    )
                )
                current_instruction = ""
                current_arguments = []
                current_raw = []
            i += 1

        # Handle any trailing open instruction
        if current_instruction:
            self.instructions.append(
                DockerfileInstruction(
                    instruction=current_instruction,
                    arguments=" ".join(current_arguments).strip(),
                    raw_text="\n".join(current_raw),
                    start_line=start_line,
                    end_line=len(lines),
                )
            )

        self._build_stages()

    def _build_stages(self) -> None:
        """Group instructions into build stages."""
        current_stage: StageInfo | None = None
        stage_idx = 0

        for inst in self.instructions:
            if inst.instruction == "FROM":
                # Syntax: FROM [--platform=...] <image> [AS <name>]
                args = inst.arguments
                # Strip flags like --platform=...
                tokens = [t for t in args.split() if not t.startswith("--")]
                base_img = tokens[0] if tokens else ""
                stage_name = None
                if len(tokens) >= 3 and tokens[1].upper() == "AS":
                    stage_name = tokens[2]

                current_stage = StageInfo(
                    index=stage_idx,
                    name=stage_name,
                    base_image=base_img,
                    from_line=inst.start_line,
                )
                self.stages.append(current_stage)
                stage_idx += 1
            elif current_stage is not None:
                if inst.instruction == "USER":
                    current_stage.last_user = inst.arguments.strip()
                    current_stage.last_user_line = inst.start_line
                elif inst.instruction == "HEALTHCHECK":
                    if inst.arguments.strip().upper() != "NONE":
                        current_stage.has_healthcheck = True
                        current_stage.healthcheck_line = inst.start_line

    def scan(self) -> ScanTargetResult:
        """Execute all Dockerfile security audit rules.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        self._parse()
        findings: list[Finding] = []

        if not self.instructions:
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.DOCKERFILE,
                findings=[],
                error_message="Empty Dockerfile or no valid instructions parsed.",
            )

        # Collect named stages to avoid flagging local aliases as unpinned images
        stage_aliases: set[str] = {s.name.lower() for s in self.stages if s.name}

        for inst in self.instructions:
            # Rule 1: LH-CONT-001 - Unpinned or :latest base image in FROM
            if inst.instruction == "FROM":
                self._check_from_pinning(inst, stage_aliases, findings)

            # Rule 3: LH-CONT-003 - Hardcoded secrets in ENV, ARG, LABEL
            if inst.instruction in ("ENV", "ARG", "LABEL"):
                self._check_hardcoded_secrets(inst, findings)

            # Rule 4: LH-CONT-004 - Remote script pipe-to-shell in RUN
            if inst.instruction == "RUN":
                self._check_remote_script_pipe(inst, findings)

            # Rule 5: LH-CONT-005 - Unsafe ADD instruction
            if inst.instruction == "ADD":
                self._check_add_instruction(inst, findings)

            # Rule 7: LH-CONT-007 - Unpurged package cache in RUN
            if inst.instruction == "RUN":
                self._check_package_manager_cache(inst, findings)

            # Rule 8: LH-CONT-008 - Exposed sensitive ports
            if inst.instruction == "EXPOSE":
                self._check_exposed_ports(inst, findings)

            # Rule 10: LH-CONT-010 - Sudoers NOPASSWD or SUID/SGID in RUN
            if inst.instruction == "RUN":
                self._check_sudoers_and_suid(inst, findings)

        # Stage-level checks on final stage
        if self.stages:
            final_stage = self.stages[-1]
            self._check_user_privilege(final_stage, findings)
            self._check_healthcheck(final_stage, findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.DOCKERFILE,
            findings=findings,
        )

    def _check_from_pinning(
        self,
        inst: DockerfileInstruction,
        stage_aliases: set[str],
        findings: list[Finding],
    ) -> None:
        """Check for unpinned or :latest base image tags (LH-CONT-001)."""
        tokens = [t for t in inst.arguments.split() if not t.startswith("--")]
        if not tokens:
            return
        image_ref = tokens[0]

        # Ignore scratch or local stages
        if image_ref.lower() == "scratch" or image_ref.lower() in stage_aliases:
            return

        # Pinned by immutable digest (e.g. image@sha256:...)
        if "@sha256:" in image_ref:
            return

        # Check tag
        if ":" not in image_ref:
            # Tag is completely omitted -> defaults to latest
            findings.append(
                Finding(
                    rule_id="LH-CONT-001",
                    title="Unpinned or :latest base image in FROM",
                    category=FindingCategory.IMAGE_BASE,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        f"Base image '{image_ref}' has no version tag specified, implicitly "
                        "using ':latest'. Pin to an explicit version tag or digest."
                    ),
                    details={"instruction": inst.arguments, "image": image_ref},
                )
            )
            return

        tag = image_ref.rsplit(":", 1)[1]
        if tag.lower() == "latest":
            findings.append(
                Finding(
                    rule_id="LH-CONT-001",
                    title="Unpinned or :latest base image in FROM",
                    category=FindingCategory.IMAGE_BASE,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        f"Base image '{image_ref}' explicitly uses ':latest' tag. Pin to an "
                        "explicit version tag or immutable SHA256 digest."
                    ),
                    details={"instruction": inst.arguments, "image": image_ref, "tag": tag},
                )
            )

    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-002: Base Image Tag is Mutable (:latest or Unpinned) (HIGH) ---
    # Evaluates security posture against base image tag is mutable (:latest or
    # unpinned).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_user_privilege(self, final_stage: StageInfo, findings: list[Finding]) -> None:
        """Check that the final stage does not run as root (LH-CONT-002)."""
        last_user = final_stage.last_user

        if last_user is None:
            # Missing USER instruction completely
            findings.append(
                Finding(
                    rule_id="LH-CONT-002",
                    title="Missing non-root USER or explicit USER root / 0",
                    category=FindingCategory.USER_PRIVILEGE,
                    severity=FindingSeverity.CRITICAL,
                    target=self.target_path,
                    line_number=final_stage.from_line,
                    message=(
                        "Container execution environment lacks a non-root USER declaration. "
                        "By default, the container will execute as the root superuser."
                    ),
                    details={"stage_index": final_stage.index, "stage_name": final_stage.name},
                )
            )
            return

        # Explicit root assignment
        user_clean = last_user.split(":")[0].strip().strip('"').strip("'")
        if user_clean.lower() in ("root", "0"):
            findings.append(
                Finding(
                    rule_id="LH-CONT-002",
                    title="Missing non-root USER or explicit USER root / 0",
                    category=FindingCategory.USER_PRIVILEGE,
                    severity=FindingSeverity.CRITICAL,
                    target=self.target_path,
                    line_number=final_stage.last_user_line or final_stage.from_line,
                    message=(
                        f"Container explicitly declares '{last_user}', running as root superuser. "
                        "Configure a dedicated non-root user instead."
                    ),
                    details={
                        "user": last_user,
                        "stage_index": final_stage.index,
                        "stage_name": final_stage.name,
                    },
                )
            )

    def _check_hardcoded_secrets(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect hardcoded credentials or tokens in ENV, ARG, or LABEL (LH-CONT-003)."""
        raw_text = inst.raw_text

        # Check for explicit token regex matches in the raw line
        for regex, name in (
            (PRIVATE_KEY_REGEX, "Private Key"),
            (AWS_KEY_REGEX, "AWS Access Key"),
            (GITHUB_TOKEN_REGEX, "GitHub Token"),
            (SLACK_TOKEN_REGEX, "Slack Token"),
        ):
            if regex.search(raw_text):
                findings.append(
                    Finding(
                        rule_id="LH-CONT-003",
                        title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                        category=FindingCategory.SECRET_EXPOSURE,
                        severity=FindingSeverity.CRITICAL,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            f"Hardcoded {name} pattern detected in {inst.instruction} instruction."
                        ),
                        details={"instruction": inst.instruction, "secret_type": name},
                    )
                )
                return

        # Parse key=value pairs
        # e.g., ENV KEY=val KEY2=val2 or ARG KEY=val or ENV KEY val
        args = inst.arguments.strip()
        pairs: list[tuple[str, str]] = []

        if "=" in args:
            # Handles KEY=val format
            matches = re.findall(r'([A-Za-z0-9_.-]+)\s*=\s*([^\s"\']+|"[^"]*"|\'[^\']*\')?', args)
            for k, v in matches:
                pairs.append((k, v.strip().strip('"').strip("'") if v else ""))
        elif inst.instruction == "ENV":
            # Legacy format: ENV KEY VALUE
            parts = args.split(maxsplit=1)
            if len(parts) == 2:
                pairs.append((parts[0], parts[1].strip().strip('"').strip("'")))

        for key, val in pairs:
            if not val or PLACEHOLDER_REGEX.match(val):
                continue

            if SECRET_KEY_REGEX.search(key):
                findings.append(
                    Finding(
                        rule_id="LH-CONT-003",
                        title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                        category=FindingCategory.SECRET_EXPOSURE,
                        severity=FindingSeverity.CRITICAL,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            f"Potential hardcoded secret assigned to '{key}' in "
                            f"{inst.instruction} instruction."
                        ),
                        details={"instruction": inst.instruction, "key": key},
                    )
                )

    def _check_remote_script_pipe(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect remote script downloaded and piped directly to shell (LH-CONT-004)."""
        if PIPE_SHELL_REGEX.search(inst.arguments):
            findings.append(
                Finding(
                    rule_id="LH-CONT-004",
                    title="Remote script pipe-to-shell (curl/wget | sh/bash) in RUN",
                    category=FindingCategory.COMMAND_EXECUTION,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        "Remote script fetched via curl/wget and piped directly to shell. "
                        "Download the script and verify checksum or signature before execution."
                    ),
                    details={"command": inst.arguments},
                )
            )

    def _check_add_instruction(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect unsafe ADD instruction instead of COPY (LH-CONT-005)."""
        args = inst.arguments.strip()
        tokens = [t for t in args.split() if not t.startswith("--")]

        if not tokens:
            return

        source = tokens[0]

        # Downloading remote URLs via ADD
        if source.startswith(("http://", "https://")):
            findings.append(
                Finding(
                    rule_id="LH-CONT-005",
                    title="Unsafe ADD instruction instead of COPY",
                    category=FindingCategory.FILE_OPERATION,
                    severity=FindingSeverity.MEDIUM,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        f"ADD used with remote URL '{source}'. Remote downloads via ADD do not "
                        "verify checksums. Use curl or wget with verification."
                    ),
                    details={"source": source},
                )
            )
            return

        # Using ADD for files that are not local compressed archives
        is_archive = any(source.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS)
        if not is_archive:
            findings.append(
                Finding(
                    rule_id="LH-CONT-005",
                    title="Unsafe ADD instruction instead of COPY",
                    category=FindingCategory.FILE_OPERATION,
                    severity=FindingSeverity.MEDIUM,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        f"ADD instruction used for regular file '{source}'. Use COPY instead of "
                        "ADD unless tar archive auto-extraction is specifically required."
                    ),
                    details={"source": source},
                )
            )

    def _check_package_manager_cache(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect unpurged package manager caches in RUN instructions (LH-CONT-007)."""
        cmd = inst.arguments

        # apt-get / apt install
        if re.search(r"\b(?:apt-get|apt)\s+(?:-[a-zA-Z]+\s+)*install\b", cmd):
            if "rm -rf /var/lib/apt/lists" not in cmd and "rm -rf /var/lib/apt/lists/*" not in cmd:
                findings.append(
                    Finding(
                        rule_id="LH-CONT-007",
                        title="Unpurged package manager cache in RUN",
                        category=FindingCategory.PACKAGE_MANAGEMENT,
                        severity=FindingSeverity.MEDIUM,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            "apt-get/apt install used without removing '/var/lib/apt/lists/*'. "
                            "Retaining cache increases image size and leaves stale package lists."
                        ),
                        details={"package_manager": "apt", "command": cmd},
                    )
                )

        # apk add
        if re.search(r"\bapk\s+(?:-[a-zA-Z]+\s+)*add\b", cmd):
            if "--no-cache" not in cmd and "rm -rf /var/cache/apk" not in cmd:
                findings.append(
                    Finding(
                        rule_id="LH-CONT-007",
                        title="Unpurged package manager cache in RUN",
                        category=FindingCategory.PACKAGE_MANAGEMENT,
                        severity=FindingSeverity.MEDIUM,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            "apk add used without '--no-cache' flag or cache cleanup. "
                            "Use 'apk add --no-cache' to avoid storing package index."
                        ),
                        details={"package_manager": "apk", "command": cmd},
                    )
                )

        # yum / dnf install
        if re.search(r"\b(?:yum|dnf)\s+(?:-[a-zA-Z]+\s+)*install\b", cmd):
            if (
                "clean all" not in cmd
                and "rm -rf /var/cache/yum" not in cmd
                and "rm -rf /var/cache/dnf" not in cmd
            ):
                findings.append(
                    Finding(
                        rule_id="LH-CONT-007",
                        title="Unpurged package manager cache in RUN",
                        category=FindingCategory.PACKAGE_MANAGEMENT,
                        severity=FindingSeverity.MEDIUM,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            "yum/dnf install used without 'clean all' or removing '/var/cache/*'. "
                            "Purge package cache in the same RUN layer."
                        ),
                        details={"package_manager": "yum/dnf", "command": cmd},
                    )
                )

        # pip install
        if re.search(r"\bpip(?:3)?\s+install\b", cmd):
            if "--no-cache-dir" not in cmd and "rm -rf" not in cmd:
                findings.append(
                    Finding(
                        rule_id="LH-CONT-007",
                        title="Unpurged package manager cache in RUN",
                        category=FindingCategory.PACKAGE_MANAGEMENT,
                        severity=FindingSeverity.MEDIUM,
                        target=self.target_path,
                        line_number=inst.start_line,
                        message=(
                            "pip install used without '--no-cache-dir' flag. "
                            "Supply '--no-cache-dir' to avoid storing pip download wheels in image."
                        ),
                        details={"package_manager": "pip", "command": cmd},
                    )
                )

    def _check_exposed_ports(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect exposed sensitive management or daemon ports (LH-CONT-008)."""
        tokens = inst.arguments.split()
        for token in tokens:
            port_part = token.split("/")[0]
            try:
                port_num = int(port_part)
                if port_num in SENSITIVE_PORTS:
                    findings.append(
                        Finding(
                            rule_id="LH-CONT-008",
                            title="Exposed sensitive ports (22, 23, 2375, 3389)",
                            category=FindingCategory.NETWORK_SECURITY,
                            severity=FindingSeverity.MEDIUM,
                            target=self.target_path,
                            line_number=inst.start_line,
                            message=(
                                f"Sensitive port {port_num} is exposed in EXPOSE instruction. "
                                "Avoid running SSH, Telnet, or Docker daemon ports in containers."
                            ),
                            details={"port": port_num, "instruction": token},
                        )
                    )
            except ValueError:
                continue

    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-009 (HIGH):
    #     Insecure Package Manager Invocation Without Cache Cleanup
    # ---
    # Evaluates security posture against insecure package manager invocation without
    # cache cleanup.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_healthcheck(self, final_stage: StageInfo, findings: list[Finding]) -> None:
        """Check for missing HEALTHCHECK in final stage (LH-CONT-009)."""
        if not final_stage.has_healthcheck:
            findings.append(
                Finding(
                    rule_id="LH-CONT-009",
                    title="Missing HEALTHCHECK in final stage",
                    category=FindingCategory.HEALTHCHECK,
                    severity=FindingSeverity.LOW,
                    target=self.target_path,
                    line_number=final_stage.from_line,
                    message=(
                        "Final stage lacks a HEALTHCHECK instruction. Define a HEALTHCHECK "
                        "to allow container orchestrators to monitor container readiness."
                    ),
                    details={"stage_index": final_stage.index, "stage_name": final_stage.name},
                )
            )

    def _check_sudoers_and_suid(
        self,
        inst: DockerfileInstruction,
        findings: list[Finding],
    ) -> None:
        """Detect NOPASSWD in sudoers or SUID/SGID bit setting in RUN (LH-CONT-010)."""
        cmd = inst.arguments

        # Sudoers NOPASSWD
        if NOPASSWD_REGEX.search(cmd):
            findings.append(
                Finding(
                    rule_id="LH-CONT-010",
                    title="Sudoers NOPASSWD or SUID/SGID chmod in RUN",
                    category=FindingCategory.PERMISSION_CONFIG,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        "Privilege escalation risk: NOPASSWD sudoers privilege detected in RUN "
                        "instruction."
                    ),
                    details={"command": cmd},
                )
            )

        # SUID / SGID octal or symbolic
        octal_match = SUID_OCTAL_REGEX.search(cmd)
        symbolic_match = SUID_SYMBOLIC_REGEX.search(cmd)

        if octal_match or symbolic_match:
            bit_type = octal_match.group(1) if octal_match else "symbolic (+s)"
            findings.append(
                Finding(
                    rule_id="LH-CONT-010",
                    title="Sudoers NOPASSWD or SUID/SGID chmod in RUN",
                    category=FindingCategory.PERMISSION_CONFIG,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=inst.start_line,
                    message=(
                        f"Privilege escalation risk: SUID/SGID bit modification ({bit_type}) "
                        "detected in RUN instruction."
                    ),
                    details={"command": cmd, "mode": bit_type},
                )
            )


def scan_dockerfile(path: Path | str) -> ScanTargetResult:
    """Read and scan a Dockerfile from disk.

    Args:
        path: Path to Dockerfile.

    Returns:
        ScanTargetResult with audit findings.
    """
    file_path = Path(path)
    if not file_path.exists():
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.DOCKERFILE,
            findings=[],
            error_message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.DOCKERFILE,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = DockerfileScanner(content=content, target_path=str(file_path))
    return scanner.scan()
