# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.oci_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OCI image and container configuration scanner for lh-container-auditor.

Inspects OCI image layout directories, exported image tar archives, and container
configuration JSON objects for user privileges, secrets, exposed ports, and healthchecks.
"""

from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path
from typing import Any

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


class OciScanner:
    """Scanner for analyzing OCI and Docker image configurations."""

    def __init__(self, target_path: str) -> None:
        """Initialize OciScanner.

        Args:
            target_path: Path to OCI directory, tar archive, or config JSON file.
        """
        self.target_path = target_path

    def scan(self) -> ScanTargetResult:
        """Scan target OCI directory, archive, or JSON file.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        target = Path(self.target_path)
        if not target.exists():
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.OCI_IMAGE,
                findings=[],
                error_message=f"Target path does not exist: {self.target_path}",
            )

        # Case 1: Directory (OCI image layout or directory with config.json)
        if target.is_dir():
            return self._scan_directory(target)

        # Case 2: Tar archive (.tar or .tar.gz)
        if tarfile.is_tarfile(target):
            return self._scan_tar_archive(target)

        # Case 3: JSON file (config.json, image.json)
        if target.suffix.lower() == ".json":
            return self._scan_json_file(target)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.OCI_IMAGE,
            findings=[],
            error_message="Unsupported artifact format. Expected directory, tar archive, or JSON.",
        )

    def _scan_json_file(self, path: Path) -> ScanTargetResult:
        """Inspect a single OCI/container config JSON file."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
        except Exception as e:
            return ScanTargetResult(
                target=str(path),
                target_type=TargetType.OCI_CONFIG,
                findings=[],
                error_message=f"Failed to read/parse JSON config: {e}",
            )

        findings = self._analyze_config_data(data, source_name=str(path))
        return ScanTargetResult(
            target=str(path),
            target_type=TargetType.OCI_CONFIG,
            findings=findings,
        )

    def _scan_directory(self, dir_path: Path) -> ScanTargetResult:
        """Inspect an OCI image layout directory."""
        index_file = dir_path / "index.json"
        config_file = dir_path / "config.json"

        if config_file.is_file():
            return self._scan_json_file(config_file)

        if not index_file.is_file():
            return ScanTargetResult(
                target=str(dir_path),
                target_type=TargetType.OCI_IMAGE,
                findings=[],
                error_message="Directory is not a valid OCI layout (missing index or config JSON).",
            )

        try:
            index_data = json.loads(index_file.read_text(encoding="utf-8"))
            manifests = index_data.get("manifests", [])
            if not manifests:
                return ScanTargetResult(
                    target=str(dir_path),
                    target_type=TargetType.OCI_IMAGE,
                    findings=[],
                    error_message="index.json contains no manifests.",
                )

            # Follow manifest digest to blob
            manifest_digest = manifests[0].get("digest", "")
            if not manifest_digest.startswith("sha256:"):
                return ScanTargetResult(
                    target=str(dir_path),
                    target_type=TargetType.OCI_IMAGE,
                    findings=[],
                    error_message=f"Unsupported digest scheme in manifest: {manifest_digest}",
                )

            manifest_hash = manifest_digest.split("sha256:")[1]
            manifest_blob = dir_path / "blobs" / "sha256" / manifest_hash

            if not manifest_blob.is_file():
                return ScanTargetResult(
                    target=str(dir_path),
                    target_type=TargetType.OCI_IMAGE,
                    findings=[],
                    error_message=f"Manifest blob not found: {manifest_blob}",
                )

            manifest_json = json.loads(manifest_blob.read_text(encoding="utf-8"))
            config_digest = manifest_json.get("config", {}).get("digest", "")
            if not config_digest.startswith("sha256:"):
                return ScanTargetResult(
                    target=str(dir_path),
                    target_type=TargetType.OCI_IMAGE,
                    findings=[],
                    error_message=f"Invalid config blob digest in manifest: {config_digest}",
                )

            config_hash = config_digest.split("sha256:")[1]
            config_blob = dir_path / "blobs" / "sha256" / config_hash

            if not config_blob.is_file():
                return ScanTargetResult(
                    target=str(dir_path),
                    target_type=TargetType.OCI_IMAGE,
                    findings=[],
                    error_message=f"Configuration blob not found: {config_blob}",
                )

            config_data = json.loads(config_blob.read_text(encoding="utf-8"))
            findings = self._analyze_config_data(config_data, source_name=str(dir_path))

            return ScanTargetResult(
                target=str(dir_path),
                target_type=TargetType.OCI_IMAGE,
                findings=findings,
            )
        except Exception as e:
            return ScanTargetResult(
                target=str(dir_path),
                target_type=TargetType.OCI_IMAGE,
                findings=[],
                error_message=f"Failed to inspect OCI layout directory: {e}",
            )

    def _scan_tar_archive(self, tar_path: Path) -> ScanTargetResult:
        """Inspect a saved Docker/OCI image tar archive."""
        try:
            with tarfile.open(tar_path, mode="r:*") as tar:
                # Look for manifest.json
                manifest_member = None
                for member in tar.getmembers():
                    if member.name in ("manifest.json", "./manifest.json"):
                        manifest_member = member
                        break

                if manifest_member:
                    fileobj = tar.extractfile(manifest_member)
                    if fileobj is None:
                        return ScanTargetResult(
                            target=str(tar_path),
                            target_type=TargetType.OCI_IMAGE,
                            findings=[],
                            error_message="Could not read manifest.json from tar archive.",
                        )
                    manifest_data = json.loads(fileobj.read().decode("utf-8"))
                    if isinstance(manifest_data, list) and manifest_data:
                        config_filename = manifest_data[0].get("Config")
                        if config_filename:
                            config_member = None
                            for member in tar.getmembers():
                                if member.name in (config_filename, f"./{config_filename}"):
                                    config_member = member
                                    break
                            if config_member:
                                cf = tar.extractfile(config_member)
                                if cf:
                                    config_data = json.loads(cf.read().decode("utf-8"))
                                    findings = self._analyze_config_data(
                                        config_data, source_name=str(tar_path)
                                    )
                                    return ScanTargetResult(
                                        target=str(tar_path),
                                        target_type=TargetType.OCI_IMAGE,
                                        findings=findings,
                                    )

                # Alternatively look for config.json or index.json
                for member in tar.getmembers():
                    if member.name.endswith(".json") and (
                        "config" in member.name.lower() or "oci" in member.name.lower()
                    ):
                        fileobj = tar.extractfile(member)
                        if fileobj:
                            raw_content = fileobj.read()
                            try:
                                data = json.loads(raw_content.decode("utf-8"))
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                data = None

                            if isinstance(data, dict) and (
                                "config" in data or "architecture" in data or "rootfs" in data
                            ):
                                findings = self._analyze_config_data(
                                    data, source_name=str(tar_path)
                                )
                                return ScanTargetResult(
                                    target=str(tar_path),
                                    target_type=TargetType.OCI_IMAGE,
                                    findings=findings,
                                )

            return ScanTargetResult(
                target=str(tar_path),
                target_type=TargetType.OCI_IMAGE,
                findings=[],
                error_message="No valid Docker/OCI manifest or configuration found in archive.",
            )
        except Exception as e:
            return ScanTargetResult(
                target=str(tar_path),
                target_type=TargetType.OCI_IMAGE,
                findings=[],
                error_message=f"Error reading image archive: {e}",
            )

    def _analyze_config_data(self, data: dict[str, Any], source_name: str) -> list[Finding]:
        """Evaluate security rules on parsed OCI image configuration data."""
        findings: list[Finding] = []

        # Extract config dictionary: could be at root or under 'config' or 'container_config'
        cfg = data.get("config") or data.get("Config") or data

        # Rule 2: LH-CONT-002 - Missing non-root USER or explicit USER root / 0
        user_val = cfg.get("User") or cfg.get("user")
        if not user_val:
            findings.append(
                Finding(
                    rule_id="LH-CONT-002",
                    title="Missing non-root USER or explicit USER root / 0",
                    category=FindingCategory.USER_PRIVILEGE,
                    severity=FindingSeverity.CRITICAL,
                    target=source_name,
                    message=(
                        "OCI image configuration does not define a 'User' attribute. "
                        "The image will run as root (UID 0) by default."
                    ),
                    details={"user": ""},
                )
            )
        else:
            user_clean = str(user_val).split(":")[0].strip().strip('"').strip("'")
            if user_clean.lower() in ("root", "0"):
                findings.append(
                    Finding(
                        rule_id="LH-CONT-002",
                        title="Missing non-root USER or explicit USER root / 0",
                        category=FindingCategory.USER_PRIVILEGE,
                        severity=FindingSeverity.CRITICAL,
                        target=source_name,
                        message=(
                            f"OCI image explicitly specifies User '{user_val}'. "
                            "Container processes will execute with superuser privileges."
                        ),
                        details={"user": user_val},
                    )
                )

        # Rule 3: LH-CONT-003 - Hardcoded secrets in Env or Labels
        env_list = cfg.get("Env") or cfg.get("env") or []
        if isinstance(env_list, list):
            for entry in env_list:
                if isinstance(entry, str) and "=" in entry:
                    k, v = entry.split("=", 1)
                    k_clean, v_clean = k.strip(), v.strip().strip('"').strip("'")
                    if not v_clean or PLACEHOLDER_REGEX.match(v_clean):
                        continue

                    # Check explicit token patterns
                    found_token = False
                    for regex, name in (
                        (PRIVATE_KEY_REGEX, "Private Key"),
                        (AWS_KEY_REGEX, "AWS Access Key"),
                        (GITHUB_TOKEN_REGEX, "GitHub Token"),
                        (SLACK_TOKEN_REGEX, "Slack Token"),
                    ):
                        if regex.search(v_clean):
                            findings.append(
                                Finding(
                                    rule_id="LH-CONT-003",
                                    title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                                    category=FindingCategory.SECRET_EXPOSURE,
                                    severity=FindingSeverity.CRITICAL,
                                    target=source_name,
                                    message=(
                                        f"OCI image environment variable '{k_clean}' contains "
                                        f"hardcoded {name}."
                                    ),
                                    details={"key": k_clean, "secret_type": name},
                                )
                            )
                            found_token = True
                            break

                    if not found_token and SECRET_KEY_REGEX.search(k_clean):
                        findings.append(
                            Finding(
                                rule_id="LH-CONT-003",
                                title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                                category=FindingCategory.SECRET_EXPOSURE,
                                severity=FindingSeverity.CRITICAL,
                                target=source_name,
                                message=(
                                    f"OCI image environment variable '{k_clean}' contains "
                                    "potential hardcoded secret."
                                ),
                                details={"key": k_clean},
                            )
                        )

        # Rule 8: LH-CONT-008 - Exposed sensitive ports
        exposed_ports = cfg.get("ExposedPorts") or cfg.get("exposed_ports") or {}
        if isinstance(exposed_ports, dict):
            for port_proto in exposed_ports:
                port_part = port_proto.split("/")[0]
                try:
                    port_num = int(port_part)
                    if port_num in SENSITIVE_PORTS:
                        findings.append(
                            Finding(
                                rule_id="LH-CONT-008",
                                title="Exposed sensitive ports (22, 23, 2375, 3389)",
                                category=FindingCategory.NETWORK_SECURITY,
                                severity=FindingSeverity.MEDIUM,
                                target=source_name,
                                message=(
                                    f"OCI image exposes sensitive port {port_num} ({port_proto}). "
                                    "Avoid running remote access and Docker daemon ports in images."
                                ),
                                details={"port": port_num, "entry": port_proto},
                            )
                        )
                except ValueError:
                    continue

        # Rule 9: LH-CONT-009 - Missing Healthcheck
        healthcheck = cfg.get("Healthcheck") or cfg.get("healthcheck")
        if not healthcheck or (
            isinstance(healthcheck, dict)
            and (
                str(healthcheck.get("Test", "")).upper() == "NONE"
                or str(healthcheck.get("test", "")).upper() == "NONE"
            )
        ):
            findings.append(
                Finding(
                    rule_id="LH-CONT-009",
                    title="Missing HEALTHCHECK in final stage",
                    category=FindingCategory.HEALTHCHECK,
                    severity=FindingSeverity.LOW,
                    target=source_name,
                    message=(
                        "OCI image configuration lacks a Healthcheck definition. "
                        "Define healthcheck parameters to enable health monitoring."
                    ),
                    details={},
                )
            )

        # Inspect history commands if present
        history = data.get("history", [])
        if isinstance(history, list):
            for item in history:
                cmd = item.get("created_by", "")
                if not cmd:
                    continue

                # Pipe to shell
                if PIPE_SHELL_REGEX.search(cmd):
                    findings.append(
                        Finding(
                            rule_id="LH-CONT-004",
                            title="Remote script pipe-to-shell (curl/wget | sh/bash) in RUN",
                            category=FindingCategory.COMMAND_EXECUTION,
                            severity=FindingSeverity.HIGH,
                            target=source_name,
                            message=(
                                "Remote script piped to shell found in image build history. "
                                "Remote execution without hash checks poses supply chain risks."
                            ),
                            details={"command": cmd},
                        )
                    )

                # NOPASSWD or SUID
                if (
                    NOPASSWD_REGEX.search(cmd)
                    or SUID_OCTAL_REGEX.search(cmd)
                    or SUID_SYMBOLIC_REGEX.search(cmd)
                ):
                    findings.append(
                        Finding(
                            rule_id="LH-CONT-010",
                            title="Sudoers NOPASSWD or SUID/SGID chmod in RUN",
                            category=FindingCategory.PERMISSION_CONFIG,
                            severity=FindingSeverity.HIGH,
                            target=source_name,
                            message=(
                                "Privilege escalation risk found in image build history "
                                "(sudoers NOPASSWD or SUID/SGID bit assigned)."
                            ),
                            details={"command": cmd},
                        )
                    )

        return findings


def scan_oci(path: Path | str) -> ScanTargetResult:
    """Scan an OCI image directory, archive, or config file.

    Args:
        path: Path to OCI target.

    Returns:
        ScanTargetResult with audit findings.
    """
    scanner = OciScanner(str(path))
    return scanner.scan()
