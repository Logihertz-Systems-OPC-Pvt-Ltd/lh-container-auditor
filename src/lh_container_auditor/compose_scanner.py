# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.compose_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Docker Compose static analysis scanner for lh-container-auditor.

Inspects Compose configurations for privileged mode, host namespaces,
docker.sock mounts, hardcoded secrets, exposed sensitive ports, and healthchecks.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

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


class ComposeScanner:
    """Scanner for analyzing Docker Compose files."""

    def __init__(self, content: str, target_path: str = "docker-compose.yml") -> None:
        """Initialize ComposeScanner with file contents.

        Args:
            content: Raw YAML content string.
            target_path: Path or filename for reporting.
        """
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()

    def _find_line(self, pattern: str, start_line: int = 1) -> int | None:
        """Find the line number matching a regex pattern after start_line."""
        regex = re.compile(pattern)
        for idx in range(start_line - 1, len(self.lines)):
            if regex.search(self.lines[idx]):
                return idx + 1
        return None

    def scan(self) -> ScanTargetResult:
        """Execute all Compose security audit rules.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        try:
            data = yaml.safe_load(self.content)
        except Exception as e:
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.COMPOSE,
                findings=[],
                error_message=f"YAML parsing error: {e}",
            )

        if not isinstance(data, dict):
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.COMPOSE,
                findings=[],
                error_message="Compose file root is not a valid YAML dictionary.",
            )

        services = data.get("services")
        if not services or not isinstance(services, dict):
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.COMPOSE,
                findings=[],
                error_message="No 'services' section found in Compose file.",
            )

        findings: list[Finding] = []

        for service_name, service_cfg in services.items():
            if not isinstance(service_cfg, dict):
                continue

            svc_line = self._find_line(rf"^\s*{re.escape(service_name)}\s*:") or 1

            self._check_privileged_and_namespaces(service_name, service_cfg, svc_line, findings)
            self._check_docker_sock_mount(service_name, service_cfg, svc_line, findings)
            self._check_user(service_name, service_cfg, svc_line, findings)
            self._check_secrets(service_name, service_cfg, svc_line, findings)
            self._check_ports(service_name, service_cfg, svc_line, findings)
            self._check_healthcheck(service_name, service_cfg, svc_line, findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.COMPOSE,
            findings=findings,
        )

    def _check_privileged_and_namespaces(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check for privileged: true or host namespaces (LH-CONT-006)."""
        # privileged
        if service_cfg.get("privileged") is True or str(service_cfg.get("privileged")).lower() in (
            "true",
            "1",
            "yes",
        ):
            line = self._find_line(r"privileged\s*:\s*(?:true|yes|1)", svc_line) or svc_line
            findings.append(
                Finding(
                    rule_id="LH-CONT-006",
                    title="Compose privileged: true, host namespaces, or docker.sock mount",
                    category=FindingCategory.CONTAINER_CAPABILITY,
                    severity=FindingSeverity.HIGH,
                    target=self.target_path,
                    line_number=line,
                    message=(
                        f"Service '{service_name}' runs in privileged mode. Privileged containers "
                        "bypass security boundaries and have full access to the host kernel."
                    ),
                    details={"service": service_name, "setting": "privileged: true"},
                )
            )

        # host namespaces: network_mode, ipc, pid, userns_mode
        for ns_key in ("network_mode", "ipc", "pid", "userns_mode"):
            val = service_cfg.get(ns_key)
            if isinstance(val, str) and val.strip().lower() == "host":
                line = self._find_line(rf"{ns_key}\s*:\s*[\"']?host[\"']?", svc_line) or svc_line
                findings.append(
                    Finding(
                        rule_id="LH-CONT-006",
                        title="Compose privileged: true, host namespaces, or docker.sock mount",
                        category=FindingCategory.CONTAINER_CAPABILITY,
                        severity=FindingSeverity.HIGH,
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"Service '{service_name}' shares host namespace '{ns_key}: host'. "
                            "This breaks process/network isolation between container and host."
                        ),
                        details={"service": service_name, "setting": f"{ns_key}: host"},
                    )
                )

    def _check_docker_sock_mount(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check for mounting docker.sock into container (LH-CONT-006)."""
        volumes = service_cfg.get("volumes", [])
        if not isinstance(volumes, list):
            return

        for vol in volumes:
            vol_str = ""
            if isinstance(vol, str):
                vol_str = vol
            elif isinstance(vol, dict):
                vol_str = str(vol.get("source", ""))

            if "docker.sock" in vol_str:
                line = self._find_line(r"docker\.sock", svc_line) or svc_line
                findings.append(
                    Finding(
                        rule_id="LH-CONT-006",
                        title="Compose privileged: true, host namespaces, or docker.sock mount",
                        category=FindingCategory.CONTAINER_CAPABILITY,
                        severity=FindingSeverity.HIGH,
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"Service '{service_name}' mounts Docker socket '{vol_str}'. "
                            "Mounting the Docker daemon socket grants root-equivalent control "
                            "over the host."
                        ),
                        details={"service": service_name, "volume": vol_str},
                    )
                )

    def _check_user(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check user configuration for root execution (LH-CONT-002)."""
        user_val = service_cfg.get("user")
        if user_val is not None:
            user_str = str(user_val).strip().strip('"').strip("'")
            user_part = user_str.split(":")[0].strip()
            if user_part.lower() in ("root", "0"):
                line = self._find_line(r"user\s*:\s*[\"']?(?:root|0)", svc_line) or svc_line
                findings.append(
                    Finding(
                        rule_id="LH-CONT-002",
                        title="Missing non-root USER or explicit USER root / 0",
                        category=FindingCategory.USER_PRIVILEGE,
                        severity=FindingSeverity.CRITICAL,
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"Service '{service_name}' explicitly specifies user '{user_str}', "
                            "running container processes as root."
                        ),
                        details={"service": service_name, "user": user_str},
                    )
                )

    def _check_secrets(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check for hardcoded secrets in environment, args, or labels (LH-CONT-003)."""
        env_vars = service_cfg.get("environment")
        items: list[tuple[str, str]] = []

        if isinstance(env_vars, dict):
            for k, v in env_vars.items():
                items.append((str(k), str(v) if v is not None else ""))
        elif isinstance(env_vars, list):
            for entry in env_vars:
                if isinstance(entry, str) and "=" in entry:
                    k, v = entry.split("=", 1)
                    items.append((k.strip(), v.strip()))

        # Also inspect build.args
        build_cfg = service_cfg.get("build")
        if isinstance(build_cfg, dict):
            args = build_cfg.get("args")
            if isinstance(args, dict):
                for k, v in args.items():
                    items.append((str(k), str(v) if v is not None else ""))
            elif isinstance(args, list):
                for entry in args:
                    if isinstance(entry, str) and "=" in entry:
                        k, v = entry.split("=", 1)
                        items.append((k.strip(), v.strip()))

        for key, val in items:
            val_clean = val.strip().strip('"').strip("'")
            if not val_clean or PLACEHOLDER_REGEX.match(val_clean):
                continue

            # Check explicit tokens in value
            found_token = False
            for regex, name in (
                (PRIVATE_KEY_REGEX, "Private Key"),
                (AWS_KEY_REGEX, "AWS Access Key"),
                (GITHUB_TOKEN_REGEX, "GitHub Token"),
                (SLACK_TOKEN_REGEX, "Slack Token"),
            ):
                if regex.search(val_clean):
                    line = self._find_line(re.escape(key), svc_line) or svc_line
                    findings.append(
                        Finding(
                            rule_id="LH-CONT-003",
                            title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                            category=FindingCategory.SECRET_EXPOSURE,
                            severity=FindingSeverity.CRITICAL,
                            target=self.target_path,
                            line_number=line,
                            message=(
                                f"Service '{service_name}' contains hardcoded {name} "
                                f"in environment key '{key}'."
                            ),
                            details={"service": service_name, "key": key, "secret_type": name},
                        )
                    )
                    found_token = True
                    break

            if found_token:
                continue

            if SECRET_KEY_REGEX.search(key):
                line = self._find_line(re.escape(key), svc_line) or svc_line
                findings.append(
                    Finding(
                        rule_id="LH-CONT-003",
                        title="Hardcoded secrets/tokens in ENV, ARG, or LABEL",
                        category=FindingCategory.SECRET_EXPOSURE,
                        severity=FindingSeverity.CRITICAL,
                        target=self.target_path,
                        line_number=line,
                        message=(
                            f"Service '{service_name}' contains potential hardcoded secret "
                            f"in configuration key '{key}'."
                        ),
                        details={"service": service_name, "key": key},
                    )
                )

    def _check_ports(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check for exposed sensitive ports (LH-CONT-008)."""
        ports = service_cfg.get("ports", [])
        if not isinstance(ports, list):
            ports = [ports]

        expose = service_cfg.get("expose", [])
        if not isinstance(expose, list):
            expose = [expose]

        all_port_entries = list(ports) + list(expose)

        for p in all_port_entries:
            port_str = str(p)
            # Format could be "host:container", "ip:host:container", or just "port"
            parts = port_str.split(":")
            container_port_part = parts[-1].split("/")[0]
            try:
                port_num = int(container_port_part)
                if port_num in SENSITIVE_PORTS:
                    line = self._find_line(re.escape(container_port_part), svc_line) or svc_line
                    findings.append(
                        Finding(
                            rule_id="LH-CONT-008",
                            title="Exposed sensitive ports (22, 23, 2375, 3389)",
                            category=FindingCategory.NETWORK_SECURITY,
                            severity=FindingSeverity.MEDIUM,
                            target=self.target_path,
                            line_number=line,
                            message=(
                                f"Service '{service_name}' exposes sensitive port {port_num}. "
                                "Avoid publishing management and daemon ports to networks."
                            ),
                            details={"service": service_name, "port": port_num, "entry": port_str},
                        )
                    )
            except ValueError:
                continue

    def _check_healthcheck(
        self,
        service_name: str,
        service_cfg: dict[str, Any],
        svc_line: int,
        findings: list[Finding],
    ) -> None:
        """Check for missing healthcheck in Compose service (LH-CONT-009)."""
        healthcheck = service_cfg.get("healthcheck")
        if not healthcheck or (
            isinstance(healthcheck, dict)
            and (
                healthcheck.get("disable") is True
                or str(healthcheck.get("test", "")).upper() == "NONE"
            )
        ):
            findings.append(
                Finding(
                    rule_id="LH-CONT-009",
                    title="Missing HEALTHCHECK in final stage",
                    category=FindingCategory.HEALTHCHECK,
                    severity=FindingSeverity.LOW,
                    target=self.target_path,
                    line_number=svc_line,
                    message=(
                        f"Service '{service_name}' does not configure a healthcheck. "
                        "Define healthcheck parameters to monitor service availability."
                    ),
                    details={"service": service_name},
                )
            )


def scan_compose(path: Path | str) -> ScanTargetResult:
    """Read and scan a Docker Compose file from disk.

    Args:
        path: Path to Compose YAML file.

    Returns:
        ScanTargetResult with audit findings.
    """
    file_path = Path(path)
    if not file_path.exists():
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.COMPOSE,
            findings=[],
            error_message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.COMPOSE,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = ComposeScanner(content=content, target_path=str(file_path))
    return scanner.scan()
