# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_compose_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for ComposeScanner."""

from __future__ import annotations

from pathlib import Path

from lh_container_auditor.compose_scanner import ComposeScanner, scan_compose
from lh_container_auditor.models import FindingSeverity

# --------------------------------------------------------------------------
# --- Rule LH-CONT-006: Host Namespace Sharing Enabled (HIGH) ---
# Evaluates security posture against host namespace sharing enabled.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_compose_privileged_and_namespaces() -> None:
    """Test LH-CONT-006: Compose privileged mode and host namespaces."""
    yaml_content = """
    services:
      app:
        image: nginx:1.25
        privileged: true
        network_mode: "host"
        pid: "host"
        ipc: "host"
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_006 = [f for f in res.findings if f.rule_id == "LH-CONT-006"]
    assert len(rule_006) == 4
    for f in rule_006:
        assert f.severity == FindingSeverity.HIGH


def test_compose_docker_sock_mount() -> None:
    """Test LH-CONT-006: docker.sock volume mount."""
    yaml_content = """
    services:
      runner:
        image: alpine:3.19
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
          - /tmp/app:/app
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_006 = [f for f in res.findings if f.rule_id == "LH-CONT-006"]
    assert len(rule_006) == 1
    assert "docker.sock" in rule_006[0].message
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-002: Base Image Tag is Mutable (:latest or Unpinned) (HIGH) ---
    # Evaluates security posture against base image tag is mutable (:latest or
    # unpinned).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_compose_user_root() -> None:
    """Test LH-CONT-002: Service user explicitly set to root or 0."""
    yaml_content = """
    services:
      web:
        image: python:3.12-slim
        user: "root"
      worker:
        image: python:3.12-slim
        user: "0"
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_002 = [f for f in res.findings if f.rule_id == "LH-CONT-002"]
    assert len(rule_002) == 2
    for f in rule_002:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-003 (CRITICAL):
    #     Hardcoded Secrets Declared in ENV or ARG Instructions
    # ---
    # Evaluates security posture against hardcoded secrets declared in env or arg
    # instructions.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_compose_secrets() -> None:
    """Test LH-CONT-003: Hardcoded secrets in environment and build args."""
    yaml_content = """
    services:
      api:
        image: node:20-alpine
        environment:
          - DB_PASSWORD=SuperSecretPass123!
          - SAFE_VAR=${RUNTIME_ENV}
        build:
          context: .
          args:
            GITHUB_TOKEN: ghp_123456789012345678901234567890123456
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_003 = [f for f in res.findings if f.rule_id == "LH-CONT-003"]
    assert len(rule_003) >= 2
    for f in rule_003:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-008 (MEDIUM):
    #     Use of Dangerous ADD Instruction Fetching Remote Tarballs
    # ---
    # Evaluates security posture against use of dangerous add instruction fetching
    # remote tarballs.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_compose_sensitive_ports() -> None:
    """Test LH-CONT-008: Sensitive ports exposed in ports/expose."""
    yaml_content = """
    services:
      bastion:
        image: alpine:3.19
        ports:
          - "22:22"
          - "8080:8080"
        expose:
          - "2375"
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_008 = [f for f in res.findings if f.rule_id == "LH-CONT-008"]
    assert len(rule_008) == 2
    ports = [f.details.get("port") for f in rule_008]
    assert 22 in ports
    assert 2375 in ports
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


def test_compose_healthcheck() -> None:
    """Test LH-CONT-009: Missing healthcheck on Compose service."""
    yaml_content = """
    services:
      web:
        image: nginx:1.25
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    assert any(f.rule_id == "LH-CONT-009" for f in res.findings)

    # Service with healthcheck
    yaml_with_hc = """
    services:
      web:
        image: nginx:1.25
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost"]
          interval: 30s
    """
    res_hc = ComposeScanner(yaml_with_hc).scan()
    assert not any(f.rule_id == "LH-CONT-009" for f in res_hc.findings)


def test_compose_clean_and_errors(tmp_path: Path) -> None:
    """Test clean compose file and error handling."""
    clean_yaml = """
    services:
      app:
        image: alpine:3.19
        user: "10001:10001"
        healthcheck:
          test: ["CMD", "true"]
        ports:
          - "8080:8080"
    """
    res = ComposeScanner(clean_yaml).scan()
    assert len(res.findings) == 0

    # Nonexistent file
    res_missing = scan_compose(tmp_path / "missing.yml")
    assert res_missing.error_message is not None

    # Invalid YAML
    res_invalid = ComposeScanner(": invalid yaml - *").scan()
    assert res_invalid.error_message is not None
