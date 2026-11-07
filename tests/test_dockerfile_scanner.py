# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_dockerfile_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for DockerfileScanner and core detection rules."""

from __future__ import annotations

from pathlib import Path

from lh_container_auditor.dockerfile_scanner import DockerfileScanner, scan_dockerfile
from lh_container_auditor.models import FindingCategory, FindingSeverity

# --------------------------------------------------------------------------
# --- Rule LH-CONT-001: Container Running as Root (CRITICAL) ---
# Evaluates security posture against container running as root.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_unpinned_base_image(tmp_path: Path) -> None:
    """Test LH-CONT-001: Unpinned or :latest base image in FROM."""
    # Violations: no tag and :latest tag
    df_vuln = tmp_path / "Dockerfile.vuln"
    df_vuln.write_text(
        "FROM alpine\n"
        "RUN echo hello\n"
        "FROM ubuntu:latest AS runner\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
    )
    res = scan_dockerfile(df_vuln)
    rule_ids = [f.rule_id for f in res.findings]
    assert rule_ids.count("LH-CONT-001") == 2

    # Clean: pinned tags, sha256 digest, scratch, and local stage alias
    df_clean = tmp_path / "Dockerfile.clean"
    df_clean.write_text(
        "FROM golang:1.22-alpine AS builder\n"
        "RUN apk add --no-cache git\n"
        "FROM builder AS tester\n"
        "RUN echo test\n"
        "FROM alpine:3.19.1\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    res_clean = scan_dockerfile(df_clean)
    assert "LH-CONT-001" not in [f.rule_id for f in res_clean.findings]

    # Scratch and sha256 digest
    df_scratch = tmp_path / "Dockerfile.scratch"
    df_scratch.write_text("FROM scratch\nUSER 10001\nHEALTHCHECK CMD true\n")
    res_scratch = scan_dockerfile(df_scratch)
    assert "LH-CONT-001" not in [f.rule_id for f in res_scratch.findings]
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-002: Base Image Tag is Mutable (:latest or Unpinned) (HIGH) ---
    # Evaluates security posture against base image tag is mutable (:latest or
    # unpinned).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_missing_or_root_user(tmp_path: Path) -> None:
    """Test LH-CONT-002: Missing non-root USER or explicit USER root / 0."""
    # Missing USER
    df_missing = tmp_path / "Dockerfile.missing_user"
    df_missing.write_text("FROM alpine:3.19\nRUN echo hello\nHEALTHCHECK CMD true\n")
    res_missing = scan_dockerfile(df_missing)
    user_findings = [f for f in res_missing.findings if f.rule_id == "LH-CONT-002"]
    assert len(user_findings) == 1
    assert user_findings[0].severity == FindingSeverity.CRITICAL

    # Explicit root / 0
    df_root = tmp_path / "Dockerfile.root"
    df_root.write_text("FROM alpine:3.19\nUSER root\nHEALTHCHECK CMD true\n")
    res_root = scan_dockerfile(df_root)
    assert any(f.rule_id == "LH-CONT-002" for f in res_root.findings)

    # Valid non-root user
    df_valid = tmp_path / "Dockerfile.valid_user"
    df_valid.write_text("FROM alpine:3.19\nUSER 10001:10001\nHEALTHCHECK CMD true\n")
    res_valid = scan_dockerfile(df_valid)
    assert not any(f.rule_id == "LH-CONT-002" for f in res_valid.findings)


def test_multistage_user_evaluation(tmp_path: Path) -> None:
    """Test that LH-CONT-002 evaluates final stage."""
    # Builder stage runs as root, but final stage switches to non-root
    df = tmp_path / "Dockerfile.multi"
    df.write_text(
        "FROM golang:1.22-alpine AS builder\n"
        "# runs as default root during build\n"
        "RUN apk add --no-cache build-base\n"
        "FROM alpine:3.19\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    res = scan_dockerfile(df)
    assert not any(f.rule_id == "LH-CONT-002" for f in res.findings)
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


def test_hardcoded_secrets() -> None:
    """Test LH-CONT-003: Hardcoded secrets/tokens in ENV, ARG, or LABEL."""
    content = (
        "FROM alpine:3.19\n"
        'ENV API_KEY="sk_live_1234567890abcdef"\n'
        "ARG GITHUB_TOKEN=ghp_123456789012345678901234567890123456\n"
        "ENV SAFE_VAR=${RUNTIME_SECRET}\n"
        'ENV EMPTY_VAR=""\n'
        'LABEL maintainer="team@example.com"\n'
        'LABEL auth.token="secret_token_123"\n'
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    secret_findings = [f for f in res.findings if f.rule_id == "LH-CONT-003"]
    assert len(secret_findings) >= 2
    for f in secret_findings:
        assert f.severity == FindingSeverity.CRITICAL
        assert f.category == FindingCategory.SECRET_EXPOSURE
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-004: Privileged Container Execution Enabled (HIGH) ---
    # Evaluates security posture against privileged container execution enabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_remote_script_pipe_to_shell() -> None:
    """Test LH-CONT-004: Remote script pipe-to-shell in RUN."""
    content = (
        "FROM alpine:3.19\n"
        "RUN curl -fsSL https://example.com/install.sh | sh\n"
        "RUN wget -qO- https://example.com/setup | bash -\n"
        "RUN curl -s http://test.com | /bin/sh\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    pipe_findings = [f for f in res.findings if f.rule_id == "LH-CONT-004"]
    assert len(pipe_findings) == 3
    for f in pipe_findings:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-005: Dangerous Host Volume Mount Exposed (CRITICAL) ---
    # Evaluates security posture against dangerous host volume mount exposed.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_unsafe_add_instruction() -> None:
    """Test LH-CONT-005: Unsafe ADD instruction instead of COPY."""
    content = (
        "FROM alpine:3.19\n"
        "ADD app.py /app/app.py\n"
        "ADD https://example.com/data.json /tmp/data.json\n"
        "ADD rootfs.tar.gz /\n"  # Legitimate archive extraction
        "COPY config.yaml /app/config.yaml\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    add_findings = [f for f in res.findings if f.rule_id == "LH-CONT-005"]
    assert len(add_findings) == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-007: Container Missing HEALTHCHECK Instruction (MEDIUM) ---
    # Evaluates security posture against container missing healthcheck instruction.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_unpurged_package_manager_cache() -> None:
    """Test LH-CONT-007: Unpurged package manager cache in RUN."""
    content = (
        "FROM ubuntu:22.04\n"
        "RUN apt-get update && apt-get install -y nginx\n"  # Missing rm lists
        "RUN apk add curl\n"  # Missing --no-cache
        "RUN pip install requests\n"  # Missing --no-cache-dir
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    cache_findings = [f for f in res.findings if f.rule_id == "LH-CONT-007"]
    assert len(cache_findings) == 3

    # Clean version
    clean_content = (
        "FROM ubuntu:22.04\n"
        "RUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*\n"
        "RUN apk add --no-cache curl\n"
        "RUN pip install --no-cache-dir requests\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    clean_scanner = DockerfileScanner(clean_content)
    clean_res = clean_scanner.scan()
    assert not any(f.rule_id == "LH-CONT-007" for f in clean_res.findings)
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


def test_exposed_sensitive_ports() -> None:
    """Test LH-CONT-008: Exposed sensitive ports (22, 23, 2375, 3389)."""
    content = (
        "FROM alpine:3.19\nEXPOSE 22/tcp 8080\nEXPOSE 2375\nUSER appuser\nHEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    port_findings = [f for f in res.findings if f.rule_id == "LH-CONT-008"]
    assert len(port_findings) == 2
    ports = [f.details.get("port") for f in port_findings]
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


def test_missing_healthcheck() -> None:
    """Test LH-CONT-009: Missing HEALTHCHECK in final stage."""
    content = "FROM alpine:3.19\nUSER appuser\n"
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    assert any(f.rule_id == "LH-CONT-009" for f in res.findings)

    # With HEALTHCHECK
    content_with_hc = (
        "FROM alpine:3.19\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n"
        "USER appuser\n"
    )
    res_hc = DockerfileScanner(content_with_hc).scan()
    assert not any(f.rule_id == "LH-CONT-009" for f in res_hc.findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-CONT-010 (LOW):
    #     Missing Container Metadata Labels or Version Declaration
    # ---
    # Evaluates security posture against missing container metadata labels or
    # version declaration.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_sudoers_and_suid() -> None:
    """Test LH-CONT-010: Sudoers NOPASSWD or SUID/SGID chmod in RUN."""
    content = (
        "FROM alpine:3.19\n"
        "RUN echo 'appuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers\n"
        "RUN chmod 4755 /usr/local/bin/helper\n"
        "RUN chmod +s /bin/myapp\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    priv_findings = [f for f in res.findings if f.rule_id == "LH-CONT-010"]
    assert len(priv_findings) == 3


def test_empty_or_nonexistent_dockerfile(tmp_path: Path) -> None:
    """Test scanner behavior with empty or missing Dockerfile."""
    res_nonexistent = scan_dockerfile(tmp_path / "NonexistentDockerfile")
    assert res_nonexistent.error_message is not None

    empty_file = tmp_path / "Dockerfile.empty"
    empty_file.write_text("# Only comments\n\n")
    res_empty = scan_dockerfile(empty_file)
    assert res_empty.error_message is not None
