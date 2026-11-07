# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the CLI interface using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_container_auditor.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Test CLI top-level and subcommand help commands."""
    res = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Enterprise container security auditor" in res.stdout

    res_scan = runner.invoke(app, ["scan", "--help"], env=CLI_ENV)
    assert res_scan.exit_code == 0
    assert "--format" in res_scan.stdout
    assert "--min-severity" in res_scan.stdout
    assert "--fail-on" in res_scan.stdout

    res_rules = runner.invoke(app, ["rules", "--help"], env=CLI_ENV)
    assert res_rules.exit_code == 0
    assert "List all supported LH-CONT security audit detection rules" in res_rules.stdout


def test_cli_rules_list() -> None:
    """Test listing all 10 LH-CONT detection rules."""
    res = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert res.exit_code == 0
    for i in range(1, 11):
        rule_id = f"LH-CONT-{i:03d}"
        assert rule_id in res.stdout


def test_cli_scan_clean_dockerfile(tmp_path: Path) -> None:
    """Test scanning a secure Dockerfile produces exit code 0."""
    clean_df = tmp_path / "Dockerfile"
    clean_df.write_text(
        "FROM alpine:3.19.1\n"
        "RUN apk add --no-cache curl\n"
        "USER 10001\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n"
    )

    res = runner.invoke(app, ["scan", str(clean_df)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_dockerfile(tmp_path: Path) -> None:
    """Test scanning a vulnerable Dockerfile produces exit code 1 with default fail-on HIGH."""
    vuln_df = tmp_path / "Dockerfile"
    vuln_df.write_text(
        "FROM alpine:latest\nRUN curl -s https://example.com/install.sh | sh\nUSER root\n"
    )

    res = runner.invoke(app, ["scan", str(vuln_df)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-CONT-001" in res.stdout
    assert "LH-CONT-002" in res.stdout
    assert "LH-CONT-004" in res.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    """Test CLI output in JSON format."""
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER appuser\nHEALTHCHECK CMD true\n")

    res = runner.invoke(app, ["scan", str(df), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["report_type"] == "container_audit"
    assert "summary" in data


def test_cli_scan_sarif_output(tmp_path: Path) -> None:
    """Test CLI output in SARIF format."""
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:latest\nUSER root\n")

    res = runner.invoke(
        app,
        ["scan", str(df), "--format", "sarif", "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test writing scan results to an output file."""
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER appuser\nHEALTHCHECK CMD true\n")
    out_file = tmp_path / "report.json"

    res = runner.invoke(
        app,
        ["scan", str(df), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["report_type"] == "container_audit"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test --fail-on threshold logic."""
    # File with only MEDIUM finding (unsafe ADD)
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nADD app.py /app/app.py\nUSER appuser\nHEALTHCHECK CMD true\n")

    # Fail on HIGH: should pass (exit 0) because finding is only MEDIUM
    res_high = runner.invoke(
        app,
        ["scan", str(df), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert res_high.exit_code == 0

    # Fail on MEDIUM: should fail (exit 1) because finding is MEDIUM
    res_med = runner.invoke(
        app,
        ["scan", str(df), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert res_med.exit_code == 1


def test_cli_scan_min_severity_filter(tmp_path: Path) -> None:
    """Test --min-severity filtering."""
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM alpine:3.19\n"
        "ADD app.py /app/app.py\n"  # MEDIUM
        "USER appuser\n"  # Clean USER
        # Missing HEALTHCHECK -> LOW
    )

    # Filter min-severity HIGH: LOW and MEDIUM are filtered out, leaving 0 findings
    res = runner.invoke(
        app,
        ["scan", str(df), "--min-severity", "HIGH", "--format", "json"],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["summary"]["total_findings"] == 0


def test_cli_scan_directory(tmp_path: Path) -> None:
    """Test scanning a directory containing both Dockerfile and Compose artifacts."""
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER appuser\nHEALTHCHECK CMD true\n")

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  web:\n    image: nginx:1.25\n    healthcheck:\n      test: ['CMD', 'true']\n"
    )

    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert len(data["results"]) >= 2


def test_cli_scan_nonexistent_target() -> None:
    """Test error handling when target path does not exist."""
    res = runner.invoke(app, ["scan", "/nonexistent/path/target"], env=CLI_ENV)
    assert res.exit_code == 2
    assert "does not exist" in res.stdout
