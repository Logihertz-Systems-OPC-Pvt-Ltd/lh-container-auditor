# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_coverage_boost
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Additional targeted unit tests to ensure high test coverage across all modules."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_container_auditor.cli import app
from lh_container_auditor.compose_scanner import ComposeScanner
from lh_container_auditor.dockerfile_scanner import DockerfileScanner
from lh_container_auditor.exporters import (
    _get_severity_badge,
    _severity_to_sarif_level,
    render_table_report,
)
from lh_container_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)
from lh_container_auditor.oci_scanner import OciScanner

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_rule_definition_to_dict() -> None:
    """Test serialization of RuleDefinition."""
    rule = RULES_REGISTRY["LH-CONT-001"]
    data = rule.to_dict()
    assert data["rule_id"] == "LH-CONT-001"
    assert "DOCKERFILE" in data["target_types"]


def test_severity_badges_and_sarif_levels() -> None:
    """Test severity badge rendering and sarif levels."""
    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"
    assert _severity_to_sarif_level(FindingSeverity.INFO) == "note"

    badge_crit = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in str(badge_crit)
    badge_info = _get_severity_badge(FindingSeverity.INFO)
    assert "INFO" in str(badge_info)


def test_multiline_and_legacy_dockerfile() -> None:
    """Test Dockerfile with multiline continuation and legacy ENV KEY VALUE syntax."""
    content = (
        "FROM alpine:3.19.1 \\\n"
        "    AS builder\n"
        "ENV SECRET_TOKEN secret_val_xyz123\n"
        "RUN apt-get update \\\n"
        "    && apt-get install -y nginx \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
        "USER appuser\n"
        "HEALTHCHECK CMD true\n"
    )
    scanner = DockerfileScanner(content)
    res = scanner.scan()
    assert any(f.rule_id == "LH-CONT-003" for f in res.findings)
    assert not any(f.rule_id == "LH-CONT-007" for f in res.findings)


def test_compose_mapping_env_and_list_args() -> None:
    """Test Compose with environment map and build args list."""
    yaml_content = """
    services:
      app:
        image: alpine:3.19
        environment:
          API_KEY: "secret_value_123"
        build:
          context: .
          args:
            - SECRET_TOKEN=ghp_123456789012345678901234567890123456
    """
    scanner = ComposeScanner(yaml_content)
    res = scanner.scan()
    rule_003 = [f for f in res.findings if f.rule_id == "LH-CONT-003"]
    assert len(rule_003) >= 2


def test_oci_layout_digest_errors(tmp_path: Path) -> None:
    """Test OCI layout with invalid manifest digest schemes."""
    layout_dir = tmp_path / "bad_oci"
    layout_dir.mkdir()
    (layout_dir / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')

    # index with empty manifests
    (layout_dir / "index.json").write_text('{"manifests": []}')
    res_empty = OciScanner(str(layout_dir)).scan()
    assert "no manifests" in res_empty.error_message

    # index with unsupported digest scheme
    (layout_dir / "index.json").write_text('{"manifests": [{"digest": "md5:1234567890"}]}')
    res_bad_digest = OciScanner(str(layout_dir)).scan()
    assert "Unsupported digest scheme" in res_bad_digest.error_message


def test_cli_scan_single_compose_and_table_output_file(tmp_path: Path) -> None:
    """Test CLI scanning a single Compose file and outputting table format to a file."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services:\n  web:\n    image: nginx:1.25\n    privileged: true\n")
    out_file = tmp_path / "report.txt"

    res = runner.invoke(
        app,
        ["scan", str(compose_file), "--format", "table", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert res.exit_code == 1
    assert out_file.exists()
    assert "Audit Executive Summary" in out_file.read_text(encoding="utf-8")


def test_cli_scan_oci_json_file(tmp_path: Path) -> None:
    """Test CLI scanning an OCI config.json file directly."""
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({"config": {"User": "root"}}))

    res = runner.invoke(app, ["scan", str(cfg_file), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["summary"]["critical"] >= 1


def test_report_error_message_display() -> None:
    """Test table rendering when target has scan error."""
    res = ScanTargetResult(
        target="bad_file.yml",
        target_type=TargetType.COMPOSE,
        findings=[],
        error_message="Corrupted file format",
    )
    report = AuditReport(parameters={}, results=[res])
    rendered = render_table_report(report)
    assert "Corrupted file format" in rendered
