# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from lh_container_auditor.exporters import (
    export_json,
    export_sarif,
    render_table_report,
)
from lh_container_auditor.models import (
    AuditReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)


def _sample_report() -> AuditReport:
    """Create a sample AuditReport with various finding severities."""
    f1 = Finding(
        rule_id="LH-CONT-001",
        title="Unpinned base image",
        category=FindingCategory.IMAGE_BASE,
        severity=FindingSeverity.HIGH,
        target="Dockerfile",
        line_number=1,
        message="Base image has no tag specified.",
    )
    f2 = Finding(
        rule_id="LH-CONT-002",
        title="Missing non-root USER",
        category=FindingCategory.USER_PRIVILEGE,
        severity=FindingSeverity.CRITICAL,
        target="Dockerfile",
        line_number=5,
        message="Runs as root superuser.",
    )
    f3 = Finding(
        rule_id="LH-CONT-009",
        title="Missing HEALTHCHECK",
        category=FindingCategory.HEALTHCHECK,
        severity=FindingSeverity.LOW,
        target="Dockerfile",
        line_number=1,
        message="No healthcheck configured.",
    )
    res = ScanTargetResult(
        target="Dockerfile",
        target_type=TargetType.DOCKERFILE,
        findings=[f1, f2, f3],
    )
    report = AuditReport(
        report_type="container_audit",
        generated_at=datetime.now(UTC),
        parameters={"format": "table", "min_severity": "LOW"},
        results=[res],
    )
    report.compute_summary()
    return report


def test_export_json() -> None:
    """Test JSON exporter serialization and schema."""
    report = _sample_report()
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "container_audit"
    assert "summary" in data
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert data["summary"]["low"] == 1
    assert len(data["results"]) == 1
    assert len(data["results"][0]["findings"]) == 3


def test_export_sarif() -> None:
    """Test OASIS SARIF v2.1.0 exporter format and compliance."""
    report = _sample_report()
    sarif_str = export_sarif(report)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    tool = run["tool"]["driver"]
    assert tool["name"] == "lh-container-auditor"
    assert len(tool["rules"]) >= 3

    results = run["results"]
    assert len(results) == 3

    levels = {r["level"] for r in results}
    assert "error" in levels
    assert "note" in levels


def test_render_table_report() -> None:
    """Test Rich terminal table rendering."""
    report = _sample_report()
    rendered = render_table_report(report)

    assert "lh-container-auditor" in rendered
    assert "Audit Executive Summary" in rendered
    assert "LH-CONT-001" in rendered
    assert "LH-CONT-002" in rendered
    assert "CRITICAL" in rendered


def test_render_table_clean_report() -> None:
    """Test Rich table rendering when no findings are detected."""
    res = ScanTargetResult(
        target="Dockerfile.clean",
        target_type=TargetType.DOCKERFILE,
        findings=[],
    )
    report = AuditReport(
        report_type="container_audit",
        generated_at=datetime.now(UTC),
        parameters={},
        results=[res],
    )
    rendered = render_table_report(report)
    assert "Clean Audit" in rendered


def test_severity_filter_and_failures() -> None:
    """Test report filtering and failure threshold checks."""
    report = _sample_report()
    assert report.has_failures(FindingSeverity.HIGH) is True
    assert report.has_failures(FindingSeverity.CRITICAL) is True

    # Filter out anything below HIGH
    report.filter_min_severity(FindingSeverity.HIGH)
    findings = report.results[0].findings
    assert len(findings) == 2  # CRITICAL and HIGH remain, LOW removed
    assert not any(f.severity == FindingSeverity.LOW for f in findings)
