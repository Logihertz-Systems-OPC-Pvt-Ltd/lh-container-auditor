# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters for audit reports in table, JSON, and SARIF v2.1.0 formats.

Provides terminal presentation via Rich, machine-readable structured JSON,
and OASIS SARIF output for CI/CD and security dashboard integrations.
"""

from __future__ import annotations

import io
import json
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_container_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingSeverity,
)

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


class OutputFormat(StrEnum):
    """Supported output formats for container audit reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF rule level."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    if severity == FindingSeverity.MEDIUM:
        return "warning"
    return "note"


def _get_severity_badge(severity: FindingSeverity) -> Text:
    """Return styled Rich Text badge for finding severity."""
    if severity == FindingSeverity.CRITICAL:
        return Text("CRITICAL", style="bold white on red")
    if severity == FindingSeverity.HIGH:
        return Text("HIGH", style="bold red")
    if severity == FindingSeverity.MEDIUM:
        return Text("MEDIUM", style="bold yellow")
    if severity == FindingSeverity.LOW:
        return Text("LOW", style="bold cyan")
    return Text(severity.value, style="bold")


def render_table_report(report: AuditReport, console: Console | None = None) -> str:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render complete AuditReport to terminal or capture to string.

    Args:
        report: AuditReport instance to render.
        console: Optional Console instance. If None, captures to string.

    Returns:
        Rendered string representation.
    """
    report.compute_summary()
    string_io = io.StringIO()
    target_console = console or Console(file=string_io, color_system="auto", width=120)

    # Header Panel
    title = "lh-container-auditor: Enterprise Container Security Audit"
    subtitle = f"Generated at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    target_console.print(
        Panel(
            Text(f"{title}\n{subtitle}", justify="center", style="bold cyan"),
            border_style="cyan",
        )
    )

    # Summary Table
    summary = report.summary
    summary_table = Table(title="Audit Executive Summary", border_style="blue")
    summary_table.add_column("Targets Analyzed", justify="right")
    summary_table.add_column("Total Findings", justify="right")
    summary_table.add_column("Critical", justify="right")
    summary_table.add_column("High", justify="right")
    summary_table.add_column("Medium", justify="right")
    summary_table.add_column("Low", justify="right")

    crit_style = "bold red" if summary.get("critical", 0) > 0 else "dim"
    high_style = "bold red" if summary.get("high", 0) > 0 else "dim"
    med_style = "bold yellow" if summary.get("medium", 0) > 0 else "dim"
    low_style = "bold cyan" if summary.get("low", 0) > 0 else "dim"

    summary_table.add_row(
        str(summary.get("total_targets", 0)),
        str(summary.get("total_findings", 0)),
        f"[{crit_style}]{summary.get('critical', 0)}[/{crit_style}]",
        f"[{high_style}]{summary.get('high', 0)}[/{high_style}]",
        f"[{med_style}]{summary.get('medium', 0)}[/{med_style}]",
        f"[{low_style}]{summary.get('low', 0)}[/{low_style}]",
    )
    target_console.print(summary_table)

    all_findings: list[Finding] = []
    for res in report.results:
        all_findings.extend(res.findings)

    if not all_findings:
        target_console.print(
            Panel(
                Text(
                    "✔ Clean Audit: No container security violations detected.",
                    justify="center",
                    style="bold green",
                ),
                border_style="green",
            )
        )
    else:
        findings_table = Table(
            title=f"Security Findings ({len(all_findings)})",
            border_style="red"
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0
            else "yellow",
        )
        findings_table.add_column("Target", style="bold white", no_wrap=True)
        findings_table.add_column("Line", justify="right")
        findings_table.add_column("Rule ID", style="bold magenta")
        findings_table.add_column("Severity")
        findings_table.add_column("Finding Message")

        for f in all_findings:
            line_str = str(f.line_number) if f.line_number else "-"
            findings_table.add_row(
                f.target,
                line_str,
                f.rule_id,
                _get_severity_badge(f.severity),
                f.message,
            )
        target_console.print(findings_table)

    # Check for target scan errors
    for res in report.results:
        if res.error_message:
            target_console.print(
                Panel(
                    Text(
                        f"Scan Error on '{res.target}': {res.error_message}",
                        style="bold red",
                    ),
                    border_style="red",
                )
            )

    return string_io.getvalue()


def export_json(report: AuditReport, indent: int = 2) -> str:
    """Export AuditReport as structured JSON string.

    Args:
        report: AuditReport instance.
        indent: JSON indentation spaces.

    Returns:
        Formatted JSON string.
    """
    return json.dumps(report.to_dict(), indent=indent)


def export_sarif(report: AuditReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export AuditReport as OASIS SARIF v2.1.0 document.

    Args:
        report: AuditReport to convert.
        indent: JSON indentation spaces.

    Returns:
        SARIF v2.1.0 JSON string.
    """
    all_findings: list[Finding] = []
    for r in report.results:
        all_findings.extend(r.findings)

    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in all_findings:
        rule_id = finding.rule_id
        if rule_id not in rules_dict:
            rule_def = RULES_REGISTRY.get(rule_id)
            if rule_def:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": rule_def.title.replace(" ", ""),
                    "shortDescription": {"text": rule_def.title},
                    "fullDescription": {"text": rule_def.description},
                    "help": {"text": rule_def.remediation},
                    "defaultConfiguration": {
                        "level": _severity_to_sarif_level(rule_def.severity),
                    },
                }
            else:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "defaultConfiguration": {
                        "level": _severity_to_sarif_level(finding.severity),
                    },
                }

        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.target or "unknown_target",
                    "uriBaseId": "%SRCROOT%",
                }
            }
        }
        if finding.line_number:
            location["physicalLocation"]["region"] = {
                "startLine": finding.line_number,
                "startColumn": 1,
            }

        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _severity_to_sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [location],
                "properties": finding.details,
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-container-auditor",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-container-auditor",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)


__all__ = [
    "OutputFormat",
    "export_json",
    "export_sarif",
    "render_table_report",
]
