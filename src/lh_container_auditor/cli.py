# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-container-auditor.

Implements CLI commands:
- lh-container scan <path> [--format table|json|sarif] [--output <path>]
                           [--min-severity <level>] [--fail-on <level>]
- lh-container rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_container_auditor.compose_scanner import scan_compose
from lh_container_auditor.dockerfile_scanner import scan_dockerfile
from lh_container_auditor.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_container_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)
from lh_container_auditor.oci_scanner import scan_oci

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-container",
    help=(
        "Enterprise container security auditor for Dockerfile, Compose, and OCI image configs.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _is_compose_file(path: Path) -> bool:
    """Check if file path or contents represent a Docker Compose file."""
    name = path.name.lower()
    if name.endswith((".yml", ".yaml")):
        if "compose" in name:
            return True
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:500]
            if "services:" in content:
                return True
        except (OSError, UnicodeDecodeError):
            return False
    return False


def _is_dockerfile(path: Path) -> bool:
    """Check if file path or contents represent a Dockerfile."""
    name = path.name.lower()
    if "dockerfile" in name:
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")[:300]
        if content.strip().startswith("FROM ") or "\nFROM " in content:
            return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Scan target path (file or recursively in directory)."""
    results: list[ScanTargetResult] = []

    if target_path.is_file():
        if _is_compose_file(target_path):
            results.append(scan_compose(target_path))
        elif _is_dockerfile(target_path):
            results.append(scan_dockerfile(target_path))
        elif target_path.suffix.lower() in (".tar", ".gz") or target_path.suffix.lower() == ".json":
            results.append(scan_oci(target_path))
        else:
            # Fallback heuristic: check if Dockerfile syntax or Compose
            try:
                head = target_path.read_text(encoding="utf-8", errors="ignore")[:400]
                if "services:" in head:
                    results.append(scan_compose(target_path))
                else:
                    results.append(scan_dockerfile(target_path))
            except Exception as e:
                results.append(
                    ScanTargetResult(
                        target=str(target_path),
                        target_type=TargetType.DOCKERFILE,
                        findings=[],
                        error_message=f"Could not read target file: {e}",
                    )
                )
        return results

    # Directory scanning
    found_targets = False

    # Check if directory itself is an OCI layout
    if (target_path / "oci-layout").is_file() or (target_path / "index.json").is_file():
        results.append(scan_oci(target_path))
        found_targets = True

    # Look for Dockerfiles
    dockerfile_patterns = ["Dockerfile*", "*Dockerfile*", "*.dockerfile"]
    dockerfile_paths: set[Path] = set()
    for pat in dockerfile_patterns:
        dockerfile_paths.update(target_path.rglob(pat))

    for df in sorted(dockerfile_paths):
        if df.is_file() and not any(part.startswith(".") for part in df.parts):
            results.append(scan_dockerfile(df))
            found_targets = True

    # Look for Compose files
    compose_patterns = [
        "*compose*.yml",
        "*compose*.yaml",
        "docker-compose*.yml",
        "docker-compose*.yaml",
    ]
    compose_paths: set[Path] = set()
    for pat in compose_patterns:
        compose_paths.update(target_path.rglob(pat))

    for cf in sorted(compose_paths):
        if cf.is_file() and not any(part.startswith(".") for part in cf.parts):
            results.append(scan_compose(cf))
            found_targets = True

    # Look for OCI image archives (.tar)
    for tar_file in sorted(target_path.glob("*.tar")):
        if tar_file.is_file() and not tar_file.name.startswith("."):
            results.append(scan_oci(tar_file))
            found_targets = True

    if not found_targets:
        results.append(
            ScanTargetResult(
                target=str(target_path),
                target_type=TargetType.DOCKERFILE,
                findings=[],
                error_message="No Dockerfile, Compose, or OCI artifacts discovered in directory.",
            )
        )

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination.

    Args:
        report: The AuditReport to export.
        fmt: Desired OutputFormat.
        output_path: Target file path or None for standard output.
    """
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        # Table format
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(
            help="Path to Dockerfile, compose file, OCI directory/tar/json, or directory to scan."
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW, INFO).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan container artifacts for security misconfigurations and compliance violations."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="container_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-CONT security audit detection rules."""
    table = Table(
        title="LH-CONT Container Security Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="cyan")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Targets")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
        FindingSeverity.INFO: "bold blue",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        targets_str = ", ".join(t.value for t in rule_def.target_types)
        table.add_row(
            rule_id,
            badge,
            rule_def.category.value,
            rule_def.title,
            targets_str,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
