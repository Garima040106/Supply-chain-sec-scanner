"""Renders a ProjectRisk as a colored table for the terminal, every
scanned package sorted by combined risk score (highest first) - unlike
the HTML report, this isn't filtered down to just the risky ones, since
a compact terminal table scans fine at full length.
"""

from rich.console import Console
from rich.table import Table

from sc_scanner.scoring.models import ProjectRisk

_TIER_STYLES = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green"}


def render_cli_table(project_risk: ProjectRisk, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Dependency Risk Report")

    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Score", justify="right")
    table.add_column("Tier")
    table.add_column("CVEs")
    table.add_column("Heuristic signals")

    for package in project_risk.packages:
        dep = package.dependency
        cve_ids = sorted({cve for vuln in package.vulnerabilities for cve in vuln.cve_ids})
        signal_summary = (
            ", ".join(signal.type.value for signal in package.heuristic_assessment.signals) or "-"
        )
        style = _TIER_STYLES[package.tier]

        table.add_row(
            f"{dep.name}@{dep.version}",
            dep.ecosystem.value,
            f"{package.combined_score:.2f}",
            f"[{style}]{package.tier}[/{style}]",
            ", ".join(cve_ids) or "-",
            signal_summary,
        )

    console.print(table)

    project_style = _TIER_STYLES[project_risk.tier]
    counts = project_risk.tier_counts
    console.print(
        f"\nProject risk: [{project_style}]{project_risk.tier}[/{project_style}] "
        f"(highest package score {project_risk.score:.2f}) — "
        f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low"
    )
