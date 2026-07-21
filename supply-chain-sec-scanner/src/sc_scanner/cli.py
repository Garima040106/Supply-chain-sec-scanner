"""Typer CLI entrypoint."""

from pathlib import Path

import typer

from sc_scanner.parsers.base import find_manifests
from sc_scanner.pipeline import run_scan
from sc_scanner.report.cli_table import render_cli_table
from sc_scanner.report.html_report import render_html_report

app = typer.Typer(
    name="sc-scan",
    help="Supply-chain security scanner for project dependencies.",
    add_completion=False,
)


@app.callback()
def callback() -> None:
    """Supply-chain security scanner for project dependencies."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="Path to a project directory, or a single manifest/lockfile.",
    ),
    html_path: Path = typer.Option(
        Path("sc-scan-report.html"),
        "--html",
        help="Where to write the standalone HTML report.",
    ),
) -> None:
    """Scan a project's dependencies for known vulnerabilities and
    malicious-package signals, then print a risk table and write an HTML
    report.

    Runs the full pipeline: parses manifests, builds whatever dependency
    graph it can (for introduction-path tracing), matches known CVEs via
    OSV.dev, runs the heuristic checks, and combines both into one score
    per package. This makes real network calls to OSV, PyPI, and the npm
    registry - responses are cached to disk, so re-scanning the same
    project is much faster.
    """
    manifests = find_manifests(path)
    if not manifests:
        typer.echo(f"No supported manifests found under {path}")
        raise typer.Exit(code=1)

    typer.echo(f"Found {len(manifests)} manifest(s): {', '.join(m.name for m in manifests)}\n")

    project_risk = run_scan(path)

    render_cli_table(project_risk)

    html_path.write_text(render_html_report(project_risk))
    typer.echo(f"\nHTML report written to {html_path}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
