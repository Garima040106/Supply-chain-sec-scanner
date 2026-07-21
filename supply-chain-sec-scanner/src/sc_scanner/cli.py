"""Typer CLI entrypoint."""

from pathlib import Path

import typer

from sc_scanner.parsers.base import find_manifests, parse_manifest

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
) -> None:
    """Scan a project's dependency manifests.

    Early-stage stub: currently only discovers and parses manifests
    (package-lock.json, requirements.txt, poetry.lock) into a flat
    dependency list. Graph building, vulnerability matching, malicious-
    package heuristics, risk scoring, and report generation are not
    implemented yet.
    """
    manifests = find_manifests(path)
    if not manifests:
        typer.echo(f"No supported manifests found under {path}")
        raise typer.Exit(code=1)

    total = 0
    for manifest in manifests:
        dependencies = parse_manifest(manifest)
        typer.echo(f"{manifest.name}: {len(dependencies)} dependencies")
        for dep in dependencies:
            typer.echo(f"  {dep.ecosystem.value:<5} {dep.name} {dep.version}")
        total += len(dependencies)

    typer.echo(f"\nParsed {total} dependencies from {len(manifests)} manifest(s).")
    typer.echo(
        "(graph building, vulnerability matching, heuristics, scoring, "
        "and reporting: not implemented yet)"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
