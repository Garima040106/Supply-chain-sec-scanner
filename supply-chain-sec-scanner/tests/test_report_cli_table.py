import io

from rich.console import Console

from sc_scanner.heuristics.models import RiskAssessment, Signal, SignalType
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.report.cli_table import render_cli_table
from sc_scanner.scoring.models import PackageRisk, ProjectRisk
from sc_scanner.vuln.models import Severity, Vulnerability


def _console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, force_terminal=True, width=120), buffer


def _package(name, score, tier_signals=(), vulnerabilities=()) -> PackageRisk:
    dep = Dependency(name=name, version="1.0.0", ecosystem=Ecosystem.NPM)
    return PackageRisk(
        dependency=dep,
        vuln_score=0.0,
        vulnerabilities=vulnerabilities,
        heuristic_assessment=RiskAssessment(signals=tier_signals, score=0.0),
        combined_score=score,
    )


def test_table_lists_every_package_including_low_tier():
    low = _package("clean-package", 0.0)
    high = _package("risky-package", 0.9)
    project = ProjectRisk(packages=(high, low), score=0.9, tier_counts={"LOW": 1, "MEDIUM": 0, "HIGH": 1})
    console, buffer = _console()

    render_cli_table(project, console=console)

    output = buffer.getvalue()
    assert "clean-package" in output
    assert "risky-package" in output


def test_table_shows_cve_ids():
    vuln = Vulnerability(
        id="GHSA-xxxx",
        aliases=("CVE-2024-0001",),
        summary="",
        severities=(Severity(type="UNKNOWN", score="CRITICAL"),),
        affected_ranges=(),
    )
    package = _package("vulnerable-package", 0.6, vulnerabilities=(vuln,))
    project = ProjectRisk(packages=(package,), score=0.6, tier_counts={"LOW": 0, "MEDIUM": 0, "HIGH": 1})
    console, buffer = _console()

    render_cli_table(project, console=console)

    assert "CVE-2024-0001" in buffer.getvalue()


def test_table_shows_heuristic_signal_types():
    signal = Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="close to 'lodash'")
    package = _package("lodahs", 0.3, tier_signals=(signal,))
    project = ProjectRisk(packages=(package,), score=0.3, tier_counts={"LOW": 0, "MEDIUM": 1, "HIGH": 0})
    console, buffer = _console()

    render_cli_table(project, console=console)

    assert "typosquat" in buffer.getvalue()


def test_prints_project_level_summary_line():
    project = ProjectRisk(packages=(), score=0.0, tier_counts={"LOW": 0, "MEDIUM": 0, "HIGH": 0})
    console, buffer = _console()

    render_cli_table(project, console=console)

    output = buffer.getvalue()
    assert "Project risk" in output
    assert "LOW" in output
