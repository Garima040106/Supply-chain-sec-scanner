import shutil
from pathlib import Path

from typer.testing import CliRunner

import sc_scanner.cli as cli_module
from sc_scanner.cli import app
from sc_scanner.heuristics.models import RiskAssessment
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.scoring.models import PackageRisk, ProjectRisk

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _fake_project_risk() -> ProjectRisk:
    # Exercising the CLI's own plumbing (arg parsing, invoking the
    # pipeline, rendering, writing the report) doesn't need a real scan -
    # run_scan's actual behavior is covered by test_pipeline.py. Making
    # real OSV/PyPI/npm calls here would be slow and flaky in CI.
    # A non-LOW tier score so it shows up as a full detail card in the
    # HTML report, not just folded into the LOW-tier summary count.
    dependency = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    package = PackageRisk(
        dependency=dependency,
        vuln_score=0.0,
        vulnerabilities=(),
        heuristic_assessment=RiskAssessment(signals=(), score=1.0),
        combined_score=0.4,
    )
    return ProjectRisk(packages=(package,), score=0.4, tier_counts={"LOW": 0, "MEDIUM": 1, "HIGH": 0})


def test_scan_renders_a_table_and_writes_an_html_report(tmp_path, monkeypatch):
    shutil.copy(FIXTURES / "package-lock.json", tmp_path / "package-lock.json")
    monkeypatch.setattr(cli_module, "run_scan", lambda path: _fake_project_risk())

    html_path = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(tmp_path), "--html", str(html_path)])

    assert result.exit_code == 0
    assert "left-pad" in result.stdout
    assert html_path.exists()
    assert "left-pad" in html_path.read_text()


def test_scan_exits_nonzero_when_no_manifests_found(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "No supported manifests found" in result.stdout
