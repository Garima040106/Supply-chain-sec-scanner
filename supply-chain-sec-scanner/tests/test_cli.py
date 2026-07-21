import shutil
from pathlib import Path

from typer.testing import CliRunner

from sc_scanner.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_reports_dependencies_found_in_a_project_directory(tmp_path):
    for fixture in ("package-lock.json", "requirements.txt", "poetry.lock"):
        shutil.copy(FIXTURES / fixture, tmp_path / fixture)

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "package-lock.json: 4 dependencies" in result.stdout
    assert "requirements.txt: 4 dependencies" in result.stdout
    assert "poetry.lock: 3 dependencies" in result.stdout


def test_scan_exits_nonzero_when_no_manifests_found(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "No supported manifests found" in result.stdout
