from pathlib import Path

from sc_scanner.models import Ecosystem
from sc_scanner.parsers import pip

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_pinned_dependencies():
    dependencies = pip.parse(FIXTURES / "requirements.txt")
    by_name = {dep.name: dep for dep in dependencies}

    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].ecosystem == Ecosystem.PYPI
    assert by_name["flask"].version == "3.0.3"


def test_strips_extras_from_package_name():
    dependencies = pip.parse(FIXTURES / "requirements.txt")
    by_name = {dep.name: dep for dep in dependencies}

    assert "uvicorn" in by_name
    assert by_name["uvicorn"].version == "0.30.1"


def test_strips_environment_markers():
    dependencies = pip.parse(FIXTURES / "requirements.txt")
    by_name = {dep.name: dep for dep in dependencies}

    assert by_name["typing-extensions"].version == "4.12.2"


def test_skips_unpinned_requirements_and_option_lines():
    dependencies = pip.parse(FIXTURES / "requirements.txt")
    names = [dep.name for dep in dependencies]

    assert "click" not in names  # unpinned (>=), version unknown
    assert len(dependencies) == 4
