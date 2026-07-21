from pathlib import Path

from sc_scanner.models import Ecosystem
from sc_scanner.parsers import poetry

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_all_locked_packages():
    dependencies = poetry.parse(FIXTURES / "poetry.lock")

    assert len(dependencies) == 3
    assert all(dep.ecosystem == Ecosystem.PYPI for dep in dependencies)


def test_extracts_name_and_version():
    dependencies = poetry.parse(FIXTURES / "poetry.lock")
    by_name = {dep.name: dep for dep in dependencies}

    assert by_name["requests"].version == "2.31.0"
    assert by_name["certifi"].version == "2024.6.2"
    assert by_name["click"].version == "8.1.7"
