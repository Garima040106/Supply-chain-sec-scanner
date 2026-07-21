from pathlib import Path

from sc_scanner.models import Ecosystem
from sc_scanner.parsers import npm

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_top_level_packages():
    dependencies = npm.parse(FIXTURES / "package-lock.json")
    by_name = {dep.name: dep for dep in dependencies}

    assert by_name["left-pad"].version == "1.3.0"
    assert by_name["left-pad"].ecosystem == Ecosystem.NPM
    assert by_name["chalk"].version == "5.3.0"


def test_resolves_nested_node_modules_to_bare_package_name():
    dependencies = npm.parse(FIXTURES / "package-lock.json")
    by_name = {dep.name: dep for dep in dependencies}

    assert "ansi-styles" in by_name
    assert by_name["ansi-styles"].version == "6.2.1"


def test_handles_scoped_packages():
    dependencies = npm.parse(FIXTURES / "package-lock.json")
    by_name = {dep.name: dep for dep in dependencies}

    assert by_name["@babel/core"].version == "7.24.0"


def test_excludes_the_root_project_entry():
    dependencies = npm.parse(FIXTURES / "package-lock.json")
    names = [dep.name for dep in dependencies]

    assert "example-app" not in names
    assert len(dependencies) == 4
