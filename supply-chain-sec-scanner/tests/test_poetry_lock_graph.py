from pathlib import Path

from sc_scanner.graph.poetry_lock import build_from_poetry_lock
from sc_scanner.models import Dependency, Ecosystem

FIXTURES = Path(__file__).parent / "fixtures"


def _pypi(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.PYPI)


def test_edges_come_from_package_dependencies_tables():
    graph = build_from_poetry_lock(FIXTURES / "poetry.lock")

    requests_dep = _pypi("requests", "2.31.0")
    certifi_dep = _pypi("certifi", "2024.6.2")
    assert certifi_dep in graph.children_of(requests_dep)


def test_with_pyproject_toml_direct_deps_are_read_accurately():
    graph = build_from_poetry_lock(FIXTURES / "poetry.lock", FIXTURES / "pyproject.toml")

    # certifi is BOTH a direct dependency (declared in pyproject.toml) and a
    # transitive dependency of requests - pyproject.toml is the only place
    # that distinction is recorded, so it must still show up as a root.
    assert graph.roots == {
        _pypi("requests", "2.31.0"),
        _pypi("click", "8.1.7"),
        _pypi("certifi", "2024.6.2"),
    }


def test_without_pyproject_toml_the_heuristic_misses_a_dual_role_dependency():
    graph = build_from_poetry_lock(FIXTURES / "poetry.lock")

    # certifi is depended-upon by requests, so the in-degree-zero heuristic
    # excludes it from roots - the documented blind spot.
    assert graph.roots == {_pypi("requests", "2.31.0"), _pypi("click", "8.1.7")}
    assert _pypi("certifi", "2024.6.2") not in graph.roots


def test_missing_pyproject_toml_path_falls_back_to_heuristic(tmp_path):
    graph = build_from_poetry_lock(
        FIXTURES / "poetry.lock", tmp_path / "does-not-exist-pyproject.toml"
    )

    assert _pypi("certifi", "2024.6.2") not in graph.roots
