from pathlib import Path

from sc_scanner.graph.pypi_resolver import (
    PyPIClient,
    build_one_level_graph,
    resolve_latest_satisfying,
)
from sc_scanner.models import Dependency, Ecosystem
from tests.fakes import FakeResponse, FakeSession


def _pypi(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.PYPI)


def _client(tmp_path: Path, responses) -> PyPIClient:
    return PyPIClient(
        cache_dir=tmp_path / "pypi-cache", session=FakeSession(responses), backoff_seconds=0
    )


def test_resolve_latest_satisfying_picks_the_max_matching_release(tmp_path):
    project = {
        "info": {"version": "2024.6.2"},
        "releases": {"2017.4.17": [], "2020.12.5": [], "2024.6.2": []},
    }
    client = _client(tmp_path, [FakeResponse(200, project)])

    assert resolve_latest_satisfying(client, "certifi", ">=1.0.0") == "2024.6.2"


def test_resolve_latest_satisfying_uses_current_release_for_empty_specifier(tmp_path):
    project = {"info": {"version": "3.2.1"}, "releases": {"3.2.1": []}}
    client = _client(tmp_path, [FakeResponse(200, project)])

    assert resolve_latest_satisfying(client, "bare-pkg", "") == "3.2.1"


def test_resolve_latest_satisfying_returns_none_when_nothing_matches(tmp_path):
    project = {"info": {"version": "1.0.0"}, "releases": {"1.0.0": []}}
    client = _client(tmp_path, [FakeResponse(200, project)])

    assert resolve_latest_satisfying(client, "totally-unknown-pkg", ">=999.0.0") is None


def test_build_one_level_graph_resolves_transitive_deps_and_skips_extras(tmp_path):
    direct = _pypi("requests", "2.31.0")
    release = {
        "info": {
            "requires_dist": [
                "certifi (>=1.0.0)",
                "bare-pkg",
                "some-optional (>=1.0) ; extra == 'foo'",
                "totally-unknown-pkg (>=999.0.0)",
            ]
        }
    }
    certifi_project = {
        "info": {"version": "2024.6.2"},
        "releases": {"2017.4.17": [], "2024.6.2": []},
    }
    bare_pkg_project = {"info": {"version": "3.2.1"}, "releases": {"3.2.1": []}}
    unknown_project = {"info": {"version": "1.0.0"}, "releases": {"1.0.0": []}}

    responses = [
        FakeResponse(200, release),
        FakeResponse(200, certifi_project),
        FakeResponse(200, bare_pkg_project),
        FakeResponse(200, unknown_project),
    ]
    client = _client(tmp_path, responses)

    graph = build_one_level_graph([direct], client=client)

    children = graph.children_of(direct)
    assert _pypi("certifi", "2024.6.2") in children
    assert _pypi("bare-pkg", "3.2.1") in children
    # the "extra"-gated optional dependency was never even queried
    assert not any(dep.name == "some-optional" for dep in children)
    # the unresolvable one is reported, not silently dropped or fatal
    assert any("totally-unknown-pkg" in note for note in graph.unresolved)


def test_build_one_level_graph_records_unresolved_when_release_metadata_is_unreachable(tmp_path):
    direct = _pypi("some-package", "1.0.0")
    client = PyPIClient(
        cache_dir=tmp_path / "pypi-cache",
        session=FakeSession([FakeResponse(503, reason="Service Unavailable")] * 4),
        max_retries=1,
        backoff_seconds=0,
    )

    graph = build_one_level_graph([direct], client=client)

    assert graph.children_of(direct) == frozenset()
    assert any("some-package" in note for note in graph.unresolved)
