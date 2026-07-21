import json
from pathlib import Path

import pytest

from sc_scanner.graph.npm_lock import build_from_package_lock
from sc_scanner.graph.models import shortest_path
from sc_scanner.models import Dependency, Ecosystem

FIXTURES = Path(__file__).parent / "fixtures"


def _npm(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)


def test_roots_are_the_projects_direct_dependencies():
    graph = build_from_package_lock(FIXTURES / "package-lock-graph.json")

    assert graph.roots == {
        _npm("chalk", "5.3.0"),
        _npm("pkg-a", "1.0.0"),
        _npm("pkg-b", "1.0.0"),
    }


def test_resolves_a_dependency_hoisted_to_the_root_node_modules():
    graph = build_from_package_lock(FIXTURES / "package-lock-graph.json")

    chalk = _npm("chalk", "5.3.0")
    ansi_styles = _npm("ansi-styles", "6.2.1")
    assert ansi_styles in graph.children_of(chalk)


def test_version_conflict_produces_two_distinct_nodes_for_the_same_name():
    graph = build_from_package_lock(FIXTURES / "package-lock-graph.json")

    pkg_a, pkg_b = _npm("pkg-a", "1.0.0"), _npm("pkg-b", "1.0.0")
    shared_v1 = _npm("shared-lib", "1.0.0")
    shared_v2 = _npm("shared-lib", "2.0.0")

    assert graph.children_of(pkg_a) == frozenset({shared_v1})
    assert graph.children_of(pkg_b) == frozenset({shared_v2})
    assert shared_v1 in graph.nodes
    assert shared_v2 in graph.nodes


def test_shortest_path_reaches_a_conflicting_version_via_its_own_parent():
    graph = build_from_package_lock(FIXTURES / "package-lock-graph.json")

    pkg_a = _npm("pkg-a", "1.0.0")
    shared_v1 = _npm("shared-lib", "1.0.0")

    assert shortest_path(graph, shared_v1) == [pkg_a, shared_v1]


def test_raises_for_unsupported_lockfile_format(tmp_path):
    bad_lock = tmp_path / "package-lock.json"
    bad_lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))

    with pytest.raises(ValueError):
        build_from_package_lock(bad_lock)
