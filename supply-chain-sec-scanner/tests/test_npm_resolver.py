from pathlib import Path

from sc_scanner.graph.npm_resolver import (
    NpmRegistryClient,
    build_one_level_graph,
    parse_package_json,
    resolve_npm_range,
)
from sc_scanner.models import Dependency, Ecosystem
from tests.fakes import FakeResponse, FakeSession

FIXTURES = Path(__file__).parent / "fixtures"


def _npm(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)


def _client(tmp_path: Path, responses) -> NpmRegistryClient:
    return NpmRegistryClient(
        cache_dir=tmp_path / "npm-cache", session=FakeSession(responses), backoff_seconds=0
    )


def test_parse_package_json_reads_only_production_dependencies():
    result = parse_package_json(FIXTURES / "package.json")

    assert result == [("lodash", "^4.17.0"), ("chalk", "~5.3.0")]
    assert not any(name == "eslint" for name, _ in result)


def test_resolve_npm_range_honors_caret_semantics(tmp_path):
    package = {"dist-tags": {"latest": "4.17.21"}, "versions": {"4.17.19": {}, "4.17.21": {}, "5.0.0": {}}}
    client = _client(tmp_path, [FakeResponse(200, package)])

    assert resolve_npm_range(client, "lodash", "^4.17.0") == "4.17.21"


def test_resolve_npm_range_honors_tilde_semantics(tmp_path):
    package = {"dist-tags": {"latest": "5.4.0"}, "versions": {"5.3.0": {}, "5.4.0": {}}}
    client = _client(tmp_path, [FakeResponse(200, package)])

    # ~5.3.0 only allows patch bumps, so 5.4.0 doesn't qualify even though
    # it's "latest".
    assert resolve_npm_range(client, "chalk", "~5.3.0") == "5.3.0"


def test_resolve_npm_range_falls_back_to_latest_for_unparseable_ranges(tmp_path):
    package = {"dist-tags": {"latest": "2.0.0"}, "versions": {"1.0.0": {}, "2.0.0": {}}}
    client = _client(tmp_path, [FakeResponse(200, package)])

    assert resolve_npm_range(client, "some-pkg", "workspace:*") == "2.0.0"


def test_resolve_npm_range_uses_latest_for_wildcard_or_missing_range(tmp_path):
    package = {"dist-tags": {"latest": "3.1.4"}, "versions": {"3.1.4": {}}}
    client = _client(tmp_path, [FakeResponse(200, package)])

    assert resolve_npm_range(client, "some-pkg", "*") == "3.1.4"


def test_build_one_level_graph_resolves_direct_and_one_level_transitive(tmp_path):
    lodash_package = {
        "dist-tags": {"latest": "4.17.21"},
        "versions": {
            "4.17.19": {},
            "4.17.21": {"dependencies": {"tiny-dep": "^1.0.0"}},
            "5.0.0": {},
        },
    }
    tiny_dep_package = {"dist-tags": {"latest": "1.2.0"}, "versions": {"1.0.0": {}, "1.2.0": {}}}
    chalk_package = {
        "dist-tags": {"latest": "5.4.0"},
        "versions": {"5.3.0": {"dependencies": {}}, "5.4.0": {}},
    }

    responses = [
        FakeResponse(200, lodash_package),
        FakeResponse(200, tiny_dep_package),
        FakeResponse(200, chalk_package),
    ]
    client = _client(tmp_path, responses)

    graph = build_one_level_graph(FIXTURES / "package.json", client=client)

    assert _npm("lodash", "4.17.21") in graph.roots
    assert _npm("chalk", "5.3.0") in graph.roots
    assert _npm("tiny-dep", "1.2.0") in graph.children_of(_npm("lodash", "4.17.21"))
    assert graph.children_of(_npm("chalk", "5.3.0")) == frozenset()


def test_build_one_level_graph_records_unresolved_when_registry_is_unreachable(tmp_path):
    client = NpmRegistryClient(
        cache_dir=tmp_path / "npm-cache",
        session=FakeSession([FakeResponse(503, reason="Service Unavailable")] * 4),
        max_retries=1,
        backoff_seconds=0,
    )

    graph = build_one_level_graph(FIXTURES / "package.json", client=client)

    assert graph.roots == frozenset()
    assert len(graph.unresolved) == 2
