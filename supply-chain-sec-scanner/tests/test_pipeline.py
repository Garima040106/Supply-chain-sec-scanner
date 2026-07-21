"""Integration tests for the full parse -> graph -> vuln -> heuristics ->
score pipeline, with every network client mocked.

Registry/downloads calls (npm registry, PyPI, pypistats, npm downloads)
default to a 404 via FakeRoutedSession - every heuristic already handles
that gracefully (proven in their own unit tests), so this deliberately
doesn't bother enumerating every possible call. Only OSV is precisely
scripted, since that's what proves vulnerability data actually reaches
the final score.
"""

import shutil
from pathlib import Path

from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.heuristics.metadata import DownloadStatsClient
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.pipeline import _build_graphs, run_scan
from sc_scanner.vuln.client import OSVClient
from tests.fakes import FakeResponse, FakeRoutedSession, FakeSession

FIXTURES = Path(__file__).parent / "fixtures"

CHALK_VULN = {
    "id": "GHSA-xxxx",
    "aliases": ["CVE-2024-0001"],
    "summary": "a bad thing in chalk",
    "severity": [],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "chalk"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "5.3.1"}]}],
        }
    ],
    "database_specific": {"severity": "CRITICAL"},
}


def _npm(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)


def _no_op_clients(tmp_path: Path):
    """Registry/downloads clients that 404 on every call - heuristics
    that need them degrade to "no signal", which is the documented,
    already-unit-tested behavior."""
    routed = FakeRoutedSession({}, default=FakeResponse(404, reason="Not Found"))
    return (
        NpmRegistryClient(cache_dir=tmp_path / "npm-cache", session=routed, backoff_seconds=0),
        PyPIClient(cache_dir=tmp_path / "pypi-cache", session=routed, backoff_seconds=0),
        DownloadStatsClient(cache_dir=tmp_path / "downloads-cache", session=routed, backoff_seconds=0),
    )


def test_run_scan_wires_graph_vuln_and_heuristics_together(tmp_path):
    shutil.copy(FIXTURES / "package-lock.json", tmp_path / "package-lock.json")

    osv_session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "results": [
                        {"vulns": []},  # left-pad
                        {"vulns": [{"id": "GHSA-xxxx"}]},  # chalk
                        {"vulns": []},  # ansi-styles
                        {"vulns": []},  # @babel/core
                    ]
                },
            ),
            FakeResponse(200, CHALK_VULN),
        ]
    )
    vuln_client = OSVClient(cache_dir=tmp_path / "osv-cache", session=osv_session, backoff_seconds=0)
    npm_client, pypi_client, downloads_client = _no_op_clients(tmp_path)

    project_risk = run_scan(
        tmp_path,
        vuln_client=vuln_client,
        npm_client=npm_client,
        pypi_client=pypi_client,
        downloads_client=downloads_client,
    )

    assert len(project_risk.packages) == 4

    by_name = {p.dependency.name: p for p in project_risk.packages}

    chalk = by_name["chalk"]
    assert chalk.vuln_score > 0
    assert chalk.vulnerabilities[0].cve_ids == ("CVE-2024-0001",)
    assert chalk.introduction_path == (_npm("chalk", "5.3.0"),)  # chalk is itself a root

    assert by_name["ansi-styles"].introduction_path == (_npm("chalk", "5.3.0"), _npm("ansi-styles", "6.2.1"))
    assert by_name["left-pad"].introduction_path == (_npm("left-pad", "1.3.0"),)

    # @babel/core is in the lockfile's flat package list but isn't
    # reachable from any root in this fixture's graph - documented, not a bug.
    assert by_name["@babel/core"].introduction_path is None

    # chalk carries a confirmed critical CVE, so it must outrank every
    # heuristic-only or clean package regardless of what else fired.
    assert project_risk.packages[0].dependency.name == "chalk"


def test_run_scan_exits_gracefully_with_no_vulnerabilities_found(tmp_path):
    shutil.copy(FIXTURES / "package-lock.json", tmp_path / "package-lock.json")

    vuln_client = OSVClient(
        cache_dir=tmp_path / "osv-cache",
        session=FakeSession([FakeResponse(200, {"results": [{"vulns": []}] * 4})]),
        backoff_seconds=0,
    )
    npm_client, pypi_client, downloads_client = _no_op_clients(tmp_path)

    project_risk = run_scan(
        tmp_path,
        vuln_client=vuln_client,
        npm_client=npm_client,
        pypi_client=pypi_client,
        downloads_client=downloads_client,
    )

    assert all(p.vuln_score == 0.0 for p in project_risk.packages)


def test_build_graphs_prefers_poetry_lock_over_requirements_txt(tmp_path):
    shutil.copy(FIXTURES / "poetry.lock", tmp_path / "poetry.lock")
    shutil.copy(FIXTURES / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copy(FIXTURES / "requirements.txt", tmp_path / "requirements.txt")

    manifests = [tmp_path / "poetry.lock", tmp_path / "requirements.txt"]
    graphs = _build_graphs(manifests, dependencies=[], pypi_client=PyPIClient())

    # Exactly one graph - poetry.lock's full resolved tree wins over
    # falling back to a best-effort one-level PyPI resolution.
    assert len(graphs) == 1
    requests_dep = Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI)
    assert requests_dep in graphs[0].roots
