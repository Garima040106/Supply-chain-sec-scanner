"""Ties every stage together into one full scan: parse manifests, build
whatever dependency graph(s) we can, match vulnerabilities, run
heuristics, and score everything into one ProjectRisk.

This is the only module that imports across every stage - by design,
each stage stays independent and separately testable (see each stage's
own module docstring for why), and this is where they finally get
composed for a real end-to-end scan. Every network-touching client is
optional and constructed here by default, but can be injected - useful
for tests, and for anyone who wants to point this at a private registry
mirror later.
"""

from pathlib import Path

from sc_scanner.graph.models import DependencyGraph, shortest_path
from sc_scanner.graph.npm_lock import build_from_package_lock
from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.poetry_lock import build_from_poetry_lock
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.graph.pypi_resolver import build_one_level_graph as build_pypi_graph
from sc_scanner.heuristics.install_scripts import check_npm_install_script, check_pypi_install_script
from sc_scanner.heuristics.metadata import (
    DownloadStatsClient,
    check_low_downloads,
    check_maintainer_change_npm,
    check_recent_publish_npm,
    check_recent_publish_pypi,
)
from sc_scanner.heuristics.models import Signal
from sc_scanner.heuristics.typosquat import check_typosquat
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.parsers.base import find_manifests, parse_manifest
from sc_scanner.scoring.models import ProjectRisk
from sc_scanner.scoring.scorer import score_package, score_project
from sc_scanner.vuln.client import OSVClient
from sc_scanner.vuln.matcher import match as match_vulnerabilities


def run_scan(
    project_path: Path,
    *,
    vuln_client: OSVClient | None = None,
    npm_client: NpmRegistryClient | None = None,
    pypi_client: PyPIClient | None = None,
    downloads_client: DownloadStatsClient | None = None,
) -> ProjectRisk:
    vuln_client = vuln_client or OSVClient()
    npm_client = npm_client or NpmRegistryClient()
    pypi_client = pypi_client or PyPIClient()
    downloads_client = downloads_client or DownloadStatsClient()

    manifests = find_manifests(project_path)
    dependencies = _unique_dependencies(manifests)
    graphs = _build_graphs(manifests, dependencies, pypi_client)

    vulnerabilities_by_dependency = {
        result.dependency: result.vulnerabilities
        for result in match_vulnerabilities(dependencies, client=vuln_client)
    }

    package_risks = []
    for dependency in dependencies:
        signals = _run_heuristics(dependency, npm_client, pypi_client, downloads_client)
        introduction_path = _find_introduction_path(graphs, dependency)
        package_risks.append(
            score_package(
                dependency,
                vulnerabilities_by_dependency.get(dependency, ()),
                signals,
                introduction_path=introduction_path,
            )
        )

    return score_project(package_risks)


def _unique_dependencies(manifests: list[Path]) -> list[Dependency]:
    seen: set[Dependency] = set()
    ordered: list[Dependency] = []
    for manifest in manifests:
        for dependency in parse_manifest(manifest):
            if dependency not in seen:
                seen.add(dependency)
                ordered.append(dependency)
    return ordered


def _build_graphs(
    manifests: list[Path], dependencies: list[Dependency], pypi_client: PyPIClient
) -> list[DependencyGraph]:
    manifest_by_name = {manifest.name: manifest for manifest in manifests}
    graphs: list[DependencyGraph] = []

    if "package-lock.json" in manifest_by_name:
        graphs.append(build_from_package_lock(manifest_by_name["package-lock.json"]))

    if "poetry.lock" in manifest_by_name:
        lock_path = manifest_by_name["poetry.lock"]
        pyproject_path = lock_path.parent / "pyproject.toml"
        graphs.append(
            build_from_poetry_lock(lock_path, pyproject_path if pyproject_path.exists() else None)
        )
    elif "requirements.txt" in manifest_by_name:
        pypi_direct = [dep for dep in dependencies if dep.ecosystem == Ecosystem.PYPI]
        if pypi_direct:
            graphs.append(build_pypi_graph(pypi_direct, client=pypi_client))

    return graphs


def _find_introduction_path(
    graphs: list[DependencyGraph], dependency: Dependency
) -> tuple[Dependency, ...] | None:
    for graph in graphs:
        path = shortest_path(graph, dependency)
        if path is not None:
            return tuple(path)
    return None


def _run_heuristics(
    dependency: Dependency,
    npm_client: NpmRegistryClient,
    pypi_client: PyPIClient,
    downloads_client: DownloadStatsClient,
) -> list[Signal]:
    signals: list[Signal] = []

    typosquat_signal = check_typosquat(dependency)
    if typosquat_signal is not None:
        signals.append(typosquat_signal)

    if dependency.ecosystem == Ecosystem.NPM:
        ecosystem_checks = (
            check_npm_install_script(dependency, npm_client),
            check_recent_publish_npm(dependency, npm_client),
            check_maintainer_change_npm(dependency, npm_client),
        )
    else:
        ecosystem_checks = (
            check_pypi_install_script(dependency, pypi_client),
            check_recent_publish_pypi(dependency, pypi_client),
        )

    for signal in ecosystem_checks:
        if signal is not None:
            signals.append(signal)

    downloads_signal = check_low_downloads(dependency, downloads_client)
    if downloads_signal is not None:
        signals.append(downloads_signal)

    return signals
