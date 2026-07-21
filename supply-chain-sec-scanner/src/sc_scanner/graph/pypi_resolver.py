"""One level of transitive dependency resolution via the PyPI JSON API,
for projects that only have a plain requirements.txt (no lock file).

There's no ground truth here — requirements.txt only pins the *direct*
dependencies; what those pull in transitively depends on a real resolver,
which we don't run. Instead, for each direct (already-pinned) dependency,
we fetch its exact release's requires_dist, and resolve each transitive
name+specifier to "the newest released version satisfying it" — using
`packaging` for PEP 440 version ordering/specifier matching (the same
logic pip itself uses) rather than reimplementing version comparison.
That's an approximation of what a real resolver would pick, not a
guarantee; anything that can't be resolved is recorded in the graph's
`unresolved` list rather than silently dropped or fatal.

Only one level deep: we don't recurse into the resolved transitive
dependencies' own dependencies.
"""

from pathlib import Path
from typing import Any

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sc_scanner.cache import DiskCache
from sc_scanner.graph.models import DependencyGraph
from sc_scanner.http import HttpError, request_json
from sc_scanner.models import Dependency, Ecosystem

API_BASE = "https://pypi.org/pypi"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "sc-scanner" / "pypi"

_TRANSIENT_ERRORS = (HttpError, requests.exceptions.RequestException)


class PyPIClient:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        session: requests.Session | None = None,
    ) -> None:
        self._cache = DiskCache(cache_dir)
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._session = session or requests.Session()

    def get_release(self, name: str, version: str) -> dict[str, Any]:
        """Metadata for one exact release, including requires_dist."""
        return self._cached_get(f"{API_BASE}/{name}/{version}/json")

    def get_project(self, name: str) -> dict[str, Any]:
        """Metadata for a project, including every ever-released version."""
        return self._cached_get(f"{API_BASE}/{name}/json")

    def _cached_get(self, url: str) -> dict[str, Any]:
        cached = self._cache.get(url)
        if cached is not None:
            return cached

        data = request_json(
            self._session,
            "GET",
            url,
            timeout=self._timeout,
            max_retries=self._max_retries,
            backoff_seconds=self._backoff_seconds,
        )
        self._cache.set(url, data)
        return data


def resolve_latest_satisfying(client: PyPIClient, name: str, specifier: str) -> str | None:
    """The newest released version of `name` matching `specifier` (an empty
    specifier means "the project's current latest release"), or None if
    nothing could be resolved."""
    try:
        project = client.get_project(name)
    except _TRANSIENT_ERRORS:
        return None

    if not specifier:
        return project["info"]["version"]

    try:
        spec_set = SpecifierSet(specifier)
    except InvalidSpecifier:
        return None

    candidates = []
    for version_str in project.get("releases", {}):
        try:
            candidates.append(Version(version_str))
        except InvalidVersion:
            continue

    matching = list(spec_set.filter(candidates))
    if not matching:
        return None
    return str(max(matching))


def build_one_level_graph(
    direct_dependencies: list[Dependency], client: PyPIClient | None = None
) -> DependencyGraph:
    client = client or PyPIClient()

    edges: dict[Dependency, set[Dependency]] = {dep: set() for dep in direct_dependencies}
    unresolved: list[str] = []

    for dep in direct_dependencies:
        try:
            release = client.get_release(dep.name, dep.version)
        except _TRANSIENT_ERRORS:
            unresolved.append(f"{dep.name}=={dep.version}: could not fetch release metadata")
            continue

        for requirement_str in release.get("info", {}).get("requires_dist") or []:
            try:
                requirement = Requirement(requirement_str)
            except InvalidRequirement:
                continue

            if requirement.marker is not None and not requirement.marker.evaluate():
                continue  # optional/"extra"-gated or environment-specific requirement

            resolved_version = resolve_latest_satisfying(
                client, requirement.name, str(requirement.specifier)
            )
            if resolved_version is None:
                unresolved.append(
                    f"{requirement.name}: no release satisfies "
                    f"{requirement.specifier or 'any version'}"
                )
                continue

            child = Dependency(name=requirement.name, version=resolved_version, ecosystem=Ecosystem.PYPI)
            edges[dep].add(child)
            edges.setdefault(child, set())

    return DependencyGraph(
        roots=frozenset(direct_dependencies),
        edges={parent: frozenset(children) for parent, children in edges.items()},
        unresolved=tuple(unresolved),
    )
