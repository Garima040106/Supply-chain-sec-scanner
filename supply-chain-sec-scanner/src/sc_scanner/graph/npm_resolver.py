"""One level of transitive dependency resolution via the npm registry, for
projects that only have a plain package.json (no lock file).

Same tradeoff as the PyPI resolver: no ground truth, so we resolve each
declared semver range to "the newest published version satisfying it".
Range matching is delegated to `node-semver` (a faithful Python port of
npm's own semver package) rather than hand-rolled — caret/tilde ranges
have real edge cases (e.g. "^0.2.3" behaves differently from "^1.2.3")
that are exactly the kind of thing worth not reimplementing. Anything
`node-semver` can't parse (hyphen ranges, "||" unions, git/tag/workspace
references, ...) falls back to the registry's "latest" dist-tag, which is
noted as an approximation rather than failing outright.

Only "dependencies" from package.json is read (not devDependencies) —
production-tree focused, same scoping as the lockfile-based npm builder.
Only one level deep: we resolve direct dependencies' own declared
dependencies, but don't recurse further.
"""

import json
from pathlib import Path
from typing import Any

import requests
from nodesemver import max_satisfying

from sc_scanner.cache import DiskCache
from sc_scanner.graph.models import DependencyGraph
from sc_scanner.http import HttpError, request_json
from sc_scanner.models import Dependency, Ecosystem

REGISTRY_BASE = "https://registry.npmjs.org"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "sc-scanner" / "npm-registry"

# The abbreviated "corgi" packument npm itself requests during install —
# same data we need (versions, dependencies, dist-tags), far less bandwidth.
_ABBREVIATED_HEADERS = {"Accept": "application/vnd.npm.install-v1+json"}

_TRANSIENT_ERRORS = (HttpError, requests.exceptions.RequestException)


class NpmRegistryClient:
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

    def get_package(self, name: str) -> dict[str, Any]:
        """The full packument: dist-tags, and every version's manifest
        (including its own "dependencies")."""
        url = f"{REGISTRY_BASE}/{name}"
        cached = self._cache.get(url)
        if cached is not None:
            return cached

        data = request_json(
            self._session,
            "GET",
            url,
            headers=_ABBREVIATED_HEADERS,
            timeout=self._timeout,
            max_retries=self._max_retries,
            backoff_seconds=self._backoff_seconds,
        )
        self._cache.set(url, data)
        return data


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """(name, declared range) pairs from package.json's "dependencies"."""
    data = json.loads(path.read_text())
    return list(data.get("dependencies", {}).items())


def resolve_npm_range(client: NpmRegistryClient, name: str, range_spec: str) -> str | None:
    """The newest published version of `name` matching `range_spec`, or
    None if the package itself couldn't be fetched at all."""
    try:
        package = client.get_package(name)
    except _TRANSIENT_ERRORS:
        return None

    latest = package.get("dist-tags", {}).get("latest")
    if not range_spec or range_spec in ("*", "latest"):
        return latest

    versions = list(package.get("versions", {}))
    try:
        resolved = max_satisfying(versions, range_spec)
    except Exception:
        # Range syntax node-semver doesn't parse (hyphen ranges, "||"
        # unions, git/tag/workspace refs, ...) - fall back to latest
        # rather than failing to resolve this dependency at all.
        return latest

    return resolved or latest


def build_one_level_graph(
    package_json_path: Path, client: NpmRegistryClient | None = None
) -> DependencyGraph:
    client = client or NpmRegistryClient()
    direct_ranges = parse_package_json(package_json_path)

    roots: set[Dependency] = set()
    edges: dict[Dependency, set[Dependency]] = {}
    unresolved: list[str] = []

    for name, range_spec in direct_ranges:
        version = resolve_npm_range(client, name, range_spec)
        if version is None:
            unresolved.append(f"{name}@{range_spec}: could not resolve a version from the registry")
            continue

        dep = Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)
        roots.add(dep)
        edges.setdefault(dep, set())

        try:
            package = client.get_package(name)
        except _TRANSIENT_ERRORS:
            continue

        child_ranges = package.get("versions", {}).get(version, {}).get("dependencies") or {}
        for child_name, child_range in child_ranges.items():
            child_version = resolve_npm_range(client, child_name, child_range)
            if child_version is None:
                unresolved.append(
                    f"{child_name}@{child_range}: could not resolve a version from the registry"
                )
                continue
            child = Dependency(name=child_name, version=child_version, ecosystem=Ecosystem.NPM)
            edges[dep].add(child)
            edges.setdefault(child, set())

    return DependencyGraph(
        roots=frozenset(roots),
        edges={parent: frozenset(children) for parent, children in edges.items()},
        unresolved=tuple(unresolved),
    )
