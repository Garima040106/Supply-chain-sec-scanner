"""Builds a DependencyGraph directly from package-lock.json's "packages" map.

npm's lockfile doesn't store edges as ready-made (name, version) pairs —
each entry just says "I depend on name X at range R", the same as
package.json would. Which physical copy that resolves to depends on
Node's own module resolution: look for a node_modules/<name> at this
package's own install path; if absent, walk up one node_modules level at
a time until one is found, ending at the project root. `_resolve` below
replicates exactly that walk against the lock file's own paths. This is
what correctly reproduces version conflicts (two different resolved
copies of the same package name, nested at different paths) as two
distinct graph nodes, rather than guessing a single target by name alone.

Only each package's "dependencies" field is followed (production
dependencies). "devDependencies"/"optionalDependencies"/"peerDependencies"
aren't traversed in this version — a package reachable only through those
simply won't appear connected to a root, which is the desired behavior
for a production dependency tree.
"""

import json
from pathlib import Path

from sc_scanner.graph.models import DependencyGraph
from sc_scanner.models import Dependency, Ecosystem


def build_from_package_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text())
    packages = data.get("packages")
    if packages is None:
        raise ValueError(
            f"{path}: unsupported package-lock.json format "
            "(expected lockfileVersion 2 or 3 with a top-level 'packages' key)"
        )

    dependency_by_path: dict[str, Dependency] = {}
    for package_path, info in packages.items():
        if package_path == "" or info.get("version") is None:
            continue
        dependency_by_path[package_path] = Dependency(
            name=_name_from_path(package_path),
            version=info["version"],
            ecosystem=Ecosystem.NPM,
        )

    edges: dict[Dependency, set[Dependency]] = {dep: set() for dep in dependency_by_path.values()}
    unresolved: list[str] = []

    for package_path, info in packages.items():
        parent = dependency_by_path.get(package_path) if package_path != "" else None
        if package_path != "" and parent is None:
            continue  # e.g. a local workspace "link" entry with no version

        for dep_name in info.get("dependencies", {}):
            target_path = _resolve(dep_name, package_path, dependency_by_path)
            if target_path is None:
                unresolved.append(f"{package_path or '<root>'}: could not resolve {dep_name}")
                continue
            if parent is not None:
                edges[parent].add(dependency_by_path[target_path])

    roots: set[Dependency] = set()
    for name in packages.get("", {}).get("dependencies", {}):
        target_path = _resolve(name, "", dependency_by_path)
        if target_path is not None:
            roots.add(dependency_by_path[target_path])

    return DependencyGraph(
        roots=frozenset(roots),
        edges={parent: frozenset(children) for parent, children in edges.items()},
        unresolved=tuple(unresolved),
    )


def _name_from_path(package_path: str) -> str:
    return package_path.rsplit("node_modules/", 1)[-1]


def _resolve(name: str, from_path: str, dependency_by_path: dict[str, Dependency]) -> str | None:
    """Walk node_modules levels outward from `from_path` looking for
    `name`, the same way Node's own module resolution (and npm's
    hoisting/dedup) does."""
    prefix = from_path
    while True:
        candidate = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        if candidate in dependency_by_path:
            return candidate
        if not prefix:
            return None
        cut = prefix.rfind("node_modules/")
        if cut == -1:
            return None
        prefix = prefix[:cut].rstrip("/")
