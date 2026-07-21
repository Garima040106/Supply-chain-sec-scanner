"""Builds a DependencyGraph from poetry.lock (+ optionally pyproject.toml).

Unlike npm, Poetry's resolver produces exactly one locked version per
package name for the whole lock file — there's no per-consumer nested
copy, so there's no version-conflict bookkeeping to do here: an edge from
package A to a dependency named "x" is just "the one poetry.lock entry
named x" (matched by PEP 503 normalized name), no range-walking required.
If this scenario *could* happen, Poetry's own resolver would have failed
to produce a lock file at all.

The one thing poetry.lock genuinely doesn't record is which packages are
the project's direct dependencies — that lives in pyproject.toml's
[tool.poetry.dependencies] (or the newer PEP 621 [project.dependencies]),
not in the lock file. If pyproject_path is given, we read the real root
set from there. Otherwise we fall back to a heuristic: any locked package
that nothing else in the lock depends on must be a root. That heuristic
has a real blind spot — a package that's both a direct dependency *and* a
transitive dependency of something else (e.g. the project pins "certifi"
itself, and "requests" also needs it) looks purely transitive and gets
missed. Parsing pyproject.toml avoids that; the heuristic is only a
fallback for when it isn't available.
"""

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from sc_scanner.graph.models import DependencyGraph
from sc_scanner.models import Dependency, Ecosystem, normalize_pypi_name


def build_from_poetry_lock(lock_path: Path, pyproject_path: Path | None = None) -> DependencyGraph:
    data = tomllib.loads(lock_path.read_text())
    packages = data.get("package", [])

    dependency_by_name: dict[str, Dependency] = {}
    dep_names_by_name: dict[str, set[str]] = {}
    for package in packages:
        normalized = normalize_pypi_name(package["name"])
        dependency_by_name[normalized] = Dependency(
            name=package["name"], version=package["version"], ecosystem=Ecosystem.PYPI
        )
        dep_names_by_name[normalized] = set(package.get("dependencies", {}).keys())

    edges: dict[Dependency, set[Dependency]] = {dep: set() for dep in dependency_by_name.values()}
    unresolved: list[str] = []

    for normalized, dep_names in dep_names_by_name.items():
        parent = dependency_by_name[normalized]
        for dep_name in dep_names:
            target = dependency_by_name.get(normalize_pypi_name(dep_name))
            if target is None:
                unresolved.append(f"{parent.name}: dependency {dep_name!r} not found in poetry.lock")
                continue
            edges[parent].add(target)

    if pyproject_path is not None and pyproject_path.exists():
        root_names = _direct_dependency_names(pyproject_path)
        roots = {
            dependency_by_name[normalize_pypi_name(name)]
            for name in root_names
            if normalize_pypi_name(name) in dependency_by_name
        }
    else:
        depended_upon = {child for children in edges.values() for child in children}
        roots = {dep for dep in dependency_by_name.values() if dep not in depended_upon}

    return DependencyGraph(
        roots=frozenset(roots),
        edges={parent: frozenset(children) for parent, children in edges.items()},
        unresolved=tuple(unresolved),
    )


def _direct_dependency_names(pyproject_path: Path) -> set[str]:
    data = tomllib.loads(pyproject_path.read_text())

    names = set(data.get("tool", {}).get("poetry", {}).get("dependencies", {}))
    names.discard("python")  # a version constraint on the interpreter itself, not a package

    for requirement_str in data.get("project", {}).get("dependencies", []):
        try:
            names.add(Requirement(requirement_str).name)
        except InvalidRequirement:
            continue

    return names
