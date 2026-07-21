"""The dependency graph itself, plus shortest-path lookup.

A node is just our existing Dependency (ecosystem, name, version) — node
identity deliberately includes the version. That single choice is what
makes version conflicts free: if two parts of the tree need different
versions of the same package name, that's simply two distinct nodes, each
with their own edges. No separate "conflict" bookkeeping is needed.

Roots (the project's direct dependencies) are tracked as a plain set
rather than represented by a synthetic "project" node — inventing a fake
Dependency for the project itself would need a fake ecosystem/version for
no real benefit.
"""

from collections import deque
from dataclasses import dataclass, field

from sc_scanner.models import Dependency


@dataclass
class DependencyGraph:
    roots: frozenset[Dependency]
    edges: dict[Dependency, frozenset[Dependency]] = field(default_factory=dict)
    # Human-readable notes about anything that couldn't be resolved (e.g. a
    # transitive dependency the registry/PyPI couldn't find a version for).
    # Best-effort resolution degrades gracefully instead of failing silently
    # or crashing the whole scan.
    unresolved: tuple[str, ...] = ()

    @property
    def nodes(self) -> frozenset[Dependency]:
        all_nodes = set(self.roots) | set(self.edges)
        for children in self.edges.values():
            all_nodes |= children
        return frozenset(all_nodes)

    def children_of(self, dependency: Dependency) -> frozenset[Dependency]:
        return self.edges.get(dependency, frozenset())


def shortest_path(graph: DependencyGraph, target: Dependency) -> list[Dependency] | None:
    """The shortest root -> ... -> target path (fewest hops), or None if
    target isn't reachable from any root.

    This is a multi-source BFS: every root is enqueued at distance 0
    simultaneously, so the first time `target` is dequeued, it's via the
    globally shortest path across *all* roots, not just the shortest path
    from whichever root happens to be checked first. A visited set makes
    this safe on graphs with cycles: a node is only ever expanded once.
    """
    if target in graph.roots:
        return [target]

    came_from: dict[Dependency, Dependency] = {}
    visited: set[Dependency] = set(graph.roots)
    queue = deque(sorted(graph.roots, key=lambda d: (d.ecosystem.value, d.name, d.version)))

    while queue:
        current = queue.popleft()
        for child in sorted(graph.children_of(current), key=lambda d: (d.ecosystem.value, d.name, d.version)):
            if child in visited:
                continue
            visited.add(child)
            came_from[child] = current
            if child == target:
                return _reconstruct_path(came_from, graph.roots, target)
            queue.append(child)

    return None


def _reconstruct_path(
    came_from: dict[Dependency, Dependency], roots: frozenset[Dependency], target: Dependency
) -> list[Dependency]:
    path = [target]
    node = target
    while node not in roots:
        node = came_from[node]
        path.append(node)
    path.reverse()
    return path
