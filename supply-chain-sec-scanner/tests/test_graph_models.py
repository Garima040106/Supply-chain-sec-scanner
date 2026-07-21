from sc_scanner.graph.models import DependencyGraph, shortest_path
from sc_scanner.models import Dependency, Ecosystem


def _dep(name: str, version: str = "1.0.0", ecosystem: Ecosystem = Ecosystem.NPM) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=ecosystem)


def test_root_target_is_a_path_of_length_one():
    root = _dep("a")
    graph = DependencyGraph(roots=frozenset({root}), edges={root: frozenset()})

    assert shortest_path(graph, root) == [root]


def test_finds_a_multi_hop_path():
    a, b, c = _dep("a"), _dep("b"), _dep("c")
    graph = DependencyGraph(
        roots=frozenset({a}),
        edges={a: frozenset({b}), b: frozenset({c}), c: frozenset()},
    )

    assert shortest_path(graph, c) == [a, b, c]


def test_returns_none_for_unreachable_target():
    a, b = _dep("a"), _dep("unreachable")
    graph = DependencyGraph(roots=frozenset({a}), edges={a: frozenset()})

    assert shortest_path(graph, b) is None


def test_picks_the_globally_shortest_path_across_multiple_roots():
    # root1 -> mid -> target (2 hops), root2 -> target directly (1 hop).
    # The direct path should win even though root1 is "checked first" by name.
    root1, root2, mid, target = _dep("root1"), _dep("root2"), _dep("mid"), _dep("target")
    graph = DependencyGraph(
        roots=frozenset({root1, root2}),
        edges={
            root1: frozenset({mid}),
            root2: frozenset({target}),
            mid: frozenset({target}),
            target: frozenset(),
        },
    )

    assert shortest_path(graph, target) == [root2, target]


def test_handles_a_cycle_without_looping_forever():
    a, b = _dep("a"), _dep("b")
    graph = DependencyGraph(roots=frozenset({a}), edges={a: frozenset({b}), b: frozenset({a})})

    assert shortest_path(graph, b) == [a, b]


def test_version_conflict_is_two_distinct_nodes_with_the_same_name():
    root = _dep("root")
    shared_v1 = _dep("shared", "1.0.0")
    shared_v2 = _dep("shared", "2.0.0")
    parent_a, parent_b = _dep("parent-a"), _dep("parent-b")
    graph = DependencyGraph(
        roots=frozenset({root}),
        edges={
            root: frozenset({parent_a, parent_b}),
            parent_a: frozenset({shared_v1}),
            parent_b: frozenset({shared_v2}),
        },
    )

    assert shared_v1 != shared_v2
    assert shortest_path(graph, shared_v1) == [root, parent_a, shared_v1]
    assert shortest_path(graph, shared_v2) == [root, parent_b, shared_v2]
    assert {shared_v1, shared_v2}.issubset(graph.nodes)


def test_nodes_property_includes_roots_and_every_edge_endpoint():
    a, b = _dep("a"), _dep("b")
    graph = DependencyGraph(roots=frozenset({a}), edges={a: frozenset({b})})

    assert graph.nodes == frozenset({a, b})
