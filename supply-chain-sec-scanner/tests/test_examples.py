"""A cheap regression guard for the README's demo: if this ever breaks,
the one-command demo in examples/vulnerable-npm-app is silently rotting."""

from pathlib import Path

from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.parsers.base import find_manifests, parse_manifest

EXAMPLE_PROJECT = Path(__file__).parent.parent / "examples" / "vulnerable-npm-app"


def test_example_project_manifests_are_discoverable_and_parseable():
    manifests = find_manifests(EXAMPLE_PROJECT)
    assert [m.name for m in manifests] == ["package-lock.json"]

    dependencies = parse_manifest(manifests[0])

    assert set(dependencies) == {
        Dependency(name="lodash", version="4.17.4", ecosystem=Ecosystem.NPM),
        Dependency(name="minimist", version="0.0.8", ecosystem=Ecosystem.NPM),
        Dependency(name="lodahs", version="0.0.1-security", ecosystem=Ecosystem.NPM),
        Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM),
    }
