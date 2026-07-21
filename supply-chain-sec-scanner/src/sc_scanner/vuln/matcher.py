"""Turns OSV vulnerability IDs into fully-parsed, per-dependency matches.

## OSV's affected-version-range semantics (why matching is thin here)

An OSV vulnerability record lists, per affected package, either explicit
`versions` or `ranges`. Each range has a `type` (SEMVER, ECOSYSTEM, or GIT)
and an ordered `events` list — facts like `{"introduced": "1.0.0"}`,
`{"fixed": "1.2.3"}`, `{"last_affected": "1.2.2"}`. A version is affected
if it falls at/after an `introduced` event and before the next `fixed` (or
at/before a `last_affected`), using version-ordering rules that differ per
ecosystem (semver for npm, PEP 440-ish for PyPI, etc).

Correctly implementing that comparison ourselves — especially pre-release
ordering and PyPI's version scheme — is exactly the kind of thing that
produces silent false negatives. So we don't: `OSVClient.query_batch()`
sends OSV the exact (ecosystem, name, version) and lets its own evaluator
decide what's affected. The parsing below only reads ranges back out of
the matched records, to show *why* something matched (e.g. "fixed in
4.17.21") — never to decide affected-or-not ourselves.

One simplification: a range's events are collapsed into a single
introduced/fixed/last_affected triple, so a record describing multiple
disjoint vulnerable windows in one range will only surface the last one.
That's rare in practice for the ecosystems this scanner targets.
"""

from typing import Any

from sc_scanner.models import Dependency, normalize_pypi_name
from sc_scanner.vuln.client import OSVClient
from sc_scanner.vuln.models import (
    OSV_ECOSYSTEM_NAMES,
    AffectedRange,
    MatchResult,
    Severity,
    Vulnerability,
)


def match(dependencies: list[Dependency], client: OSVClient | None = None) -> list[MatchResult]:
    """Look up every dependency against OSV and return its matched vulnerabilities."""
    client = client or OSVClient()

    vuln_ids_by_dependency = client.query_batch(dependencies)
    unique_ids = {vuln_id for ids in vuln_ids_by_dependency.values() for vuln_id in ids}
    raw_by_id = {vuln_id: client.get_vulnerability(vuln_id) for vuln_id in unique_ids}

    results = []
    for dependency in dependencies:
        vulnerabilities = tuple(
            _parse_vulnerability(raw_by_id[vuln_id], dependency)
            for vuln_id in vuln_ids_by_dependency.get(dependency, [])
        )
        results.append(MatchResult(dependency=dependency, vulnerabilities=vulnerabilities))

    return results


def _parse_vulnerability(raw: dict[str, Any], dependency: Dependency) -> Vulnerability:
    return Vulnerability(
        id=raw["id"],
        aliases=tuple(raw.get("aliases", [])),
        summary=raw.get("summary", ""),
        severities=_parse_severities(raw),
        affected_ranges=_parse_affected_ranges(raw, dependency),
    )


def _parse_severities(raw: dict[str, Any]) -> tuple[Severity, ...]:
    severities = tuple(
        Severity(type=entry["type"], score=entry["score"]) for entry in raw.get("severity", [])
    )
    if severities:
        return severities

    # Many GHSA-sourced advisories skip the CVSS "severity" array entirely
    # and only carry a qualitative rating here instead.
    qualitative = raw.get("database_specific", {}).get("severity")
    if qualitative:
        return (Severity(type="UNKNOWN", score=qualitative),)

    return ()


def _parse_affected_ranges(raw: dict[str, Any], dependency: Dependency) -> tuple[AffectedRange, ...]:
    ecosystem_name = OSV_ECOSYSTEM_NAMES[dependency.ecosystem]
    target_name = normalize_pypi_name(dependency.name)

    ranges: list[AffectedRange] = []
    for affected in raw.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != ecosystem_name:
            continue
        if normalize_pypi_name(package.get("name", "")) != target_name:
            continue

        for range_entry in affected.get("ranges", []):
            events: dict[str, str] = {}
            for event in range_entry.get("events", []):
                events.update(event)

            ranges.append(
                AffectedRange(
                    range_type=range_entry.get("type", "UNKNOWN"),
                    introduced=events.get("introduced"),
                    fixed=events.get("fixed"),
                    last_affected=events.get("last_affected"),
                )
            )

    return tuple(ranges)

