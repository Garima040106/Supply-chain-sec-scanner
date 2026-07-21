"""Data types for OSV vulnerability matches.

Also holds the ecosystem-name mapping OSV's API expects on requests and
uses in "affected" package entries. It doesn't match our own Ecosystem
enum values (e.g. "pypi" vs OSV's "PyPI"), so client.py and matcher.py
both translate through this table rather than guessing a casing.
"""

from dataclasses import dataclass

from sc_scanner.models import Dependency, Ecosystem

OSV_ECOSYSTEM_NAMES: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
}


@dataclass(frozen=True, slots=True)
class Severity:
    """type is a CVSS version ("CVSS_V2"/"CVSS_V3"/"CVSS_V4") or "UNKNOWN"
    for a qualitative-only rating; score is a CVSS vector string, or for
    UNKNOWN a plain label like "HIGH"."""

    type: str
    score: str


@dataclass(frozen=True, slots=True)
class AffectedRange:
    """One introduced/fixed window for this package, from a single OSV
    range entry. See matcher.py for why multi-window ranges collapse to
    their last introduced/fixed/last_affected values."""

    range_type: str  # "SEMVER", "ECOSYSTEM", or "GIT"
    introduced: str | None
    fixed: str | None
    last_affected: str | None


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severities: tuple[Severity, ...]
    affected_ranges: tuple[AffectedRange, ...]

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """CVE identifiers for this vulnerability, whether it's natively a
        CVE or a GHSA/PYSEC/etc. entry that cross-references one via
        "aliases"."""
        candidates = (self.id, *self.aliases)
        return tuple(dict.fromkeys(c for c in candidates if c.startswith("CVE-")))


@dataclass(frozen=True, slots=True)
class MatchResult:
    dependency: Dependency
    vulnerabilities: tuple[Vulnerability, ...]

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0
