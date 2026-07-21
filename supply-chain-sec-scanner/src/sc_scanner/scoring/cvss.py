"""Normalizes OSV severity entries (CVSS vectors or qualitative labels)
to a single 0.0-1.0 score, so known-CVE severity is comparable to
heuristic signal scores on the same scale.

CVSS base-score computation is delegated to the `cvss` library rather
than reimplemented - the v2/v3/v4 formulas have enough edge cases
(scope-changed impact sub-formulas, version-specific rounding rules) that
hand-rolling them risks silently wrong scores. Same reasoning as
delegating PEP 440/semver range matching elsewhere in this project.
"""

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from sc_scanner.vuln.models import Severity, Vulnerability

_CVSS_PARSERS = {
    "CVSS_V2": CVSS2,
    "CVSS_V3": CVSS3,
    "CVSS_V4": CVSS4,
}

# Approximate CVSS-equivalent bands for qualitative-only ratings (no CVSS
# vector available - common for GHSA-sourced advisories that only carry
# database_specific.severity; see vuln/matcher.py).
_QUALITATIVE_SCORES = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MODERATE": 0.5,
    "MEDIUM": 0.5,
    "LOW": 0.2,
}


def normalize_severity(severity: Severity) -> float | None:
    """This severity entry's score, scaled to 0.0-1.0, or None if it
    can't be interpreted (unrecognized type, unparseable vector, or an
    unrecognized qualitative label)."""
    if severity.type == "UNKNOWN":
        return _QUALITATIVE_SCORES.get(severity.score.upper())

    parser = _CVSS_PARSERS.get(severity.type)
    if parser is None:
        return None

    try:
        # base_score is a decimal.Decimal, not a float - cast explicitly
        # rather than let a Decimal/float mix raise downstream.
        return float(parser(severity.score).base_score) / 10.0
    except CVSSError:
        return None


def worst_severity_score(vulnerabilities: tuple[Vulnerability, ...]) -> float:
    """The highest normalized severity across every severity entry of
    every given vulnerability, or 0.0 if none could be scored - including
    when there are no vulnerabilities at all."""
    scores = [
        normalized
        for vuln in vulnerabilities
        for severity in vuln.severities
        if (normalized := normalize_severity(severity)) is not None
    ]
    return max(scores, default=0.0)
