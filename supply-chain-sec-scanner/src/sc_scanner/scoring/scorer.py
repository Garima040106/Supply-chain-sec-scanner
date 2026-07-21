"""Combines a package's known-CVE severity with its heuristic signals
into one score, then rolls per-package scores up into a project summary.

Weights (vuln 0.6 / heuristics 0.4): a matched CVE is a confirmed, known
issue; a heuristic signal is, by design and by every signal module's own
documented false-positive discussion, a probabilistic hint that needs a
human look. Weighting CVEs higher reflects that difference in certainty -
a package with no CVEs but a maxed-out heuristic score (a near-perfect
typosquat AND a malicious-looking install script AND brand new) lands at
MEDIUM, not HIGH, on heuristics alone; reaching HIGH from heuristics
requires either corroborating CVE evidence or an even more extreme
combination. That's intentional: heuristics earn a second look, not an
automatic verdict.
"""

from sc_scanner.heuristics.models import Signal
from sc_scanner.heuristics.scorer import combine as combine_heuristic_signals
from sc_scanner.models import Dependency
from sc_scanner.scoring.cvss import worst_severity_score
from sc_scanner.scoring.models import PackageRisk, ProjectRisk
from sc_scanner.vuln.models import Vulnerability

VULN_WEIGHT = 0.6
HEURISTIC_WEIGHT = 0.4


def score_package(
    dependency: Dependency,
    vulnerabilities: tuple[Vulnerability, ...],
    heuristic_signals: list[Signal],
    introduction_path: tuple[Dependency, ...] | None = None,
) -> PackageRisk:
    vuln_score = worst_severity_score(vulnerabilities)
    heuristic_assessment = combine_heuristic_signals(heuristic_signals)
    combined_score = min(vuln_score * VULN_WEIGHT + heuristic_assessment.score * HEURISTIC_WEIGHT, 1.0)

    return PackageRisk(
        dependency=dependency,
        vuln_score=vuln_score,
        vulnerabilities=tuple(vulnerabilities),
        heuristic_assessment=heuristic_assessment,
        combined_score=combined_score,
        introduction_path=introduction_path,
    )


def score_project(packages: list[PackageRisk]) -> ProjectRisk:
    sorted_packages = tuple(sorted(packages, key=lambda p: p.combined_score, reverse=True))

    tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for package in sorted_packages:
        tier_counts[package.tier] += 1

    highest_score = sorted_packages[0].combined_score if sorted_packages else 0.0
    return ProjectRisk(packages=sorted_packages, score=highest_score, tier_counts=tier_counts)
