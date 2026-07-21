"""Data types for combined (vuln + heuristic) risk: one package's score,
and the project-wide roll-up of every scored package."""

from dataclasses import dataclass

from sc_scanner.heuristics.models import RiskAssessment
from sc_scanner.models import Dependency
from sc_scanner.risk_tier import tier_for_score
from sc_scanner.vuln.models import Vulnerability


@dataclass(frozen=True, slots=True)
class PackageRisk:
    dependency: Dependency
    vuln_score: float
    vulnerabilities: tuple[Vulnerability, ...]
    heuristic_assessment: RiskAssessment
    combined_score: float
    introduction_path: tuple[Dependency, ...] | None = None

    @property
    def tier(self) -> str:
        return tier_for_score(self.combined_score)


@dataclass(frozen=True, slots=True)
class ProjectRisk:
    """packages is sorted by combined_score, descending. score is the
    highest combined_score among them (0.0 if there are none) - "a
    project is only as risky as its riskiest dependency", the standard,
    defensible framing for this kind of report rather than a novel
    aggregate formula."""

    packages: tuple[PackageRisk, ...]
    score: float
    tier_counts: dict[str, int]

    @property
    def tier(self) -> str:
        return tier_for_score(self.score)
