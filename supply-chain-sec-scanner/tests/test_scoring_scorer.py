import pytest

from sc_scanner.heuristics.models import Signal, SignalType
from sc_scanner.heuristics.scorer import WEIGHTS as HEURISTIC_SIGNAL_WEIGHTS
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.scoring.scorer import HEURISTIC_WEIGHT, VULN_WEIGHT, score_package, score_project
from sc_scanner.vuln.models import Severity, Vulnerability

DEP = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)


def _every_signal_maxed() -> list[Signal]:
    # A RiskAssessment that itself scores 1.0 requires every signal type
    # at max severity, since heuristics.scorer.combine() weights them -
    # see test_heuristic_scorer.py's equivalent test.
    return [Signal(type=signal_type, score=1.0, evidence="e") for signal_type in HEURISTIC_SIGNAL_WEIGHTS]


def _critical_vuln() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xxxx",
        aliases=("CVE-2024-0001",),
        summary="bad stuff",
        severities=(Severity(type="UNKNOWN", score="CRITICAL"),),
        affected_ranges=(),
    )


def test_weights_sum_to_one():
    assert VULN_WEIGHT + HEURISTIC_WEIGHT == 1.0


def test_clean_package_scores_zero():
    risk = score_package(DEP, (), [])

    assert risk.combined_score == 0.0
    assert risk.tier == "LOW"


def test_a_confirmed_critical_cve_alone_reaches_high_tier():
    risk = score_package(DEP, (_critical_vuln(),), [])

    assert risk.vuln_score == 1.0
    assert risk.combined_score == pytest.approx(VULN_WEIGHT)
    assert risk.tier == "HIGH"


def test_maxed_out_heuristics_alone_do_not_reach_high_tier():
    # By design: heuristics earn a second look, not an automatic verdict -
    # see scorer.py's module docstring for why.
    risk = score_package(DEP, (), _every_signal_maxed())

    assert risk.heuristic_assessment.score == pytest.approx(1.0)
    assert risk.combined_score == pytest.approx(HEURISTIC_WEIGHT)
    assert risk.tier != "HIGH"


def test_cve_plus_heuristics_combine_higher_than_either_alone():
    signals = [Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="e")]

    cve_only = score_package(DEP, (_critical_vuln(),), [])
    combined = score_package(DEP, (_critical_vuln(),), signals)

    assert combined.combined_score > cve_only.combined_score


def test_combined_score_never_exceeds_one():
    risk = score_package(DEP, (_critical_vuln(),), _every_signal_maxed())

    assert risk.combined_score == pytest.approx(1.0)


def test_introduction_path_is_carried_through_untouched():
    root = Dependency(name="root-thing", version="1.0.0", ecosystem=Ecosystem.NPM)
    path = (root, DEP)

    risk = score_package(DEP, (), [], introduction_path=path)

    assert risk.introduction_path == path


def test_score_project_sorts_by_combined_score_descending():
    dep_a = Dependency(name="a", version="1.0.0", ecosystem=Ecosystem.NPM)
    dep_b = Dependency(name="b", version="1.0.0", ecosystem=Ecosystem.NPM)

    low = score_package(dep_a, (), [])
    high = score_package(dep_b, (_critical_vuln(),), [])

    project = score_project([low, high])

    assert project.packages == (high, low)
    assert project.score == high.combined_score


def test_score_project_counts_packages_per_tier():
    clean = score_package(Dependency(name="clean", version="1.0.0", ecosystem=Ecosystem.NPM), (), [])
    risky = score_package(
        Dependency(name="risky", version="1.0.0", ecosystem=Ecosystem.NPM), (_critical_vuln(),), []
    )

    project = score_project([clean, risky])

    assert project.tier_counts == {"LOW": 1, "MEDIUM": 0, "HIGH": 1}


def test_score_project_with_no_packages_scores_zero():
    project = score_project([])

    assert project.score == 0.0
    assert project.packages == ()
    assert project.tier_counts == {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
