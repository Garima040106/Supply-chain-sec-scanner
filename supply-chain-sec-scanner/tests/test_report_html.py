from datetime import datetime, timezone

from sc_scanner.heuristics.models import RiskAssessment, Signal, SignalType
from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.report.html_report import render_html_report
from sc_scanner.scoring.models import PackageRisk, ProjectRisk
from sc_scanner.vuln.models import Severity, Vulnerability

GENERATED_AT = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)


def _dep(name="risky-package", version="1.0.0") -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.NPM)


def _vuln() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xxxx",
        aliases=("CVE-2024-0001",),
        summary="Remote code execution",
        severities=(Severity(type="UNKNOWN", score="CRITICAL"),),
        affected_ranges=(),
    )


def test_report_is_self_contained_with_no_external_assets():
    project = ProjectRisk(packages=(), score=0.0, tier_counts={"LOW": 0, "MEDIUM": 0, "HIGH": 0})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "<!doctype html>" in html.lower()
    assert "<style>" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "<script" not in html.lower()


def test_high_tier_package_gets_a_full_detail_card():
    package = PackageRisk(
        dependency=_dep(),
        vuln_score=1.0,
        vulnerabilities=(_vuln(),),
        heuristic_assessment=RiskAssessment(signals=(), score=0.0),
        combined_score=0.6,
    )
    project = ProjectRisk(packages=(package,), score=0.6, tier_counts={"LOW": 0, "MEDIUM": 0, "HIGH": 1})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "risky-package" in html
    assert "CVE-2024-0001" in html
    assert "Remote code execution" in html


def test_low_tier_packages_are_summarized_not_individually_shown():
    package = PackageRisk(
        dependency=_dep(name="totally-clean-package"),
        vuln_score=0.0,
        vulnerabilities=(),
        heuristic_assessment=RiskAssessment(signals=(), score=0.0),
        combined_score=0.0,
    )
    project = ProjectRisk(packages=(package,), score=0.0, tier_counts={"LOW": 1, "MEDIUM": 0, "HIGH": 0})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "totally-clean-package" not in html
    assert "1 other package(s) scanned" in html


def test_introduction_path_is_rendered_as_a_chain():
    root = Dependency(name="root-pkg", version="2.0.0", ecosystem=Ecosystem.NPM)
    target = _dep()
    package = PackageRisk(
        dependency=target,
        vuln_score=0.0,
        vulnerabilities=(),
        heuristic_assessment=RiskAssessment(
            signals=(Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="close to 'lodash'"),),
            score=0.35,
        ),
        combined_score=0.3,
        introduction_path=(root, target),
    )
    project = ProjectRisk(packages=(package,), score=0.3, tier_counts={"LOW": 0, "MEDIUM": 1, "HIGH": 0})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "root-pkg@2.0.0" in html
    assert "risky-package@1.0.0" in html
    assert "close to &#x27;lodash&#x27;" in html or "close to 'lodash'" in html


def test_missing_introduction_path_is_reported_honestly():
    package = PackageRisk(
        dependency=_dep(),
        vuln_score=0.0,
        vulnerabilities=(),
        heuristic_assessment=RiskAssessment(
            signals=(Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="e"),), score=0.35
        ),
        combined_score=0.3,
        introduction_path=None,
    )
    project = ProjectRisk(packages=(package,), score=0.3, tier_counts={"LOW": 0, "MEDIUM": 1, "HIGH": 0})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "not available" in html


def test_untrusted_text_is_html_escaped_not_injected():
    # Package names, CVE summaries, and signal evidence all ultimately
    # come from external registries/advisories - this report must not
    # trust them as raw HTML.
    malicious_name = "<script>alert(1)</script>"
    package = PackageRisk(
        dependency=_dep(name=malicious_name),
        vuln_score=0.0,
        vulnerabilities=(),
        heuristic_assessment=RiskAssessment(
            signals=(Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="<img src=x onerror=alert(2)>"),),
            score=0.35,
        ),
        combined_score=0.3,
    )
    project = ProjectRisk(packages=(package,), score=0.3, tier_counts={"LOW": 0, "MEDIUM": 1, "HIGH": 0})

    html = render_html_report(project, generated_at=GENERATED_AT)

    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(2)>" not in html
    assert "&lt;script&gt;" in html
