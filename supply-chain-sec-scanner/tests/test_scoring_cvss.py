import pytest

from sc_scanner.scoring.cvss import normalize_severity, worst_severity_score
from sc_scanner.vuln.models import AffectedRange, Severity, Vulnerability


def _vuln(severities: tuple[Severity, ...], vuln_id: str = "GHSA-xxxx") -> Vulnerability:
    return Vulnerability(id=vuln_id, aliases=(), summary="", severities=severities, affected_ranges=())


def test_normalize_severity_scales_cvss_v3_base_score_to_unit_range():
    severity = Severity(type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    result = normalize_severity(severity)

    assert result == pytest.approx(0.98)  # base score 9.8 / 10


def test_normalize_severity_handles_cvss_v2():
    severity = Severity(type="CVSS_V2", score="AV:N/AC:L/Au:N/C:C/I:C/A:C")

    assert normalize_severity(severity) == 1.0  # base score 10.0 / 10


def test_normalize_severity_handles_cvss_v4():
    severity = Severity(
        type="CVSS_V4",
        score="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )

    result = normalize_severity(severity)

    assert result is not None
    assert 0.0 <= result <= 1.0


def test_normalize_severity_maps_qualitative_labels():
    assert normalize_severity(Severity(type="UNKNOWN", score="CRITICAL")) == 1.0
    assert normalize_severity(Severity(type="UNKNOWN", score="HIGH")) == 0.8
    assert normalize_severity(Severity(type="UNKNOWN", score="LOW")) == 0.2


def test_normalize_severity_returns_none_for_unparseable_vector():
    severity = Severity(type="CVSS_V3", score="not a real vector")

    assert normalize_severity(severity) is None


def test_normalize_severity_returns_none_for_unrecognized_qualitative_label():
    severity = Severity(type="UNKNOWN", score="WHO_KNOWS")

    assert normalize_severity(severity) is None


def test_worst_severity_score_is_zero_with_no_vulnerabilities():
    assert worst_severity_score(()) == 0.0


def test_worst_severity_score_takes_the_max_across_vulnerabilities():
    low = _vuln((Severity(type="UNKNOWN", score="LOW"),), vuln_id="GHSA-low")
    critical = _vuln((Severity(type="UNKNOWN", score="CRITICAL"),), vuln_id="GHSA-critical")

    assert worst_severity_score((low, critical)) == 1.0


def test_worst_severity_score_ignores_unparseable_entries_rather_than_failing():
    vuln = _vuln(
        (
            Severity(type="CVSS_V3", score="garbage"),
            Severity(type="UNKNOWN", score="MODERATE"),
        )
    )

    assert worst_severity_score((vuln,)) == 0.5
