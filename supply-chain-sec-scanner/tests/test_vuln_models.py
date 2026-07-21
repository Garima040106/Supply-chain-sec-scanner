from sc_scanner.vuln.models import Vulnerability

_EMPTY = {"summary": "", "severities": (), "affected_ranges": ()}


def test_cve_ids_includes_id_when_it_is_itself_a_cve():
    vuln = Vulnerability(id="CVE-2024-0001", aliases=(), **_EMPTY)
    assert vuln.cve_ids == ("CVE-2024-0001",)


def test_cve_ids_includes_cve_aliases():
    vuln = Vulnerability(id="GHSA-xxxx", aliases=("CVE-2021-23337", "SNYK-JS-1234"), **_EMPTY)
    assert vuln.cve_ids == ("CVE-2021-23337",)


def test_cve_ids_empty_when_no_cve_present():
    vuln = Vulnerability(id="GHSA-xxxx", aliases=("SNYK-JS-1234",), **_EMPTY)
    assert vuln.cve_ids == ()


def test_cve_ids_deduplicates():
    vuln = Vulnerability(id="CVE-2024-0001", aliases=("CVE-2024-0001",), **_EMPTY)
    assert vuln.cve_ids == ("CVE-2024-0001",)
