from pathlib import Path

from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.vuln.client import OSVClient
from sc_scanner.vuln.matcher import match
from sc_scanner.vuln.models import Severity
from tests.fakes import FakeResponse, FakeSession

LODASH_VULN = {
    "id": "GHSA-jf85-cpcp-j695",
    "aliases": ["CVE-2021-23337"],
    "summary": "Command Injection in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
}


def _client(tmp_path: Path, responses) -> OSVClient:
    return OSVClient(cache_dir=tmp_path / "osv-cache", session=FakeSession(responses), backoff_seconds=0)


def test_match_attaches_cve_ids_severity_and_ranges(tmp_path):
    dep = Dependency(name="lodash", version="4.17.15", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]}]}),
        FakeResponse(200, LODASH_VULN),
    ]
    client = _client(tmp_path, responses)

    [result] = match([dep], client=client)

    assert result.dependency == dep
    assert result.is_vulnerable
    [vuln] = result.vulnerabilities
    assert vuln.cve_ids == ("CVE-2021-23337",)
    assert vuln.severities[0].score.startswith("CVSS:3.1")
    assert vuln.affected_ranges[0].introduced == "0"
    assert vuln.affected_ranges[0].fixed == "4.17.21"


def test_match_returns_empty_vulnerabilities_for_a_clean_dependency(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [FakeResponse(200, {"results": [{"vulns": []}]})]
    client = _client(tmp_path, responses)

    [result] = match([dep], client=client)

    assert not result.is_vulnerable
    assert result.vulnerabilities == ()


def test_match_falls_back_to_qualitative_severity(tmp_path):
    dep = Dependency(name="pkg", version="1.0.0", ecosystem=Ecosystem.PYPI)
    raw = {
        "id": "GHSA-aaaa",
        "aliases": [],
        "summary": "some issue",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
            }
        ],
        "database_specific": {"severity": "HIGH"},
    }
    responses = [
        FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-aaaa"}]}]}),
        FakeResponse(200, raw),
    ]
    client = _client(tmp_path, responses)

    [result] = match([dep], client=client)

    assert result.vulnerabilities[0].severities == (Severity(type="UNKNOWN", score="HIGH"),)


def test_match_normalizes_pypi_name_case_and_separators(tmp_path):
    dep = Dependency(name="Typing_Extensions", version="4.12.2", ecosystem=Ecosystem.PYPI)
    raw = {
        "id": "PYSEC-0000",
        "aliases": [],
        "summary": "example",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "typing-extensions"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.12.3"}]}],
            }
        ],
    }
    responses = [
        FakeResponse(200, {"results": [{"vulns": [{"id": "PYSEC-0000"}]}]}),
        FakeResponse(200, raw),
    ]
    client = _client(tmp_path, responses)

    [result] = match([dep], client=client)

    assert len(result.vulnerabilities[0].affected_ranges) == 1


def test_match_ignores_affected_entries_for_other_ecosystems_or_packages(tmp_path):
    dep = Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI)
    raw = {
        "id": "GHSA-bbbb",
        "aliases": [],
        "summary": "unrelated in another ecosystem",
        "affected": [
            {"package": {"ecosystem": "npm", "name": "requests"}, "ranges": []},
            {"package": {"ecosystem": "PyPI", "name": "some-other-package"}, "ranges": []},
        ],
    }
    responses = [
        FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-bbbb"}]}]}),
        FakeResponse(200, raw),
    ]
    client = _client(tmp_path, responses)

    [result] = match([dep], client=client)

    assert result.vulnerabilities[0].affected_ranges == ()


def test_match_deduplicates_vulnerability_lookups_across_dependencies(tmp_path):
    dep_a = Dependency(name="lodash", version="4.17.15", ecosystem=Ecosystem.NPM)
    dep_b = Dependency(name="lodash", version="4.17.10", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(
            200,
            {
                "results": [
                    {"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]},
                    {"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]},
                ]
            },
        ),
        FakeResponse(200, LODASH_VULN),  # only one call expected for the shared vuln id
    ]
    client = _client(tmp_path, responses)

    results = match([dep_a, dep_b], client=client)

    assert all(r.is_vulnerable for r in results)
