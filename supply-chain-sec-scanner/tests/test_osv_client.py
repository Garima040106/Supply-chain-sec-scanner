from pathlib import Path

import pytest
import requests

from sc_scanner.models import Dependency, Ecosystem
from sc_scanner.vuln.client import OSVClient, OSVClientError
from tests.fakes import FakeResponse, FakeSession


def _client(tmp_path: Path, responses, max_retries: int = 2) -> OSVClient:
    return OSVClient(
        cache_dir=tmp_path / "osv-cache",
        session=FakeSession(responses),
        max_retries=max_retries,
        backoff_seconds=0,
        timeout=1.0,
    )


def test_query_batch_returns_vuln_ids_per_dependency(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-xxxx", "modified": "2024-01-01"}]}]}),
    ]
    client = _client(tmp_path, responses)

    result = client.query_batch([dep])

    assert result[dep] == ["GHSA-xxxx"]


def test_query_batch_handles_dependency_with_no_vulnerabilities(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [FakeResponse(200, {"results": [{"vulns": []}]})]
    client = _client(tmp_path, responses)

    result = client.query_batch([dep])

    assert result[dep] == []


def test_query_batch_caches_results_to_disk(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    session = FakeSession([FakeResponse(200, {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]})])
    client = OSVClient(cache_dir=tmp_path / "osv-cache", session=session, backoff_seconds=0)

    first = client.query_batch([dep])
    second = client.query_batch([dep])  # should be served from disk, not the now-empty fake session

    assert first == second == {dep: ["GHSA-xxxx"]}
    assert len(session.calls) == 1


def test_query_batch_cache_persists_across_client_instances(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    cache_dir = tmp_path / "osv-cache"
    session = FakeSession([FakeResponse(200, {"results": [{"vulns": []}]})])
    OSVClient(cache_dir=cache_dir, session=session, backoff_seconds=0).query_batch([dep])

    second_client = OSVClient(cache_dir=cache_dir, session=FakeSession([]), backoff_seconds=0)
    result = second_client.query_batch([dep])

    assert result[dep] == []


def test_get_vulnerability_returns_and_caches_full_record(tmp_path):
    record = {"id": "GHSA-xxxx", "summary": "test vuln"}
    session = FakeSession([FakeResponse(200, record)])
    client = OSVClient(cache_dir=tmp_path / "osv-cache", session=session, backoff_seconds=0)

    first = client.get_vulnerability("GHSA-xxxx")
    second = client.get_vulnerability("GHSA-xxxx")

    assert first == second == record
    assert len(session.calls) == 1


def test_retries_on_429_then_succeeds(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(429, headers={"Retry-After": "0"}, reason="Too Many Requests"),
        FakeResponse(200, {"results": [{"vulns": []}]}),
    ]
    client = _client(tmp_path, responses)

    result = client.query_batch([dep])

    assert result[dep] == []


def test_retries_on_timeout_then_succeeds(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [
        requests.exceptions.Timeout("timed out"),
        FakeResponse(200, {"results": [{"vulns": []}]}),
    ]
    client = _client(tmp_path, responses)

    result = client.query_batch([dep])

    assert result[dep] == []


def test_retries_on_server_error_then_succeeds(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(503, reason="Service Unavailable"),
        FakeResponse(200, {"results": [{"vulns": []}]}),
    ]
    client = _client(tmp_path, responses)

    result = client.query_batch([dep])

    assert result[dep] == []


def test_raises_osv_client_error_after_exhausting_retries(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    responses = [
        FakeResponse(503, reason="Service Unavailable"),
        FakeResponse(503, reason="Service Unavailable"),
        FakeResponse(503, reason="Service Unavailable"),
    ]
    client = _client(tmp_path, responses, max_retries=2)

    with pytest.raises(OSVClientError):
        client.query_batch([dep])


def test_does_not_retry_non_retryable_status_codes(tmp_path):
    dep = Dependency(name="left-pad", version="1.3.0", ecosystem=Ecosystem.NPM)
    session = FakeSession([FakeResponse(400, reason="Bad Request")])
    client = OSVClient(
        cache_dir=tmp_path / "osv-cache", session=session, max_retries=3, backoff_seconds=0
    )

    with pytest.raises(requests.exceptions.HTTPError):
        client.query_batch([dep])

    assert len(session.calls) == 1
