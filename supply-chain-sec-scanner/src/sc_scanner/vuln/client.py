"""HTTP client for the OSV.dev vulnerability database API.

Two endpoints are used:

- POST /v1/querybatch — given a list of (ecosystem, name, version) tuples,
  returns, for each one, just the IDs of any vulnerabilities OSV considers
  it affected by. OSV does the affected-version-range evaluation for us;
  see matcher.py for why we don't reimplement that ourselves.
- GET /v1/vulns/{id} — the full vulnerability record for one ID (aliases,
  severity, affected ranges, ...). Called once per unique ID returned by
  the batch query.

Every response is cached to disk (see cache.py) so re-scanning the same
project doesn't re-hit the network for packages already looked up.

Note: querybatch paginates (via a "next_page_token") when a single query
matches 1000+ vulnerabilities. That's not handled here — it would only
happen for a package with an implausibly large number of advisories, and
handling it would mean re-querying per affected dependency. Results are
simply whatever fit in the first page.
"""

from pathlib import Path
from typing import Any

import requests

from sc_scanner.cache import DiskCache
from sc_scanner.http import HttpError, request_json
from sc_scanner.models import Dependency
from sc_scanner.vuln.models import OSV_ECOSYSTEM_NAMES

API_BASE = "https://api.osv.dev/v1"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "sc-scanner" / "osv"

_BATCH_CHUNK_SIZE = 1000


class OSVClientError(Exception):
    """Raised when the OSV API can't be reached after retries are exhausted."""


class OSVClient:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        session: requests.Session | None = None,
    ) -> None:
        self._cache = DiskCache(cache_dir)
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._session = session or requests.Session()

    def query_batch(self, dependencies: list[Dependency]) -> dict[Dependency, list[str]]:
        """Return the OSV vulnerability IDs affecting each dependency."""
        results: dict[Dependency, list[str]] = {}
        uncached: list[Dependency] = []

        for dep in dependencies:
            cached = self._cache.get(_query_cache_key(dep))
            if cached is None:
                uncached.append(dep)
            else:
                results[dep] = cached

        for chunk in _chunked(uncached, _BATCH_CHUNK_SIZE):
            body = {"queries": [_to_osv_query(dep) for dep in chunk]}
            response = self._request_json("POST", f"{API_BASE}/querybatch", body)

            for dep, result in zip(chunk, response["results"]):
                vuln_ids = [vuln["id"] for vuln in result.get("vulns", [])]
                results[dep] = vuln_ids
                self._cache.set(_query_cache_key(dep), vuln_ids)

        return results

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """Return the full OSV vulnerability record for one ID."""
        cache_key = f"vuln:{vuln_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        data = self._request_json("GET", f"{API_BASE}/vulns/{vuln_id}", None)
        self._cache.set(cache_key, data)
        return data

    def _request_json(self, method: str, url: str, json_body: dict | None) -> dict[str, Any]:
        try:
            return request_json(
                self._session,
                method,
                url,
                json_body=json_body,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._backoff_seconds,
            )
        except HttpError as exc:
            raise OSVClientError(str(exc)) from exc


def _to_osv_query(dependency: Dependency) -> dict[str, Any]:
    return {
        "version": dependency.version,
        "package": {
            "name": dependency.name,
            "ecosystem": OSV_ECOSYSTEM_NAMES[dependency.ecosystem],
        },
    }


def _query_cache_key(dependency: Dependency) -> str:
    return f"query:{dependency.ecosystem.value}:{dependency.name}:{dependency.version}"


def _chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
