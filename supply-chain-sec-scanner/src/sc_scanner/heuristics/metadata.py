"""Anomalous registry metadata: how new is this package, how little is it
used, and (npm only) did a new, unrecognized account just publish it?

False-positive risk - recent publish: a brand-new *version* of a
decade-old trusted package is completely normal (patch releases happen
constantly, including same-day CVE fixes). The meaningful signal is the
*package's* age since its first-ever release, not this version's age -
using version age instead would flag most actively-maintained
dependencies after a routine release. Package age alone is still weak:
legitimate new packages are published constantly by trustworthy authors.

False-positive risk - low downloads: the majority of legitimate,
safe packages have low download counts - obscurity is the norm for the
long tail of any package ecosystem, not the exception. Taken alone this
would flag most dependencies, so it's the lowest-weighted signal, and
it's correlated with (not independent of) "recently published" - a
brand-new legitimate package always starts near zero downloads. Both
registry APIs used here (npmjs.org, pypistats.org) can also simply have
no data for a very new/obscure package; that's treated as "unknown", not
"confirmed low", to avoid mistaking absence of data for evidence.

False-positive risk - maintainer change (npm only; PyPI's JSON API
doesn't expose per-release uploader identity, so this signal doesn't
exist for PyPI): maintainer handoffs are a routine, healthy part of open
source - an inactive author transferring to a trusted maintainer, an org
adopting an abandoned package, or a project migrating to CI/OIDC "trusted
publishing" (which changes the publishing identity for good reasons) all
look identical, from registry metadata alone, to the actual attack
pattern this is meant to catch (a stranger added as co-maintainer quietly
shipping a compromised release). Trusted-publisher (OIDC CI) accounts are
explicitly excluded since npm's registry marks them; beyond that, this
stays a low-confidence "worth checking who published this and why"
signal, not an accusation.
"""

from datetime import datetime, timezone
from pathlib import Path

import requests

from sc_scanner.cache import DiskCache
from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.heuristics.models import Signal, SignalType
from sc_scanner.http import HttpError, request_json
from sc_scanner.models import Dependency, Ecosystem

DEFAULT_DOWNLOAD_STATS_CACHE_DIR = Path.home() / ".cache" / "sc-scanner" / "download-stats"

NPM_DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-month"
PYPISTATS_BASE = "https://pypistats.org/api/packages"

_TRANSIENT_ERRORS = (HttpError, requests.exceptions.RequestException)

# (age_days threshold, score) - first matching (age < threshold) wins.
_AGE_SCORES = ((7, 1.0), (30, 0.6), (90, 0.3))
# (monthly downloads threshold, score) - first matching (downloads < threshold) wins.
_DOWNLOAD_SCORES = ((100, 1.0), (1_000, 0.6), (10_000, 0.3))


def check_recent_publish_npm(
    dependency: Dependency, client: NpmRegistryClient, now: datetime | None = None
) -> Signal | None:
    try:
        package = client.get_full_package(dependency.name)
    except _TRANSIENT_ERRORS:
        return None

    created = package.get("time", {}).get("created")
    if not created:
        return None

    return _score_age(_age_in_days(created, now))


def check_recent_publish_pypi(
    dependency: Dependency, client: PyPIClient, now: datetime | None = None
) -> Signal | None:
    try:
        project = client.get_project(dependency.name)
    except _TRANSIENT_ERRORS:
        return None

    upload_times = [
        file_info["upload_time_iso_8601"]
        for files in project.get("releases", {}).values()
        for file_info in files
        if "upload_time_iso_8601" in file_info
    ]
    if not upload_times:
        return None

    return _score_age(_age_in_days(min(upload_times), now))


def _score_age(age_days: int) -> Signal | None:
    for threshold, score in _AGE_SCORES:
        if age_days < threshold:
            return Signal(
                type=SignalType.RECENT_PUBLISH,
                score=score,
                evidence=f"package was first published {age_days} day(s) ago",
            )
    return None


def _age_in_days(iso_timestamp: str, now: datetime | None) -> int:
    now = now or datetime.now(timezone.utc)
    published = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    return (now - published).days


class DownloadStatsClient:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_DOWNLOAD_STATS_CACHE_DIR,
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

    def npm_monthly_downloads(self, name: str) -> int | None:
        data = self._get(f"{NPM_DOWNLOADS_BASE}/{name}")
        return None if data is None else data.get("downloads")

    def pypi_monthly_downloads(self, name: str) -> int | None:
        data = self._get(f"{PYPISTATS_BASE}/{name}/recent")
        return None if data is None else data.get("data", {}).get("last_month")

    def _get(self, url: str) -> dict | None:
        cached = self._cache.get(url)
        if cached is not None:
            return cached

        try:
            data = request_json(
                self._session,
                "GET",
                url,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._backoff_seconds,
            )
        except _TRANSIENT_ERRORS:
            return None

        self._cache.set(url, data)
        return data


def check_low_downloads(dependency: Dependency, client: DownloadStatsClient) -> Signal | None:
    downloads = (
        client.npm_monthly_downloads(dependency.name)
        if dependency.ecosystem == Ecosystem.NPM
        else client.pypi_monthly_downloads(dependency.name)
    )
    if downloads is None:
        return None  # no data available - not evidence of anything

    for threshold, score in _DOWNLOAD_SCORES:
        if downloads < threshold:
            return Signal(
                type=SignalType.LOW_DOWNLOADS,
                score=score,
                evidence=f"only {downloads} downloads in the last month",
            )
    return None


def check_maintainer_change_npm(dependency: Dependency, client: NpmRegistryClient) -> Signal | None:
    try:
        package = client.get_full_package(dependency.name)
    except _TRANSIENT_ERRORS:
        return None

    ordered_versions = _versions_in_publish_order(package)
    if dependency.version not in ordered_versions:
        return None

    index = ordered_versions.index(dependency.version)
    if index == 0:
        return None  # first-ever version - nothing prior to compare against

    current_publisher = _npm_user_name(package, dependency.version)
    prior_publishers = {_npm_user_name(package, v) for v in ordered_versions[:index]}
    prior_publishers.discard(None)

    if current_publisher is None or current_publisher in prior_publishers:
        return None

    if _is_trusted_publisher(package, dependency.version):
        return None  # migrated to CI/OIDC trusted publishing - not a red flag

    return Signal(
        type=SignalType.MAINTAINER_CHANGE,
        score=0.5,
        evidence=(
            f"published by '{current_publisher}', who never published a prior "
            "version of this package - could be a routine maintainer handoff"
        ),
    )


def _versions_in_publish_order(package: dict) -> list[str]:
    time_map = package.get("time", {})
    version_times = [(v, t) for v, t in time_map.items() if v not in ("created", "modified")]
    version_times.sort(key=lambda vt: vt[1])
    return [v for v, _ in version_times]


def _npm_user_name(package: dict, version: str) -> str | None:
    user = package.get("versions", {}).get(version, {}).get("_npmUser")
    return user.get("name") if user else None


def _is_trusted_publisher(package: dict, version: str) -> bool:
    user = package.get("versions", {}).get(version, {}).get("_npmUser") or {}
    return "trustedPublisher" in user
