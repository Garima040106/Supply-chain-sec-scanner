from datetime import datetime, timezone
from pathlib import Path

from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.heuristics.metadata import (
    DownloadStatsClient,
    check_low_downloads,
    check_maintainer_change_npm,
    check_recent_publish_npm,
    check_recent_publish_pypi,
)
from sc_scanner.models import Dependency, Ecosystem
from tests.fakes import FakeResponse, FakeSession

NOW = datetime(2026, 7, 21, tzinfo=timezone.utc)


def _npm_client(tmp_path: Path, responses) -> NpmRegistryClient:
    return NpmRegistryClient(
        cache_dir=tmp_path / "npm-cache", session=FakeSession(responses), backoff_seconds=0
    )


def _pypi_client(tmp_path: Path, responses) -> PyPIClient:
    return PyPIClient(
        cache_dir=tmp_path / "pypi-cache", session=FakeSession(responses), backoff_seconds=0
    )


def _downloads_client(tmp_path: Path, responses) -> DownloadStatsClient:
    return DownloadStatsClient(
        cache_dir=tmp_path / "downloads-cache", session=FakeSession(responses), backoff_seconds=0
    )


# --- recent publish ---


def test_recent_publish_npm_flags_a_package_created_days_ago(tmp_path):
    dep = Dependency(name="brand-new-thing", version="1.0.0", ecosystem=Ecosystem.NPM)
    package = {"time": {"created": "2026-07-19T00:00:00.000Z"}}
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    signal = check_recent_publish_npm(dep, client, now=NOW)

    assert signal is not None
    assert "2 day" in signal.evidence


def test_recent_publish_npm_does_not_flag_a_decade_old_package(tmp_path):
    dep = Dependency(name="lodash", version="4.17.21", ecosystem=Ecosystem.NPM)
    package = {"time": {"created": "2012-04-05T00:00:00.000Z"}}
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    assert check_recent_publish_npm(dep, client, now=NOW) is None


def test_recent_publish_pypi_uses_earliest_release_not_this_versions_date(tmp_path):
    # requests 2.31.0 is old, but PyPI JSON always reports the *project's*
    # oldest release date regardless of which version we asked about - a
    # routine new patch release of an old package must not be flagged.
    dep = Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI)
    project = {
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2011-02-14T00:00:00Z"}],
            "2.31.0": [{"upload_time_iso_8601": "2026-07-20T00:00:00Z"}],
        }
    }
    client = _pypi_client(tmp_path, [FakeResponse(200, project)])

    assert check_recent_publish_pypi(dep, client, now=NOW) is None


def test_recent_publish_pypi_flags_a_project_whose_earliest_release_is_new(tmp_path):
    dep = Dependency(name="brand-new-thing", version="0.1.0", ecosystem=Ecosystem.PYPI)
    project = {"releases": {"0.1.0": [{"upload_time_iso_8601": "2026-07-15T00:00:00Z"}]}}
    client = _pypi_client(tmp_path, [FakeResponse(200, project)])

    signal = check_recent_publish_pypi(dep, client, now=NOW)

    assert signal is not None


# --- low downloads ---


def test_low_downloads_flags_a_near_zero_npm_package(tmp_path):
    dep = Dependency(name="obscure-thing", version="1.0.0", ecosystem=Ecosystem.NPM)
    client = _downloads_client(tmp_path, [FakeResponse(200, {"downloads": 12})])

    signal = check_low_downloads(dep, client)

    assert signal is not None
    assert signal.score == 1.0


def test_low_downloads_does_not_flag_a_hugely_popular_package(tmp_path):
    dep = Dependency(name="lodash", version="4.17.21", ecosystem=Ecosystem.NPM)
    client = _downloads_client(tmp_path, [FakeResponse(200, {"downloads": 50_000_000})])

    assert check_low_downloads(dep, client) is None


def test_low_downloads_treats_missing_pypistats_data_as_unknown_not_zero(tmp_path):
    # pypistats.org 404s for packages it has no data for yet - that must
    # not be read as "confirmed near-zero downloads".
    dep = Dependency(name="too-new-to-have-stats", version="1.0.0", ecosystem=Ecosystem.PYPI)
    client = _downloads_client(tmp_path, [FakeResponse(404, reason="Not Found")])

    assert check_low_downloads(dep, client) is None


# --- maintainer change (npm only) ---


def test_maintainer_change_flags_a_new_publisher_with_no_prior_history(tmp_path):
    dep = Dependency(name="some-package", version="2.0.0", ecosystem=Ecosystem.NPM)
    package = {
        "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-07-01T00:00:00Z"},
        "versions": {
            "1.0.0": {"_npmUser": {"name": "original-author"}},
            "2.0.0": {"_npmUser": {"name": "someone-new"}},
        },
    }
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    signal = check_maintainer_change_npm(dep, client)

    assert signal is not None
    assert "someone-new" in signal.evidence


def test_maintainer_change_does_not_flag_the_same_publisher(tmp_path):
    dep = Dependency(name="some-package", version="2.0.0", ecosystem=Ecosystem.NPM)
    package = {
        "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-07-01T00:00:00Z"},
        "versions": {
            "1.0.0": {"_npmUser": {"name": "original-author"}},
            "2.0.0": {"_npmUser": {"name": "original-author"}},
        },
    }
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    assert check_maintainer_change_npm(dep, client) is None


def test_maintainer_change_does_not_flag_the_first_ever_version(tmp_path):
    dep = Dependency(name="some-package", version="1.0.0", ecosystem=Ecosystem.NPM)
    package = {
        "time": {"1.0.0": "2026-07-01T00:00:00Z"},
        "versions": {"1.0.0": {"_npmUser": {"name": "original-author"}}},
    }
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    assert check_maintainer_change_npm(dep, client) is None


def test_maintainer_change_does_not_flag_trusted_ci_publishing(tmp_path):
    # A project migrating to OIDC/CI-based publishing changes the
    # publisher identity for good reasons - npm marks this explicitly.
    dep = Dependency(name="some-package", version="2.0.0", ecosystem=Ecosystem.NPM)
    package = {
        "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-07-01T00:00:00Z"},
        "versions": {
            "1.0.0": {"_npmUser": {"name": "original-author"}},
            "2.0.0": {"_npmUser": {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}}},
        },
    }
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    assert check_maintainer_change_npm(dep, client) is None
