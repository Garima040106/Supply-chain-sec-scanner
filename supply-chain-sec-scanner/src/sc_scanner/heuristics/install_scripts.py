"""Suspicious install-time behavior: npm lifecycle hooks, and PyPI
setup.py scripts that exec/eval or reach out over the network.

False-positive risk - npm hooks: extremely common and mostly benign.
Native-addon compilation (bcrypt, sharp), downloading a browser binary
(puppeteer, playwright), git-hook setup (husky) all legitimately need
install scripts. Presence alone will flag a large share of normal,
trusted packages, so this is scored as a weak, contributing signal only.

False-positive risk - PyPI setup.py: the most common legitimate reason a
setup.py calls exec()/eval() is loading a version string from a separate
file (`exec(open("_version.py").read())`) to avoid import-time side
effects - a well-established, benign packaging pattern. Bare exec/eval is
scored low for exactly that reason. An actual network call (urlopen,
requests.get, socket, shelling out to curl/wget) at install time is much
rarer and far more specific - legitimate packages essentially never need
to phone home during setup.py - so it's scored much higher, and highest
when both co-occur.

Coverage gap, not a clean bill of health: a growing share of packages
ship wheel-only with no sdist, or use pyproject.toml-based build backends
with no setup.py at all. For those this check simply doesn't apply.
SetupPyFindings.inspected distinguishes "nothing to see here" from
"we had nothing to inspect" so the difference isn't lost.
"""

import ast
import io
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests

from sc_scanner.cache import DiskCache
from sc_scanner.graph.npm_resolver import NpmRegistryClient
from sc_scanner.graph.pypi_resolver import PyPIClient
from sc_scanner.heuristics.models import Signal, SignalType
from sc_scanner.http import HttpError, request_bytes
from sc_scanner.models import Dependency

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "sc-scanner" / "pypi-setup-scan"

_TRANSIENT_ERRORS = (HttpError, requests.exceptions.RequestException)

# Full dotted call paths, e.g. "urllib.request.urlopen" - built by walking
# the AST's attribute chain (see _dotted_call_name), not just one level.
_ALWAYS_NETWORK_CALLS = {
    "urllib.request.urlopen",
    "urllib2.urlopen",
    "urlopen",  # e.g. `from urllib.request import urlopen`
    "requests.get",
    "requests.post",
    "requests.request",
    "http.client.HTTPConnection",
    "socket.socket",
}
_SHELL_EXEC_CALLS = {
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
_DOWNLOADER_HINTS = ("curl", "wget", "http://", "https://")


def check_npm_install_script(dependency: Dependency, client: NpmRegistryClient) -> Signal | None:
    """Uses the npm registry directly (independent of any lockfile).

    Reads "hasInstallScript" - a flag the registry itself computes from
    whether preinstall/install/postinstall are defined, present even in
    the abbreviated packument (which doesn't include the "scripts" object
    itself). This is the exact same flag package-lock.json's "packages"
    entries expose, so both checks below share one code path.
    """
    try:
        package = client.get_package(dependency.name)
    except _TRANSIENT_ERRORS:
        return None

    version_manifest = package.get("versions", {}).get(dependency.version, {})
    return _signal_for_hooks(bool(version_manifest.get("hasInstallScript")))


def check_npm_install_script_from_lockfile(
    dependency: Dependency, has_install_script: bool
) -> Signal | None:
    """Uses package-lock.json's own "hasInstallScript" flag when it's
    already available - no network call needed."""
    return _signal_for_hooks(has_install_script)


def _signal_for_hooks(has_install_script: bool) -> Signal | None:
    if not has_install_script:
        return None
    return Signal(
        type=SignalType.INSTALL_SCRIPT,
        score=0.3,
        evidence=(
            "defines a preinstall/install/postinstall script - common for legitimate "
            "native builds or binary downloads, but also how real supply-chain attacks execute code"
        ),
    )


@dataclass(frozen=True, slots=True)
class SetupPyFindings:
    inspected: bool
    has_setup_py: bool
    has_exec_or_eval: bool
    has_network_call: bool


class SetupPyInspector:
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

    def inspect(self, name: str, version: str, pypi_client: PyPIClient) -> SetupPyFindings:
        cache_key = f"{name}:{version}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return SetupPyFindings(**cached)

        findings = self._inspect_uncached(name, version, pypi_client)
        self._cache.set(cache_key, asdict(findings))
        return findings

    def _inspect_uncached(self, name: str, version: str, pypi_client: PyPIClient) -> SetupPyFindings:
        not_inspected = SetupPyFindings(
            inspected=False, has_setup_py=False, has_exec_or_eval=False, has_network_call=False
        )

        try:
            release = pypi_client.get_release(name, version)
        except _TRANSIENT_ERRORS:
            return not_inspected

        sdist_url = _find_sdist_url(release)
        if sdist_url is None:
            return not_inspected  # wheel-only release - nothing to inspect

        try:
            tarball = request_bytes(
                self._session,
                "GET",
                sdist_url,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._backoff_seconds,
            )
        except _TRANSIENT_ERRORS:
            return not_inspected

        source = _extract_setup_py(tarball)
        if source is None:
            return SetupPyFindings(
                inspected=True, has_setup_py=False, has_exec_or_eval=False, has_network_call=False
            )

        has_exec_or_eval, has_network_call = _scan_source(source)
        return SetupPyFindings(
            inspected=True,
            has_setup_py=True,
            has_exec_or_eval=has_exec_or_eval,
            has_network_call=has_network_call,
        )


def check_pypi_install_script(
    dependency: Dependency, pypi_client: PyPIClient, inspector: SetupPyInspector | None = None
) -> Signal | None:
    inspector = inspector or SetupPyInspector()
    findings = inspector.inspect(dependency.name, dependency.version, pypi_client)

    if not findings.inspected or not findings.has_setup_py:
        return None

    if findings.has_exec_or_eval and findings.has_network_call:
        return Signal(
            type=SignalType.INSTALL_SCRIPT,
            score=0.95,
            evidence="setup.py both fetches a network resource and exec()/eval()s content at install time",
        )
    if findings.has_network_call:
        return Signal(
            type=SignalType.INSTALL_SCRIPT,
            score=0.7,
            evidence="setup.py makes a network call at install time - unusual for a normal build",
        )
    if findings.has_exec_or_eval:
        return Signal(
            type=SignalType.INSTALL_SCRIPT,
            score=0.3,
            evidence="setup.py calls exec()/eval() - often a benign version-loading pattern, but worth a look",
        )
    return None


def _find_sdist_url(release: dict[str, Any]) -> str | None:
    for file_info in release.get("urls", []):
        if file_info.get("packagetype") == "sdist":
            return file_info.get("url")
    return None


def _extract_setup_py(tarball_bytes: bytes) -> str | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
            # setup.py should be at the sdist root, e.g. "six-1.17.0/setup.py" -
            # not nested inside a subdirectory, which would be a test fixture
            # or vendored copy rather than the package's own build script.
            candidates = [
                member
                for member in tar.getmembers()
                if member.isfile() and member.name.split("/")[-1] == "setup.py" and member.name.count("/") == 1
            ]
            if not candidates:
                return None
            extracted = tar.extractfile(candidates[0])
            if extracted is None:
                return None
            return extracted.read().decode("utf-8", errors="replace")
    except (tarfile.TarError, OSError):
        return None


def _scan_source(source: str) -> tuple[bool, bool]:
    """(has_exec_or_eval, has_network_call)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False, False

    has_exec_or_eval = False
    has_network_call = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        dotted = _dotted_call_name(node)
        if dotted is None:
            continue

        if dotted in ("exec", "eval"):
            has_exec_or_eval = True
        elif dotted in _ALWAYS_NETWORK_CALLS:
            has_network_call = True
        elif dotted in _SHELL_EXEC_CALLS and _call_mentions_downloader(node):
            has_network_call = True

    return has_exec_or_eval, has_network_call


def _dotted_call_name(node: ast.Call) -> str | None:
    """The full dotted path of a call target, e.g. "urllib.request.urlopen"
    for `urllib.request.urlopen(...)`, or just "eval" for a bare
    `eval(...)`. None for anything else (a call on a subscript, another
    call's result, etc.) - not a simple name we can pattern-match."""
    parts: list[str] = []
    func = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        parts.append(func.id)
    elif parts:
        return None
    else:
        return None

    return ".".join(reversed(parts))


def _call_mentions_downloader(node: ast.Call) -> bool:
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                lowered = sub.value.lower()
                if any(hint in lowered for hint in _DOWNLOADER_HINTS):
                    return True
    return False
