"""Typosquat detection: is this package name suspiciously close to a
well-known one it isn't?

False-positive risk (see also the design discussion this was built from):
edit distance can't tell "malicious near-miss" from "legitimately related
package" - `react-dom` is deliberately close to `react`, and some
genuinely unrelated popular packages sit at distance 1 from each other by
coincidence (`color` and `colors` are both real, both popular, and both
distance 1 apart). Mitigations applied here:
  - only distances 1-2 are considered (most legitimate satellite-package
    naming, e.g. adding a "-cli"/"-dom"/"-loader" suffix, differs by more
    than that);
  - an exact match is never flagged (it just *is* the popular package);
  - popular names shorter than MIN_TARGET_LENGTH are skipped as typosquat
    targets, since at distance 1-2 a huge fraction of short strings are
    "close" to them by chance, not by intent.
None of this closes the `color`/`colors` kind of gap - this is scored as
a "worth a human look" signal, not a verdict, and the popular package it
resembles is always included so a reviewer can judge it directly.

The bundled lists (data/top-{npm,pypi}-packages.txt) are ~1000 package
names each, ranked by real popularity data (PyPI: download counts via
hugovk/top-pypi-packages; npm: dependency-graph rank via
Meyond/npm-top-1000-packages, a 2019 snapshot - stale on exact ranking,
but the *names* of top packages change slowly, so it's still a reasonable
reference set for this purpose).
"""

from functools import lru_cache
from pathlib import Path

from sc_scanner.heuristics.models import Signal, SignalType
from sc_scanner.models import Dependency, Ecosystem, normalize_pypi_name

DATA_DIR = Path(__file__).parent / "data"

MAX_DISTANCE = 2
MIN_TARGET_LENGTH = 4

_DISTANCE_SCORES = {1: 0.9, 2: 0.6}


@lru_cache(maxsize=None)
def _popular_names(ecosystem: Ecosystem) -> tuple[str, ...]:
    filename = "top-npm-packages.txt" if ecosystem == Ecosystem.NPM else "top-pypi-packages.txt"
    lines = (DATA_DIR / filename).read_text().splitlines()
    return tuple(name.strip() for name in lines if name.strip())


def _distance(a: str, b: str) -> int:
    """Classic Levenshtein (Wagner-Fischer) edit distance."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row[j] = min(
                previous_row[j] + 1,  # deletion
                current_row[j - 1] + 1,  # insertion
                previous_row[j - 1] + cost,  # substitution
            )
        previous_row = current_row

    return previous_row[-1]


def check_typosquat(dependency: Dependency) -> Signal | None:
    name = (
        normalize_pypi_name(dependency.name)
        if dependency.ecosystem == Ecosystem.PYPI
        else dependency.name
    )

    best_distance: int | None = None
    best_match: str | None = None

    for popular in _popular_names(dependency.ecosystem):
        comparable = normalize_pypi_name(popular) if dependency.ecosystem == Ecosystem.PYPI else popular
        if comparable == name or len(popular) < MIN_TARGET_LENGTH:
            continue

        distance = _distance(name, comparable)
        if distance > MAX_DISTANCE:
            continue
        if best_distance is None or distance < best_distance:
            best_distance, best_match = distance, popular

    if best_distance is None:
        return None

    return Signal(
        type=SignalType.TYPOSQUAT,
        score=_DISTANCE_SCORES[best_distance],
        evidence=(
            f"'{dependency.name}' is edit-distance {best_distance} from "
            f"popular package '{best_match}' - possible typosquat, or an "
            f"unrelated coincidentally-similar name; needs a human look"
        ),
    )
