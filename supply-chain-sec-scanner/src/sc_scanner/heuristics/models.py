"""Data types shared by every heuristic signal and the scorer that
combines them.

Every signal is independently scored and explained — never collapsed
into a single "malicious/not" verdict on its own. See each module's
docstring for the false-positive tradeoffs behind its scoring.
"""

from dataclasses import dataclass
from enum import Enum


class SignalType(str, Enum):
    TYPOSQUAT = "typosquat"
    INSTALL_SCRIPT = "install_script"
    RECENT_PUBLISH = "recent_publish"
    LOW_DOWNLOADS = "low_downloads"
    MAINTAINER_CHANGE = "maintainer_change"


@dataclass(frozen=True, slots=True)
class Signal:
    """One heuristic's opinion about one package.

    `score` is this signal's own severity, 0.0 (nothing notable) to 1.0
    (as suspicious as this signal alone can indicate) — never a verdict on
    the package as a whole. `evidence` is a short, human-readable reason a
    reviewer can act on directly (e.g. "distance 1 from 'lodash'").
    """

    type: SignalType
    score: float
    evidence: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The combined result for one package: every signal that was
    evaluated, plus a single weighted score. See scorer.py for exactly how
    that weighting works and why."""

    signals: tuple[Signal, ...]
    score: float

    @property
    def tier(self) -> str:
        if self.score >= 0.5:
            return "HIGH"
        if self.score >= 0.2:
            return "MEDIUM"
        return "LOW"
