"""Combines independently-scored signals into one RiskAssessment.

Each signal type has a fixed weight (below), chosen so the weights sum to
1.0 - a package hitting every signal at maximum severity tops out at 1.0,
not an unbounded pile-up. The combination is a plain weighted sum, not a
weighted *average*: a package with only one applicable signal is scored
on that signal alone (times its weight), not inflated by pretending the
signals we couldn't evaluate were "clean". That means a partial
assessment naturally produces a lower ceiling score than a full one -
an honest reflection of "we could only check some of this", not a claim
that the unchecked parts are safe. `RiskAssessment` keeps every
individual Signal so a reviewer can see exactly why a score landed where
it did, never just a bare number.

Weights, and the reasoning (see each signal module's docstring for the
full false-positive discussion):
  - typosquat (0.35): the most direct evidence of *intent to deceive*
    when it fires, even though it's also the noisiest signal to compute.
  - install_script (0.30): genuinely how real supply-chain attacks
    execute code, but common and mostly benign on its own - weighted
    high because the signal's own score already accounts for severity
    (bare hook presence scores low; setup.py exec+network scores high).
  - recent_publish (0.15): a real attacker pattern (freshly-published
    malicious packages) but true of the large majority of harmless new
    packages too.
  - low_downloads (0.10): the weakest signal - obscurity is the norm for
    most legitimate packages - and correlated with recent_publish rather
    than independent evidence.
  - maintainer_change (0.10): plausible attack pattern, but
    indistinguishable from routine, healthy maintainer handoffs without
    social context this scanner doesn't have.
"""

from sc_scanner.heuristics.models import RiskAssessment, Signal, SignalType

WEIGHTS: dict[SignalType, float] = {
    SignalType.TYPOSQUAT: 0.35,
    SignalType.INSTALL_SCRIPT: 0.30,
    SignalType.RECENT_PUBLISH: 0.15,
    SignalType.LOW_DOWNLOADS: 0.10,
    SignalType.MAINTAINER_CHANGE: 0.10,
}


def combine(signals: list[Signal]) -> RiskAssessment:
    total = sum(signal.score * WEIGHTS[signal.type] for signal in signals)
    return RiskAssessment(signals=tuple(signals), score=min(total, 1.0))
