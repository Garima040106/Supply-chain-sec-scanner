from sc_scanner.heuristics.models import Signal, SignalType
from sc_scanner.heuristics.scorer import WEIGHTS, combine


def test_weights_sum_to_one():
    # A package hitting every signal at maximum severity should top out
    # at 1.0, not pile up past it.
    assert sum(WEIGHTS.values()) == 1.0


def test_no_signals_scores_zero():
    result = combine([])

    assert result.score == 0.0
    assert result.tier == "LOW"
    assert result.signals == ()


def test_a_single_weak_signal_stays_low_tier():
    result = combine([Signal(type=SignalType.LOW_DOWNLOADS, score=0.3, evidence="e")])

    assert result.score == 0.3 * WEIGHTS[SignalType.LOW_DOWNLOADS]
    assert result.tier == "LOW"


def test_a_strong_typosquat_signal_alone_reaches_medium_or_higher():
    result = combine([Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="e")])

    assert result.score == 0.9 * WEIGHTS[SignalType.TYPOSQUAT]
    assert result.tier in ("MEDIUM", "HIGH")


def test_multiple_weak_signals_combine_to_something_higher_than_any_alone():
    signals = [
        Signal(type=SignalType.RECENT_PUBLISH, score=0.6, evidence="new"),
        Signal(type=SignalType.LOW_DOWNLOADS, score=0.6, evidence="obscure"),
        Signal(type=SignalType.MAINTAINER_CHANGE, score=0.5, evidence="new publisher"),
    ]

    result = combine(signals)

    individually_highest = max(s.score * WEIGHTS[s.type] for s in signals)
    assert result.score > individually_highest


def test_every_maxed_out_signal_together_caps_at_one():
    signals = [Signal(type=signal_type, score=1.0, evidence="e") for signal_type in WEIGHTS]

    result = combine(signals)

    assert result.score == 1.0
    assert result.tier == "HIGH"


def test_result_retains_every_individual_signal_for_inspection():
    signals = [
        Signal(type=SignalType.TYPOSQUAT, score=0.9, evidence="close to 'lodash'"),
        Signal(type=SignalType.INSTALL_SCRIPT, score=0.3, evidence="has postinstall"),
    ]

    result = combine(signals)

    assert result.signals == tuple(signals)
