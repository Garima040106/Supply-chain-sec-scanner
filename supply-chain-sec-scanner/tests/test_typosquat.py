from sc_scanner.heuristics.typosquat import check_typosquat
from sc_scanner.models import Dependency, Ecosystem


def test_flags_a_single_character_omission_of_a_popular_npm_package():
    # "lodash" is real and popular; "lodahs" is a one-swap typo of it.
    dep = Dependency(name="lodahs", version="1.0.0", ecosystem=Ecosystem.NPM)

    signal = check_typosquat(dep)

    assert signal is not None
    assert "lodash" in signal.evidence
    assert signal.score > 0


def test_flags_a_classic_transposition_typo_of_a_popular_pypi_package():
    # "reqeusts" (transposed letters) is a well-known real typosquat pattern of "requests".
    dep = Dependency(name="reqeusts", version="1.0.0", ecosystem=Ecosystem.PYPI)

    signal = check_typosquat(dep)

    assert signal is not None
    assert "requests" in signal.evidence


def test_does_not_flag_an_exact_match_of_a_popular_package():
    dep = Dependency(name="lodash", version="1.0.0", ecosystem=Ecosystem.NPM)

    assert check_typosquat(dep) is None


def test_does_not_flag_an_unrelated_name_far_from_anything_popular():
    dep = Dependency(name="my-completely-unrelated-internal-tool", version="1.0.0", ecosystem=Ecosystem.NPM)

    assert check_typosquat(dep) is None


def test_a_closer_match_scores_higher_than_a_more_distant_one():
    one_edit = check_typosquat(Dependency(name="lodahs", version="1.0.0", ecosystem=Ecosystem.NPM))
    two_edits = check_typosquat(Dependency(name="lodahz9", version="1.0.0", ecosystem=Ecosystem.NPM))

    assert one_edit is not None
    if two_edits is not None:
        assert one_edit.score >= two_edits.score


def test_documented_false_positive_color_vs_colors():
    # "color" and "colors" are both real, popular, unrelated npm packages
    # that happen to sit at edit-distance 1. The heuristic can't tell them
    # apart from name alone - this test documents that known limitation
    # rather than pretending it's solved.
    dep = Dependency(name="color", version="1.0.0", ecosystem=Ecosystem.NPM)

    signal = check_typosquat(dep)

    assert signal is not None
    assert "colors" in signal.evidence


def test_pypi_names_are_compared_pep503_normalized():
    # "Typing_Extensions" should match against "typing-extensions" in the
    # bundled list despite case/separator differences, same as an exact
    # dependency name would - not get flagged as its own typosquat.
    dep = Dependency(name="typing_extensions", version="1.0.0", ecosystem=Ecosystem.PYPI)

    signal = check_typosquat(dep)

    assert signal is None
