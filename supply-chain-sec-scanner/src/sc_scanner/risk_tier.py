"""The single LOW/MEDIUM/HIGH tier definition for any 0.0-1.0 risk score,
shared by heuristic assessments and combined package/project risk scores
so "HIGH" means the same thing everywhere in the app."""

_HIGH_THRESHOLD = 0.5
_MEDIUM_THRESHOLD = 0.2


def tier_for_score(score: float) -> str:
    if score >= _HIGH_THRESHOLD:
        return "HIGH"
    if score >= _MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
