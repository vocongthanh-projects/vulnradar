"""Transparent vulnerability prioritization helpers."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Priority:
    score: float
    level: str
    reasons: tuple[str, ...]


def calculate_priority(
    *, in_kev: bool, cvss_score: Optional[float], epss_score: Optional[float]
) -> Priority:
    """Return a deterministic 0-100 score and an auditable explanation."""
    score = 0.0
    reasons = []

    if in_kev:
        score += 60
        reasons.append("listed in CISA KEV")

    if cvss_score is not None:
        normalized_cvss = min(max(float(cvss_score), 0.0), 10.0)
        score += normalized_cvss * 3
        reasons.append(f"CVSS {normalized_cvss:.1f}")

    if epss_score is not None:
        normalized_epss = min(max(float(epss_score), 0.0), 1.0)
        score += normalized_epss * 10
        reasons.append(f"EPSS {normalized_epss:.1%}")

    score = round(min(score, 100.0), 1)
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return Priority(score=score, level=level, reasons=tuple(reasons or ["limited evidence"]))


def priority_for_entry(entry) -> Priority:
    return calculate_priority(
        in_kev=bool(entry.in_kev),
        cvss_score=entry.cvss_score,
        epss_score=entry.epss_score,
    )
