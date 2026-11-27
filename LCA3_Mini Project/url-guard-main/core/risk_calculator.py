"""
core/risk_calculator.py - Risk Scoring Engine for URL Guard.

Aggregates points across detection checks, applies score capping (0-100),
classifies risk tiers (LOW, MEDIUM, HIGH), and generates plain-language guidance.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple
from core.detector import CheckResult


class RiskLevel(str, Enum):
    """Categorical risk classifications for analyzed URLs."""
    LOW = "LOW RISK"
    MEDIUM = "MEDIUM RISK"
    HIGH = "HIGH RISK"


@dataclass(frozen=True)
class RiskScoreResult:
    """Immutable result structure from the risk scoring calculation."""
    total_score: int
    raw_score: int
    risk_level: RiskLevel
    badge_color: str
    recommendation: str
    summary: str


def classify_risk_score(score: int) -> Tuple[RiskLevel, str, str, str]:
    """
    Classify an integer score into a RiskLevel, badge color, recommendation, and summary.
    
    Thresholds:
      0–20:   LOW RISK    (#10B981 emerald green)
      21–50:  MEDIUM RISK (#F59E0B amber orange)
      51–100: HIGH RISK   (#EF4444 crimson red)
    """
    clamped_score = max(0, min(score, 100))

    if clamped_score <= 20:
        level = RiskLevel.LOW
        badge_color = "#10B981"
        recommendation = (
            "No major suspicious characteristics were detected by this scanner. "
            "However, this does not guarantee that the website is safe. "
            "Always exercise standard caution before entering credentials, "
            "personal details, or downloading files."
        )
        summary = f"URL displays legitimate-looking characteristics with a low risk score ({clamped_score}/100)."
    elif clamped_score <= 50:
        level = RiskLevel.MEDIUM
        badge_color = "#F59E0B"
        recommendation = (
            "Several suspicious indicators were identified. "
            "Proceed with caution and independently verify the website identity "
            "and domain legitimacy before interacting."
        )
        summary = f"URL exhibits several suspicious characteristics resulting in an elevated risk score ({clamped_score}/100)."
    else:
        level = RiskLevel.HIGH
        badge_color = "#EF4444"
        recommendation = (
            "Strong phishing indicators were detected. "
            "Do not enter passwords, credit card numbers, OTPs, or any sensitive "
            "information on this website."
        )
        summary = f"URL exhibits strong phishing indicators with a critical risk score ({clamped_score}/100)."

    return level, badge_color, recommendation, summary


def calculate_risk(checks: List[CheckResult]) -> RiskScoreResult:
    """
    Calculate the overall risk score from detection check results.
    
    Guarantees:
      - Point accumulation: sums points for all detected checks.
      - Deduplication: ensures no check rule is counted more than once by check_id.
      - Capping: score is strictly capped at 100 (and bounded at 0).
      - No probability language: never describes score as a percentage probability.
      - Safety honesty: never guarantees a low-risk URL is safe.
    """
    seen_check_ids = set()
    unique_detected_checks: List[CheckResult] = []

    for check in checks:
        if check.check_id not in seen_check_ids:
            seen_check_ids.add(check.check_id)
            if check.detected and check.points > 0:
                unique_detected_checks.append(check)

    raw_score = sum(c.points for c in unique_detected_checks)
    total_score = max(0, min(raw_score, 100))

    level, badge_color, recommendation, summary = classify_risk_score(total_score)

    return RiskScoreResult(
        total_score=total_score,
        raw_score=raw_score,
        risk_level=level,
        badge_color=badge_color,
        recommendation=recommendation,
        summary=summary,
    )
