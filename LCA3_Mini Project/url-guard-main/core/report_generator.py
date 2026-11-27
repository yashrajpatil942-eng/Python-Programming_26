"""
core/report_generator.py - Result Report Generator for URL Guard.

Compiles the 14 mandatory structured analysis fields and UI/persistence metadata
into an understandable, non-technical AnalysisReport.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from core.parser import ParsedURL
from core.detector import CheckResult
from core.risk_calculator import RiskScoreResult


@dataclass(frozen=True)
class AnalysisReport:
    """
    Complete analysis report encapsulating all 14 mandatory fields from Section 8
    of the specification plus UI/persistence metadata.
    """
    # 1. Original URL, displayed safely
    original_url: str
    # 2. Normalised hostname
    normalized_hostname: str
    # 3. URL validation status
    validation_status: str
    # 4. Protocol information
    protocol_info: str
    # 5. URL length
    url_length: int
    # 6. IP address detection result
    ip_detection: CheckResult
    # 7. Suspicious keyword detection result
    keyword_detection: CheckResult
    # 8. Special character detection result
    special_char_detection: CheckResult
    # 9. Hyphen analysis
    hyphen_analysis: CheckResult
    # 10. Subdomain analysis
    subdomain_analysis: CheckResult
    # 11. Individual risk points
    individual_points: Dict[str, int]
    # 12. Total risk score
    total_risk_score: int
    # 13. Final risk classification
    risk_classification: str
    # 14. Plain-language explanation of detected indicators
    detected_explanations: List[str]

    # Additional metadata for UI and persistence
    recommendation: str
    timestamp: str
    sanitized_url: str
    badge_color: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary."""
        return asdict(self)


def _find_check_result(checks: List[CheckResult], check_id: str, default_name: str) -> CheckResult:
    """Safely find a specific check result by check_id with fallback."""
    for c in checks:
        if c.check_id == check_id:
            return c
    return CheckResult(
        check_id=check_id,
        check_name=default_name,
        detected=False,
        points=0,
        explanation=f"No {default_name.lower()} data available.",
        evidence=None,
    )


def generate_report(
    parsed: ParsedURL,
    checks: List[CheckResult],
    risk: RiskScoreResult,
    timestamp: Optional[str] = None
) -> AnalysisReport:
    """
    Generate an AnalysisReport from parsed URL components, check results, and risk scores.
    """
    # 1. Format protocol information
    if parsed.has_explicit_scheme:
        scheme_clean = (parsed.explicit_scheme or "").strip().lower()
        if scheme_clean == "https":
            protocol_info = "HTTPS (Encrypted communication)"
        elif scheme_clean == "http":
            protocol_info = "HTTP (Unencrypted - vulnerable to interception)"
        else:
            protocol_info = f"{parsed.explicit_scheme.upper()} (Explicit non-standard scheme)"
    else:
        protocol_info = "Scheme not explicitly provided (Inspected without assuming encryption)"

    # 2. Extract individual required check results
    ip_detection = _find_check_result(checks, "check_ip", "IP Address Detection")
    keyword_detection = _find_check_result(checks, "check_keywords", "Suspicious Keyword Detection")
    special_char_detection = _find_check_result(checks, "check_special_chars", "Special Character Analysis")
    hyphen_analysis = _find_check_result(checks, "check_hyphens", "Excessive Hyphen Analysis")
    subdomain_analysis = _find_check_result(checks, "check_subdomains", "Subdomain Complexity Analysis")

    # 3. Individual points mapping
    individual_points = {c.check_id: c.points for c in checks}

    # 4. Explanations for detected indicators
    detected_explanations = [
        c.explanation for c in checks if c.detected and c.explanation
    ]
    if not detected_explanations:
        detected_explanations = [
            "No suspicious phishing indicators were identified by the rule engine."
        ]

    # 5. Timestamp generation (ISO 8601 UTC)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return AnalysisReport(
        original_url=parsed.raw_url,
        normalized_hostname=parsed.hostname,
        validation_status="Valid (Formatting and structure verified)",
        protocol_info=protocol_info,
        url_length=len(parsed.raw_url),
        ip_detection=ip_detection,
        keyword_detection=keyword_detection,
        special_char_detection=special_char_detection,
        hyphen_analysis=hyphen_analysis,
        subdomain_analysis=subdomain_analysis,
        individual_points=individual_points,
        total_risk_score=risk.total_score,
        risk_classification=risk.risk_level.value,
        detected_explanations=detected_explanations,
        recommendation=risk.recommendation,
        timestamp=timestamp,
        sanitized_url=parsed.sanitized_url,
        badge_color=risk.badge_color,
    )
