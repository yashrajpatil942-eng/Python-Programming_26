"""
URL Guard - Core Detection Engine Package
"""

from core.validator import ValidationResult, validate_url
from core.parser import ParsedURL, parse_url
from core.detector import (
    CheckResult,
    run_detection_checks,
    check_https,
    check_url_length,
    check_ip_address,
    check_suspicious_keywords,
    check_special_characters,
    check_excessive_hyphens,
    check_subdomain_complexity,
    CHECK_ID_HTTPS,
    CHECK_ID_LENGTH,
    CHECK_ID_IP,
    CHECK_ID_KEYWORDS,
    CHECK_ID_SPECIAL_CHARS,
    CHECK_ID_HYPHENS,
    CHECK_ID_SUBDOMAINS,
    SUSPICIOUS_KEYWORDS,
)
from core.risk_calculator import (
    RiskLevel,
    RiskScoreResult,
    calculate_risk,
    classify_risk_score,
)
from core.report_generator import AnalysisReport, generate_report

__version__ = "1.0.0"

__all__ = [
    # Validator
    "ValidationResult",
    "validate_url",
    # Parser
    "ParsedURL",
    "parse_url",
    # Detector
    "CheckResult",
    "run_detection_checks",
    "check_https",
    "check_url_length",
    "check_ip_address",
    "check_suspicious_keywords",
    "check_special_characters",
    "check_excessive_hyphens",
    "check_subdomain_complexity",
    "CHECK_ID_HTTPS",
    "CHECK_ID_LENGTH",
    "CHECK_ID_IP",
    "CHECK_ID_KEYWORDS",
    "CHECK_ID_SPECIAL_CHARS",
    "CHECK_ID_HYPHENS",
    "CHECK_ID_SUBDOMAINS",
    "SUSPICIOUS_KEYWORDS",
    # Risk Calculator
    "RiskLevel",
    "RiskScoreResult",
    "calculate_risk",
    "classify_risk_score",
    # Report Generator
    "AnalysisReport",
    "generate_report",
]
