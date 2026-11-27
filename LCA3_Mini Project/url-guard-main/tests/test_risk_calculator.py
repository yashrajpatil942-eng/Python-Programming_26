"""
Unit tests for core/risk_calculator.py and core/report_generator.py.
Tests scoring aggregation, capping at 100, risk classification boundaries,
deduplication, plain-language constraints, and comprehensive report generation.
"""

from datetime import datetime
import pytest

from core.detector import CheckResult
from core.risk_calculator import (
    RiskLevel,
    RiskScoreResult,
    calculate_risk,
    classify_risk_score,
)
from core.validator import validate_url
from core.parser import parse_url
from core.report_generator import generate_report, AnalysisReport


def _make_check(check_id: str, points: int, detected: bool = True) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=f"Check {check_id}",
        detected=detected,
        points=points if detected else 0,
        explanation=f"Explanation for {check_id}" if detected else "Not detected",
        evidence=None,
    )


class TestRiskCalculator:
    """Test suite for risk calculation and classification."""

    def test_empty_checks_list_yields_zero_low_risk(self):
        res = calculate_risk([])
        assert res.total_score == 0
        assert res.raw_score == 0
        assert res.risk_level == RiskLevel.LOW
        assert res.badge_color == "#10B981"

    def test_all_undetected_checks_yields_zero_low_risk(self):
        checks = [
            _make_check("c1", 10, detected=False),
            _make_check("c2", 25, detected=False),
        ]
        res = calculate_risk(checks)
        assert res.total_score == 0
        assert res.risk_level == RiskLevel.LOW
        assert res.badge_color == "#10B981"

    def test_low_risk_upper_boundary_20_points(self):
        # 10 + 10 = 20 points
        checks = [
            _make_check("c1", 10),
            _make_check("c2", 10),
        ]
        res = calculate_risk(checks)
        assert res.total_score == 20
        assert res.risk_level == RiskLevel.LOW
        assert res.badge_color == "#10B981"

    def test_medium_risk_lower_boundary_21_points(self):
        level, color, rec, sumry = classify_risk_score(21)
        assert level == RiskLevel.MEDIUM
        assert color == "#F59E0B"

        checks = [
            _make_check("c1", 10),
            _make_check("c2", 11),
        ]
        res = calculate_risk(checks)
        assert res.total_score == 21
        assert res.risk_level == RiskLevel.MEDIUM
        assert res.badge_color == "#F59E0B"

    def test_medium_risk_upper_boundary_50_points(self):
        checks = [
            _make_check("c1", 25),
            _make_check("c2", 15),
            _make_check("c3", 10),
        ]
        res = calculate_risk(checks)
        assert res.total_score == 50
        assert res.risk_level == RiskLevel.MEDIUM
        assert res.badge_color == "#F59E0B"

    def test_high_risk_lower_boundary_51_points(self):
        level, color, rec, sumry = classify_risk_score(51)
        assert level == RiskLevel.HIGH
        assert color == "#EF4444"

        checks = [
            _make_check("c1", 25),
            _make_check("c2", 15),
            _make_check("c3", 11),
        ]
        res = calculate_risk(checks)
        assert res.total_score == 51
        assert res.risk_level == RiskLevel.HIGH
        assert res.badge_color == "#EF4444"

    def test_maximum_standard_score_100_points(self):
        # 10 + 10 + 25 + 15 + 15 + 10 + 15 = 100
        checks = [
            _make_check("check_https", 10),
            _make_check("check_length", 10),
            _make_check("check_ip", 25),
            _make_check("check_keywords", 15),
            _make_check("check_special_chars", 15),
            _make_check("check_hyphens", 10),
            _make_check("check_subdomains", 15),
        ]
        res = calculate_risk(checks)
        assert res.raw_score == 100
        assert res.total_score == 100
        assert res.risk_level == RiskLevel.HIGH
        assert res.badge_color == "#EF4444"

    def test_score_capping_over_100(self):
        checks = [
            _make_check("c1", 50),
            _make_check("c2", 50),
            _make_check("c3", 30),
        ]
        res = calculate_risk(checks)
        assert res.raw_score == 130
        assert res.total_score == 100
        assert res.risk_level == RiskLevel.HIGH

    def test_check_deduplication_by_id(self):
        # If check_id is duplicated in input, only first occurrence is counted
        checks = [
            _make_check("check_keywords", 15),
            _make_check("check_keywords", 15),
            _make_check("check_keywords", 15),
        ]
        res = calculate_risk(checks)
        assert res.raw_score == 15
        assert res.total_score == 15

    def test_plain_language_constraints(self):
        # 1. No % or probability in recommendations or summaries
        for score in [0, 10, 20, 21, 50, 51, 80, 100]:
            _, _, rec, sumry = classify_risk_score(score)
            assert "%" not in rec
            assert "%" not in sumry
            assert "probability" not in rec.lower()
            assert "probability" not in sumry.lower()
            assert "chance" not in rec.lower()
            assert "chance" not in sumry.lower()

        # 2. LOW risk recommendation explicitly states it does not guarantee safety
        _, _, low_rec, _ = classify_risk_score(10)
        assert "does not guarantee that the website is safe" in low_rec


class TestReportGenerator:
    """Test suite for result report generation."""

    def test_generate_report_field_completeness(self):
        url = "https://example.com/login"
        val = validate_url(url)
        parsed = parse_url(url, val)
        checks = [
            CheckResult("check_https", "HTTPS Check", False, 0, "Uses HTTPS", None),
            CheckResult("check_length", "Length", False, 0, "Normal length", len(url)),
            CheckResult("check_ip", "IP Check", False, 0, "Domain", None),
            CheckResult("check_keywords", "Keywords", True, 15, "Found login keyword", ["login"]),
            CheckResult("check_special_chars", "Special Chars", False, 0, "Clean", None),
            CheckResult("check_hyphens", "Hyphens", False, 0, "Clean", {"count": 0}),
            CheckResult("check_subdomains", "Subdomains", False, 0, "Clean", {"count": 0}),
        ]
        risk = calculate_risk(checks)
        report = generate_report(parsed, checks, risk)

        assert isinstance(report, AnalysisReport)
        assert report.original_url == url
        assert report.normalized_hostname == "example.com"
        assert "Valid" in report.validation_status
        assert "HTTPS" in report.protocol_info
        assert report.url_length == len(url)
        assert report.keyword_detection.detected is True
        assert report.total_risk_score == 15
        assert report.risk_classification == "LOW RISK"
        assert len(report.detected_explanations) == 1
        assert "Found login keyword" in report.detected_explanations[0]
        assert report.sanitized_url == "https://example.com/login"
        assert report.badge_color == "#10B981"
        assert report.timestamp.endswith("Z")

    def test_protocol_info_variants(self):
        # 1. HTTPS
        v1 = validate_url("https://example.com")
        p1 = parse_url("https://example.com", v1)
        r1 = generate_report(p1, [], calculate_risk([]))
        assert "HTTPS (Encrypted communication)" in r1.protocol_info

        # 2. HTTP
        v2 = validate_url("http://example.com")
        p2 = parse_url("http://example.com", v2)
        r2 = generate_report(p2, [], calculate_risk([]))
        assert "HTTP (Unencrypted" in r2.protocol_info

        # 3. Missing scheme
        v3 = validate_url("example.com")
        p3 = parse_url("example.com", v3)
        r3 = generate_report(p3, [], calculate_risk([]))
        assert "Scheme not explicitly provided" in r3.protocol_info

    def test_report_to_dict_serialization(self):
        url = "https://example.com"
        val = validate_url(url)
        parsed = parse_url(url, val)
        report = generate_report(parsed, [], calculate_risk([]))

        rep_dict = report.to_dict()
        assert isinstance(rep_dict, dict)
        assert rep_dict["original_url"] == url
        assert rep_dict["total_risk_score"] == 0
        assert rep_dict["risk_classification"] == "LOW RISK"

    def test_fallback_when_check_missing(self):
        # If checks list does not contain check_ip, generator should not crash
        url = "https://example.com"
        val = validate_url(url)
        parsed = parse_url(url, val)
        report = generate_report(parsed, [], calculate_risk([]))
        assert report.ip_detection.check_id == "check_ip"
        assert report.ip_detection.detected is False
