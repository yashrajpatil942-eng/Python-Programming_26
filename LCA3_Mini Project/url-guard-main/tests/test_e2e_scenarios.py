"""
URL Guard — End-to-End (E2E) Comprehensive Test Suite
File: tests/test_e2e_scenarios.py

Authoritative opaque-box integration and system test suite validating the complete
URL Guard pipeline against user requirements in ORIGINAL_REQUEST.md and interface
contracts in PROJECT.md § Interface Contracts.

Structure:
- PipelineExecution and run_pipeline harness
- TestTier1FeatureCoverage: Features F1 through F13 (>= 5 tests per feature)
- TestTier2BoundaryValueAnalysis: 8 boundary condition groups (>= 5 tests per group)
- TestTier3PairwiseCombinations: 19 pairwise combinations + 2 threshold boundaries
- TestTier4RealWorldPhishingScenarios: All 9 realistic phishing and legitimate scenarios
- TestStorageAndPersistenceE2E: History storage, retrieval, clearing, export & privacy redaction
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import pytest

# Ensure workspace root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safe imports for core modules
from core.validator import validate_url, ValidationResult
from core.parser import parse_url, ParsedURL
from core.detector import (
    run_detection_checks,
    CheckResult,
    CHECK_ID_HTTPS,
    CHECK_ID_LENGTH,
    CHECK_ID_IP,
    CHECK_ID_KEYWORDS,
    CHECK_ID_SPECIAL_CHARS,
    CHECK_ID_HYPHENS,
    CHECK_ID_SUBDOMAINS,
)
from core.risk_calculator import calculate_risk, RiskScoreResult, RiskLevel
from core.report_generator import generate_report, AnalysisReport

# Defensive import for storage (M2 dependency isolation)
try:
    from storage.history_manager import save_scan, get_history, clear_history, export_history_csv
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False


# ============================================================================
# Pipeline Runner & Execution Context
# ============================================================================

class PipelineExecution:
    """Encapsulates the end-to-end execution of a URL Guard scan."""

    def __init__(
        self,
        raw_url: str,
        validation: ValidationResult,
        parsed: Optional[ParsedURL] = None,
        checks: Optional[List[CheckResult]] = None,
        risk: Optional[RiskScoreResult] = None,
        report: Optional[AnalysisReport] = None,
        saved_successfully: Optional[bool] = None,
    ):
        self.raw_url = raw_url
        self.validation = validation
        self.parsed = parsed
        self.checks = checks or []
        self.risk = risk
        self.report = report
        self.saved_successfully = saved_successfully

    def get_check(self, check_id: str) -> Optional[CheckResult]:
        """Retrieve a specific CheckResult by its canonical check_id."""
        for c in self.checks:
            if c.check_id == check_id:
                return c
        return None

    def assert_success(
        self,
        expected_hostname: str,
        expected_score: int,
        expected_level: RiskLevel,
        expected_triggered_checks: Set[str],
    ):
        """Asserts expected outcomes across all pipeline stages."""
        assert self.validation.is_valid is True, f"Validation failed: {self.validation.error_message}"
        assert self.validation.error_message is None
        assert self.parsed is not None, "ParsedURL is None"
        assert self.parsed.hostname == expected_hostname

        assert len(self.checks) == 7, f"Expected 7 detection checks, got {len(self.checks)}"
        actual_triggered = {c.check_id for c in self.checks if c.detected}
        assert actual_triggered == expected_triggered_checks, (
            f"Triggered checks mismatch. Expected {expected_triggered_checks}, got {actual_triggered}"
        )

        for c in self.checks:
            if c.check_id in expected_triggered_checks:
                assert c.detected is True
                assert c.points > 0, f"Triggered check {c.check_id} awarded 0 points"
            else:
                assert c.detected is False
                assert c.points == 0, f"Undetected check {c.check_id} awarded {c.points} points"

        assert self.risk is not None, "RiskScoreResult is None"
        assert self.risk.total_score == expected_score
        assert self.risk.risk_level == expected_level

        assert self.report is not None, "AnalysisReport is None"
        assert self.report.normalized_hostname == expected_hostname
        assert self.report.total_risk_score == expected_score
        assert self.report.risk_classification == expected_level.value


def run_pipeline(raw_url: str, data_dir: Optional[Path] = None) -> PipelineExecution:
    """Executes the complete URL Guard pipeline from raw string to storage."""
    validation = validate_url(raw_url)
    if not validation.is_valid:
        return PipelineExecution(raw_url=raw_url, validation=validation)

    parsed = parse_url(raw_url, validation)
    checks = run_detection_checks(parsed)
    risk = calculate_risk(checks)
    report = generate_report(parsed, checks, risk)

    saved = None
    if data_dir is not None and STORAGE_AVAILABLE:
        saved = save_scan(report, data_dir=data_dir)

    return PipelineExecution(
        raw_url=raw_url,
        validation=validation,
        parsed=parsed,
        checks=checks,
        risk=risk,
        report=report,
        saved_successfully=saved,
    )


@pytest.fixture
def pipeline_runner():
    """Fixture providing pipeline execution function."""
    return run_pipeline


# ============================================================================
# Tier 1: Feature Coverage (F1 to F13)
# ============================================================================

class TestTier1FeatureCoverage:
    """Tier 1: Comprehensive verification of individual features (>= 5 tests per feature)."""

    # --- F1: URL Input Validation ---
    def test_f1_01_empty_string_rejected(self, pipeline_runner):
        res = pipeline_runner("")
        assert res.validation.is_valid is False
        assert res.validation.error_message is not None
        assert res.parsed is None
        assert res.report is None

    def test_f1_02_whitespace_only_rejected(self, pipeline_runner):
        res = pipeline_runner("   \t\r\n   ")
        assert res.validation.is_valid is False
        assert res.validation.error_message is not None
        assert res.parsed is None

    def test_f1_03_length_exceeds_4096_rejected(self, pipeline_runner):
        long_url = "https://example.com/" + "a" * 4090
        res = pipeline_runner(long_url)
        assert res.validation.is_valid is False
        assert "4096" in res.validation.error_message

    def test_f1_04_missing_hostname_rejected(self, pipeline_runner):
        res = pipeline_runner("http:///only-a-path/index.html")
        assert res.validation.is_valid is False
        assert res.validation.error_message is not None

    def test_f1_05_port_out_of_range_rejected(self, pipeline_runner):
        res = pipeline_runner("http://example.com:70000/path")
        assert res.validation.is_valid is False
        assert "port" in res.validation.error_message.lower()

    def test_f1_06_non_numeric_port_rejected(self, pipeline_runner):
        res = pipeline_runner("http://example.com:abc/path")
        assert res.validation.is_valid is False
        assert "port" in res.validation.error_message.lower()

    # --- F2: Scheme Handling ---
    def test_f2_01_explicit_https_accepted(self, pipeline_runner):
        res = pipeline_runner("https://example.com/safe")
        assert res.validation.is_valid is True
        assert res.validation.has_explicit_scheme is True
        assert res.validation.raw_scheme == "https"
        assert res.parsed.effective_scheme == "https"

    def test_f2_02_explicit_http_accepted(self, pipeline_runner):
        res = pipeline_runner("http://insecure-portal.example.com")
        assert res.validation.is_valid is True
        assert res.validation.has_explicit_scheme is True
        assert res.validation.raw_scheme == "http"
        assert res.parsed.effective_scheme == "http"

    def test_f2_03_missing_scheme_normalized_without_claiming_https(self, pipeline_runner):
        res = pipeline_runner("example.com/login")
        assert res.validation.is_valid is True
        assert res.validation.has_explicit_scheme is False
        assert res.validation.raw_scheme is None
        assert res.parsed.effective_scheme == "http"
        assert res.parsed.has_explicit_scheme is False
        # Missing scheme must not be penalized as HTTP (+10) nor praised as HTTPS
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is False
        assert c1.points == 0

    def test_f2_04_javascript_scheme_rejected(self, pipeline_runner):
        res = pipeline_runner("javascript:alert(document.cookie)")
        assert res.validation.is_valid is False
        assert "scheme" in res.validation.error_message.lower()

    def test_f2_05_file_scheme_rejected(self, pipeline_runner):
        res = pipeline_runner("file:///C:/Windows/System32/calc.exe")
        assert res.validation.is_valid is False
        assert "scheme" in res.validation.error_message.lower()

    def test_f2_06_ftp_scheme_rejected(self, pipeline_runner):
        res = pipeline_runner("ftp://ftp.example.com/files")
        assert res.validation.is_valid is False
        assert "scheme" in res.validation.error_message.lower()

    # --- F3: Component Parsing & Extraction ---
    def test_f3_01_standard_component_extraction(self, pipeline_runner):
        res = pipeline_runner("https://www.example.com/portal/index.html")
        assert res.parsed.hostname == "www.example.com"
        assert res.parsed.domain == "example.com"
        assert res.parsed.subdomain == "www"
        assert res.parsed.path == "/portal/index.html"

    def test_f3_02_query_string_extraction(self, pipeline_runner):
        res = pipeline_runner("https://shop.example.com/search?category=books&sort=asc")
        assert res.parsed.query == "category=books&sort=asc"
        assert res.parsed.path == "/search"

    def test_f3_03_fragment_extraction(self, pipeline_runner):
        res = pipeline_runner("https://docs.example.com/guide#installation")
        assert res.parsed.fragment == "installation"
        assert res.parsed.path == "/guide"

    def test_f3_04_custom_port_extraction(self, pipeline_runner):
        res = pipeline_runner("https://service.example.com:8443/api")
        assert res.parsed.port == 8443
        assert res.parsed.hostname == "service.example.com"

    def test_f3_05_userinfo_extraction_and_sanitization(self, pipeline_runner):
        res = pipeline_runner("http://admin:secret123@internal.example.com/panel")
        assert res.parsed.username == "admin"
        assert res.parsed.password == "secret123"
        assert "secret123" not in res.parsed.sanitized_url
        assert "admin@" not in res.parsed.sanitized_url

    def test_f3_06_punycode_idn_handling(self, pipeline_runner):
        res = pipeline_runner("http://xn--mnchen-3ya.de/welcome")
        assert res.parsed.is_idn is True
        assert res.parsed.ascii_hostname == "xn--mnchen-3ya.de"

    def test_f3_07_trailing_dot_and_case_normalization(self, pipeline_runner):
        res = pipeline_runner("HTTP://EXAMPLE.COM./WELCOME")
        assert res.parsed.hostname == "example.com"
        assert res.parsed.effective_scheme == "http"

    # --- F4: Check 1: HTTPS Detection ---
    def test_f4_01_http_explicit_penalized_10_points(self, pipeline_runner):
        res = pipeline_runner("http://insecure-site.org/")
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is True
        assert c1.points == 10

    def test_f4_02_https_explicit_awarded_zero_points(self, pipeline_runner):
        res = pipeline_runner("https://site.org/")
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is False
        assert c1.points == 0

    def test_f4_03_missing_scheme_not_penalized(self, pipeline_runner):
        res = pipeline_runner("site.org/home")
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is False
        assert c1.points == 0

    def test_f4_04_uppercase_http_penalized(self, pipeline_runner):
        res = pipeline_runner("HTTP://my-insecure-test.net/")
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is True
        assert c1.points == 10

    def test_f4_05_uppercase_https_not_penalized(self, pipeline_runner):
        res = pipeline_runner("HTTPS://my-clean-test.net/")
        c1 = res.get_check(CHECK_ID_HTTPS)
        assert c1.detected is False
        assert c1.points == 0

    # --- F5: Check 2: Length Analysis ---
    def test_f5_01_short_url_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://www.google.com")
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is False
        assert c2.points == 0

    def test_f5_02_medium_url_under_75_not_penalized(self, pipeline_runner):
        url = "https://example.org/about/team/contact-directory.html"
        assert len(url) <= 75
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is False
        assert c2.points == 0

    def test_f5_03_url_length_over_75_penalized_10_points(self, pipeline_runner):
        url = "https://phishing-portal-verification.com/update-security-credentials/login.php"
        assert len(url) > 75
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is True
        assert c2.points == 10

    def test_f5_04_url_length_99_penalized(self, pipeline_runner):
        url = "https://example.org/catalogs/internal/departments/operations/files/documents/archive/view.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is True
        assert c2.points == 10

    def test_f5_05_url_length_extreme_penalized(self, pipeline_runner):
        url = "https://example.com/static/" + "x" * 120
        assert len(url) == 147
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is True
        assert c2.points == 10

    # --- F6: Check 3: IP Address Detection ---
    def test_f6_01_ipv4_host_penalized_25_points(self, pipeline_runner):
        res = pipeline_runner("http://192.0.2.1/home")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is True
        assert c3.points == 25
        assert res.parsed.is_ip is True

    def test_f6_02_ipv4_with_port_penalized(self, pipeline_runner):
        res = pipeline_runner("http://192.168.1.105:8080/test")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is True
        assert c3.points == 25

    def test_f6_03_ipv6_host_penalized(self, pipeline_runner):
        res = pipeline_runner("http://[2001:db8::1]/index.html")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is True
        assert c3.points == 25
        assert res.parsed.is_ip is True

    def test_f6_04_ipv6_loopback_with_port_penalized(self, pipeline_runner):
        res = pipeline_runner("http://[::1]:9000/api")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is True
        assert c3.points == 25

    def test_f6_05_domain_with_numbers_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://web2.server34.example.com/test")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is False
        assert c3.points == 0
        assert res.parsed.is_ip is False

    def test_f6_06_domain_resembling_ip_nip_io_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://192-168-1-1.nip.io/main")
        c3 = res.get_check(CHECK_ID_IP)
        assert c3.detected is False
        assert c3.points == 0

    # --- F7: Check 4: Suspicious Keywords ---
    def test_f7_01_single_keyword_login_penalized_15_points(self, pipeline_runner):
        res = pipeline_runner("https://example.com/login")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15

    def test_f7_02_keyword_in_hostname_banking_detected(self, pipeline_runner):
        res = pipeline_runner("https://banking.example.com/dashboard")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15

    def test_f7_03_multiple_keywords_flat_15_points(self, pipeline_runner):
        res = pipeline_runner("https://example.com/verify/account/password-reset")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15  # Flat, non-repeating points

    def test_f7_04_repeated_keyword_counted_once(self, pipeline_runner):
        res = pipeline_runner("https://login.example.com/login/auth/login.php")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15

    def test_f7_05_case_insensitive_keyword_matching(self, pipeline_runner):
        res = pipeline_runner("https://crypto.example.com/WALLET/CONFIRM")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15

    def test_f7_06_other_keywords_in_13_set_detected(self, pipeline_runner):
        res = pipeline_runner("https://example.com/free/bonus/support/signin/update")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is True
        assert c4.points == 15

    def test_f7_07_clean_documentation_url_no_keywords(self, pipeline_runner):
        res = pipeline_runner("https://docs.python.org/3/library/urllib.parse.html")
        c4 = res.get_check(CHECK_ID_KEYWORDS)
        assert c4.detected is False
        assert c4.points == 0

    # --- F8: Check 5: Special Characters / @ in Authority ---
    def test_f8_01_at_symbol_in_authority_penalized_15_points(self, pipeline_runner):
        res = pipeline_runner("http://paypal.com@attacker-site.com/auth")
        c5 = res.get_check(CHECK_ID_SPECIAL_CHARS)
        assert c5.detected is True
        assert c5.points == 15

    def test_f8_02_userinfo_credentials_penalized_15_points(self, pipeline_runner):
        res = pipeline_runner("http://admin:pass123@192.168.1.1/admin")
        c5 = res.get_check(CHECK_ID_SPECIAL_CHARS)
        assert c5.detected is True
        assert c5.points == 15

    def test_f8_03_at_symbol_in_query_parameter_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://example.com/search?user=john@test.com")
        c5 = res.get_check(CHECK_ID_SPECIAL_CHARS)
        assert c5.detected is False
        assert c5.points == 0

    def test_f8_04_at_symbol_in_fragment_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://example.com/page#contact@section")
        c5 = res.get_check(CHECK_ID_SPECIAL_CHARS)
        assert c5.detected is False
        assert c5.points == 0

    def test_f8_05_clean_authority_without_userinfo_clean(self, pipeline_runner):
        res = pipeline_runner("https://example.com/dashboard/home")
        c5 = res.get_check(CHECK_ID_SPECIAL_CHARS)
        assert c5.detected is False
        assert c5.points == 0

    # --- F9: Check 6: Excessive Hyphens ---
    def test_f9_01_three_hyphens_in_hostname_penalized_10_points(self, pipeline_runner):
        res = pipeline_runner("https://my-secure-bank-login.com/test")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is True
        assert c6.points == 10

    def test_f9_02_five_hyphens_in_hostname_penalized_10_points(self, pipeline_runner):
        res = pipeline_runner("https://a-b-c-d-e-f.com/home")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is True
        assert c6.points == 10

    def test_f9_03_single_hyphen_in_hostname_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://my-domain.com/index")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    def test_f9_04_two_hyphens_in_hostname_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://pay-pal-portal.com/home")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    def test_f9_05_hyphens_in_path_strictly_ignored(self, pipeline_runner):
        res = pipeline_runner("https://example.com/a-b-c-d-e-f")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    # --- F10: Check 7: Subdomain Analysis ---
    def test_f10_01_four_subdomain_labels_penalized_15_points(self, pipeline_runner):
        res = pipeline_runner("https://a.b.c.d.example.com/home")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is True
        assert c7.points == 15

    def test_f10_02_five_subdomain_labels_penalized_15_points(self, pipeline_runner):
        res = pipeline_runner("https://p1.p2.p3.p4.p5.example.org/test")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is True
        assert c7.points == 15

    def test_f10_03_single_subdomain_label_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://www.example.com/about")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    def test_f10_04_three_subdomain_labels_not_penalized(self, pipeline_runner):
        res = pipeline_runner("https://x.y.z.example.com/test")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    def test_f10_05_cctld_four_subdomains_correctly_penalized(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.s3.s4.service.co.uk/api")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is True
        assert c7.points == 15

    def test_f10_06_ip_address_host_bypasses_subdomain_check(self, pipeline_runner):
        res = pipeline_runner("http://192.168.1.1/admin")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    # --- F11: Risk Scoring & Capping ---
    def test_f11_01_clean_url_scores_zero(self, pipeline_runner):
        res = pipeline_runner("https://example.com/")
        assert res.risk.raw_score == 0
        assert res.risk.total_score == 0

    def test_f11_02_single_http_rule_scores_ten(self, pipeline_runner):
        res = pipeline_runner("http://example.com/")
        assert res.risk.raw_score == 10
        assert res.risk.total_score == 10

    def test_f11_03_sum_of_multiple_rules_accumulates(self, pipeline_runner):
        # HTTP (10) + Length > 75 (10) + Keyword 'login' (15) = 35
        url = "http://example.com/login?token=abc" + "x" * 60
        assert len(url) > 75
        res = pipeline_runner(url)
        assert res.risk.total_score == 35

    def test_f11_04_high_cumulative_score_without_capping(self, pipeline_runner):
        # HTTP (10) + Length (10) + IP (25) + Keyword 'login' (15) + SpecialChar '@' (15) = 75
        url = "http://user@192.168.1.1/login?token=" + "z" * 60
        assert len(url) > 75
        res = pipeline_runner(url)
        assert res.risk.total_score == 75

    def test_f11_05_synthetic_all_seven_rules_sum_to_100(self):
        checks = [
            CheckResult(check_id="check_https", check_name="HTTPS", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_length", check_name="Length", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_ip", check_name="IP", detected=True, points=25, explanation="", evidence=""),
            CheckResult(check_id="check_keywords", check_name="Keywords", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="check_special_chars", check_name="SpecialChar", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="check_hyphens", check_name="Hyphens", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_subdomains", check_name="Subdomains", detected=True, points=15, explanation="", evidence=""),
        ]
        risk = calculate_risk(checks)
        assert risk.raw_score == 100
        assert risk.total_score == 100
        assert risk.risk_level == RiskLevel.HIGH

    def test_f11_06_score_capping_over_100_strictly_enforced(self):
        # Synthetic checks exceeding 100
        checks = [
            CheckResult(check_id="c1", check_name="C1", detected=True, points=50, explanation="", evidence=""),
            CheckResult(check_id="c2", check_name="C2", detected=True, points=40, explanation="", evidence=""),
            CheckResult(check_id="c3", check_name="C3", detected=True, points=35, explanation="", evidence=""),
        ]
        risk = calculate_risk(checks)
        assert risk.raw_score == 125
        assert risk.total_score == 100
        assert risk.risk_level == RiskLevel.HIGH

    # --- F12: Risk Classification ---
    def test_f12_01_classify_score_0_low_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=False, points=0, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.LOW
        assert risk.badge_color == "#10B981"

    def test_f12_02_classify_score_10_low_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=10, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.LOW
        assert risk.badge_color == "#10B981"

    def test_f12_03_classify_score_20_low_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=20, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.LOW
        assert risk.badge_color == "#10B981"

    def test_f12_04_classify_score_21_medium_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=21, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.MEDIUM
        assert risk.badge_color == "#F59E0B"

    def test_f12_05_classify_score_50_medium_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=50, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.MEDIUM
        assert risk.badge_color == "#F59E0B"

    def test_f12_06_classify_score_51_high_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=51, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.HIGH
        assert risk.badge_color == "#EF4444"

    def test_f12_07_classify_score_100_high_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=100, explanation="", evidence="")])
        assert risk.risk_level == RiskLevel.HIGH
        assert risk.badge_color == "#EF4444"

    # --- F13: Report Generation & Storage Redaction ---
    def test_f13_01_all_14_report_fields_populated(self, pipeline_runner):
        res = pipeline_runner("https://www.example.com/test")
        rep = res.report
        assert rep.original_url == "https://www.example.com/test"
        assert rep.normalized_hostname == "www.example.com"
        assert rep.validation_status is not None
        assert rep.protocol_info is not None
        assert rep.url_length == len("https://www.example.com/test")
        assert rep.ip_detection is not None
        assert rep.keyword_detection is not None
        assert rep.special_char_detection is not None
        assert rep.hyphen_analysis is not None
        assert rep.subdomain_analysis is not None
        assert len(rep.individual_points) == 7
        assert rep.total_risk_score == 0
        assert rep.risk_classification == "LOW RISK"
        assert len(rep.detected_explanations) > 0
        assert rep.recommendation is not None
        assert rep.sanitized_url is not None
        assert rep.badge_color == "#10B981"

    def test_f13_02_report_ip_and_port_formatting(self, pipeline_runner):
        res = pipeline_runner("http://192.168.1.10:8080/portal")
        rep = res.report
        assert rep.normalized_hostname == "192.168.1.10"
        assert rep.total_risk_score == 35  # HTTP(10) + IP(25)
        assert rep.risk_classification == "MEDIUM RISK"

    def test_f13_03_report_sensitive_query_parameters_masked(self, pipeline_runner):
        res = pipeline_runner("https://bank.com/transfer?account=98765&pin=1234")
        assert "98765" not in res.report.sanitized_url
        assert "1234" not in res.report.sanitized_url

    def test_f13_04_report_authority_credentials_masked(self, pipeline_runner):
        res = pipeline_runner("http://admin:secret@portal.com/login")
        assert "secret" not in res.report.sanitized_url
        assert "admin@" not in res.report.sanitized_url

    def test_f13_05_report_fragment_stripped_from_sanitized_url(self, pipeline_runner):
        res = pipeline_runner("https://example.com/docs#sensitive-token-abc")
        assert "sensitive-token-abc" not in res.report.sanitized_url


# ============================================================================
# Tier 2: Boundary Value Analysis (B1 to B8)
# ============================================================================

class TestTier2BoundaryValueAnalysis:
    """Tier 2: Boundary value analysis across 8 boundary groups (>= 5 tests per group)."""

    # --- B1: URL Length Boundary (75 vs 76 Chars) ---
    def test_b1_01_length_74_chars_no_penalty(self, pipeline_runner):
        url = "https://example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"
        assert len(url) == 74
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is False
        assert c2.points == 0

    def test_b1_02_length_75_chars_exact_boundary_no_penalty(self, pipeline_runner):
        url = "https://example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrs"
        assert len(url) == 75
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is False
        assert c2.points == 0

    def test_b1_03_length_76_chars_exact_boundary_penalized(self, pipeline_runner):
        url = "https://example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst"
        assert len(url) == 76
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is True
        assert c2.points == 10

    def test_b1_04_length_77_chars_penalized(self, pipeline_runner):
        url = "https://example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu"
        assert len(url) == 77
        res = pipeline_runner(url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is True
        assert c2.points == 10

    def test_b1_05_schemeless_length_75_evaluated_on_raw_input(self, pipeline_runner):
        raw_url = "example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu012345"
        assert len(raw_url) == 75
        res = pipeline_runner(raw_url)
        c2 = res.get_check(CHECK_ID_LENGTH)
        assert c2.detected is False
        assert c2.points == 0

    # --- B2: Hostname Hyphens Boundary (2 vs 3 Hyphens) ---
    def test_b2_01_one_hyphen_no_penalty(self, pipeline_runner):
        res = pipeline_runner("https://my-domain.com/")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    def test_b2_02_two_hyphens_exact_boundary_no_penalty(self, pipeline_runner):
        res = pipeline_runner("https://my-web-portal.com/")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    def test_b2_03_three_hyphens_exact_boundary_penalized(self, pipeline_runner):
        res = pipeline_runner("https://my-web-portal-service.com/")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is True
        assert c6.points == 10

    def test_b2_04_four_hyphens_penalized(self, pipeline_runner):
        res = pipeline_runner("https://my-web-portal-service-auth.com/")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is True
        assert c6.points == 10

    def test_b2_05_path_hyphens_do_not_count_toward_hostname_hyphens(self, pipeline_runner):
        res = pipeline_runner("https://my-site.com/path-one-two-three-four-five")
        c6 = res.get_check(CHECK_ID_HYPHENS)
        assert c6.detected is False
        assert c6.points == 0

    # --- B3: Subdomain Labels Boundary (3 vs 4 Subdomains) ---
    def test_b3_01_two_subdomains_no_penalty(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.example.com/")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    def test_b3_02_three_subdomains_exact_boundary_no_penalty(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.s3.example.com/")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    def test_b3_03_four_subdomains_exact_boundary_penalized(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.s3.s4.example.com/")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is True
        assert c7.points == 15

    def test_b3_04_cctld_three_subdomains_no_penalty(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.s3.example.co.uk/")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is False
        assert c7.points == 0

    def test_b3_05_cctld_four_subdomains_penalized(self, pipeline_runner):
        res = pipeline_runner("https://s1.s2.s3.s4.example.co.uk/")
        c7 = res.get_check(CHECK_ID_SUBDOMAINS)
        assert c7.detected is True
        assert c7.points == 15

    # --- B4: Risk Score Boundary (20 vs 21 Points) ---
    def test_b4_01_score_10_is_low_risk(self, pipeline_runner):
        res = pipeline_runner("http://example.com/")
        assert res.risk.total_score == 10
        assert res.risk.risk_level == RiskLevel.LOW

    def test_b4_02_score_20_exact_boundary_is_low_risk(self, pipeline_runner):
        # HTTP (10) + Length 76 (10) = 20
        url = "http://example.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu"
        assert len(url) == 76
        res = pipeline_runner(url)
        assert res.risk.total_score == 20
        assert res.risk.risk_level == RiskLevel.LOW

    def test_b4_03_score_21_exact_boundary_is_medium_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=21, explanation="", evidence="")])
        assert risk.total_score == 21
        assert risk.risk_level == RiskLevel.MEDIUM

    def test_b4_04_score_25_is_medium_risk(self, pipeline_runner):
        # HTTPS (0) + IP (25) = 25
        res = pipeline_runner("https://192.168.1.1/")
        assert res.risk.total_score == 25
        assert res.risk.risk_level == RiskLevel.MEDIUM

    def test_b4_05_score_20_schemeless_boundary_is_low_risk(self, pipeline_runner):
        # Schemeless (0 HTTP) + Length 76 (10) + Hyphens 3 (10) = 20
        raw = "a-b-c-d.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"
        assert len(raw) == 60  # Wait, len must be 76
        raw76 = "a-b-c-d.com/abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl0123456789abcdefgh"
        assert len(raw76) == 78  # let's construct exactly 76
        prefix = "a-b-c-d.com/"  # 12 chars
        raw_exact_76 = prefix + "x" * (76 - len(prefix))
        assert len(raw_exact_76) == 76
        res = pipeline_runner(raw_exact_76)
        assert res.risk.total_score == 20
        assert res.risk.risk_level == RiskLevel.LOW

    # --- B5: Risk Score Boundary (50 vs 51 Points) ---
    def test_b5_01_score_45_is_medium_risk(self, pipeline_runner):
        # HTTP (10) + Length > 75 (10) + Keyword 'login' (15) + Hyphens 3 (10) = 45
        prefix = "http://a-b-c-d.com/login/"
        url = prefix + "x" * (78 - len(prefix))
        assert len(url) == 78
        res = pipeline_runner(url)
        assert res.risk.total_score == 45
        assert res.risk.risk_level == RiskLevel.MEDIUM

    def test_b5_02_score_50_exact_boundary_is_medium_risk(self, pipeline_runner):
        # HTTP (10) + IP (25) + Keyword 'login' (15) = 50
        res = pipeline_runner("http://192.168.1.1/login")
        assert len("http://192.168.1.1/login") <= 75
        assert res.risk.total_score == 50
        assert res.risk.risk_level == RiskLevel.MEDIUM

    def test_b5_03_score_51_exact_boundary_is_high_risk(self):
        risk = calculate_risk([CheckResult(check_id="c", check_name="c", detected=True, points=51, explanation="", evidence="")])
        assert risk.total_score == 51
        assert risk.risk_level == RiskLevel.HIGH

    def test_b5_04_score_50_alternative_combo_is_medium_risk(self, pipeline_runner):
        # HTTP (10) + IP (25) + SpecialChar '@' (15) = 50
        res = pipeline_runner("http://client@192.168.1.1/")
        assert len("http://client@192.168.1.1/") <= 75
        assert res.risk.total_score == 50
        assert res.risk.risk_level == RiskLevel.MEDIUM

    def test_b5_05_score_60_is_high_risk(self, pipeline_runner):
        # HTTP (10) + Length > 75 (10) + IP (25) + Keyword 'login' (15) = 60
        url = "http://192.168.1.1/login/session/auth/verify/customer/account/credentials.html"
        assert len(url) == 78
        res = pipeline_runner(url)
        assert res.risk.total_score == 60
        assert res.risk.risk_level == RiskLevel.HIGH

    # --- B6: Score Capping (> 100 Points) ---
    def test_b6_01_score_real_world_75_high_risk(self, pipeline_runner):
        # HTTP (10) + Length (10) + IP (25) + Keyword 'login' (15) + SpecialChar (15) = 75
        url = "http://user@192.168.1.1/login?token=" + "a" * 50
        assert len(url) > 75
        res = pipeline_runner(url)
        assert res.risk.total_score == 75
        assert res.risk.risk_level == RiskLevel.HIGH

    def test_b6_02_score_real_world_6_rules_75_high_risk(self, pipeline_runner):
        # HTTP (10) + Length (10) + Keyword (15) + SpecialChar (15) + Hyphens (10) + Subdomains (15) = 75
        url = "http://user@a-b-c-d.s1.s2.s3.s4.example.com/login?token=" + "x" * 50
        assert len(url) > 75
        res = pipeline_runner(url)
        assert res.risk.total_score == 75
        assert res.risk.risk_level == RiskLevel.HIGH

    def test_b6_03_score_all_7_rules_exactly_100_high_risk(self):
        checks = [
            CheckResult(check_id="c1", check_name="HTTPS", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="c2", check_name="Length", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="c3", check_name="IP", detected=True, points=25, explanation="", evidence=""),
            CheckResult(check_id="c4", check_name="Keywords", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="c5", check_name="SpecialChar", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="c6", check_name="Hyphens", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="c7", check_name="Subdomains", detected=True, points=15, explanation="", evidence=""),
        ]
        risk = calculate_risk(checks)
        assert risk.raw_score == 100
        assert risk.total_score == 100
        assert risk.risk_level == RiskLevel.HIGH

    def test_b6_04_score_capping_105_clamped_to_100(self):
        checks = [
            CheckResult(check_id="c1", check_name="c1", detected=True, points=70, explanation="", evidence=""),
            CheckResult(check_id="c2", check_name="c2", detected=True, points=35, explanation="", evidence=""),
        ]
        risk = calculate_risk(checks)
        assert risk.raw_score == 105
        assert risk.total_score == 100
        assert risk.risk_level == RiskLevel.HIGH

    def test_b6_05_score_capping_150_clamped_to_100(self):
        checks = [
            CheckResult(check_id="c1", check_name="c1", detected=True, points=100, explanation="", evidence=""),
            CheckResult(check_id="c2", check_name="c2", detected=True, points=50, explanation="", evidence=""),
        ]
        risk = calculate_risk(checks)
        assert risk.raw_score == 150
        assert risk.total_score == 100
        assert risk.risk_level == RiskLevel.HIGH

    # --- B7: 0 Risk Point Clean URLs Baseline ---
    def test_b7_01_clean_google_search_zero_points(self, pipeline_runner):
        res = pipeline_runner("https://www.google.com/")
        res.assert_success(
            expected_hostname="www.google.com",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )

    def test_b7_02_clean_wikipedia_zero_points(self, pipeline_runner):
        res = pipeline_runner("https://en.wikipedia.org/wiki/Computer_science")
        res.assert_success(
            expected_hostname="en.wikipedia.org",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )

    def test_b7_03_clean_schemeless_repo_zero_points(self, pipeline_runner):
        res = pipeline_runner("github.com/python/cpython")
        res.assert_success(
            expected_hostname="github.com",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )

    def test_b7_04_clean_catalog_query_zero_points(self, pipeline_runner):
        res = pipeline_runner("https://example.org/catalog?item=456&color=blue")
        res.assert_success(
            expected_hostname="example.org",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )

    def test_b7_05_clean_documentation_fragment_zero_points(self, pipeline_runner):
        res = pipeline_runner("https://docs.pytest.org/en/latest/#documentation")
        res.assert_success(
            expected_hostname="docs.pytest.org",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )

    # --- B8: Port Bounds (0, 80, 443, 65535, 65536) ---
    def test_b8_01_port_0_valid(self, pipeline_runner):
        res = pipeline_runner("http://example.com:0/path")
        assert res.validation.is_valid is True
        assert res.parsed.port == 0

    def test_b8_02_port_80_valid(self, pipeline_runner):
        res = pipeline_runner("http://example.com:80/path")
        assert res.validation.is_valid is True
        assert res.parsed.port == 80

    def test_b8_03_port_443_valid(self, pipeline_runner):
        res = pipeline_runner("https://example.com:443/path")
        assert res.validation.is_valid is True
        assert res.parsed.port == 443

    def test_b8_04_port_65535_valid(self, pipeline_runner):
        res = pipeline_runner("http://example.com:65535/path")
        assert res.validation.is_valid is True
        assert res.parsed.port == 65535

    def test_b8_05_port_65536_invalid(self, pipeline_runner):
        res = pipeline_runner("http://example.com:65536/path")
        assert res.validation.is_valid is False
        assert "port" in res.validation.error_message.lower()


# ============================================================================
# Tier 3: Pairwise Combinations (19 Combinations + 2 Boundary Tests)
# ============================================================================

class TestTier3PairwiseCombinations:
    """Tier 3: Pairwise combinations verifying orthogonal rule accumulation and isolation."""

    def test_tier3_pair_01_http_and_length(self, pipeline_runner):
        url = "http://example.com/a/very/long/path/that/exceeds/seventy/five/characters/in/total/length/index.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="example.com",
            expected_score=20,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_LENGTH},
        )

    def test_tier3_pair_02_http_and_ip(self, pipeline_runner):
        url = "http://192.168.1.1/index.html"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="192.168.1.1",
            expected_score=35,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_IP},
        )

    def test_tier3_pair_03_http_and_keywords(self, pipeline_runner):
        url = "http://myportal.com/login"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="myportal.com",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_KEYWORDS},
        )

    def test_tier3_pair_04_http_and_special_chars(self, pipeline_runner):
        url = "http://client@service.org/main"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="service.org",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_SPECIAL_CHARS},
        )

    def test_tier3_pair_05_http_and_hyphens(self, pipeline_runner):
        url = "http://my-news-media-feed.com/index"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="my-news-media-feed.com",
            expected_score=20,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_HYPHENS},
        )

    def test_tier3_pair_06_http_and_subdomains(self, pipeline_runner):
        url = "http://w.x.y.z.example.org/home"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="w.x.y.z.example.org",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_SUBDOMAINS},
        )

    def test_tier3_pair_07_length_and_ip(self, pipeline_runner):
        url = "https://192.168.1.1/deep/nested/path/to/resource/file/document/archive/data/test/content/report.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="192.168.1.1",
            expected_score=35,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_LENGTH, CHECK_ID_IP},
        )

    def test_tier3_pair_08_length_and_keywords(self, pipeline_runner):
        url = "https://example.com/customer/authentication/service/user/login/credential/entry/screen/flow/target.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="example.com",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_LENGTH, CHECK_ID_KEYWORDS},
        )

    def test_tier3_pair_09_length_and_special_chars(self, pipeline_runner):
        url = "https://legituser@example.org/catalogs/internal/departments/operations/files/documents/archive/view.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="example.org",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_LENGTH, CHECK_ID_SPECIAL_CHARS},
        )

    def test_tier3_pair_10_length_and_hyphens(self, pipeline_runner):
        url = "https://alpha-beta-gamma-delta.org/departments/engineering/software/platform/services/overview.html"
        assert len(url) > 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="alpha-beta-gamma-delta.org",
            expected_score=20,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks={CHECK_ID_LENGTH, CHECK_ID_HYPHENS},
        )

    def test_tier3_pair_11_length_and_subdomains(self, pipeline_runner):
        url = "https://dev.stage.test.preview.example.org/applications/modules/network/diagnostics/results.html"
        assert len(url) == 96
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="dev.stage.test.preview.example.org",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_LENGTH, CHECK_ID_SUBDOMAINS},
        )

    def test_tier3_pair_12_ip_and_keywords(self, pipeline_runner):
        url = "https://10.0.0.5/user/verify"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="10.0.0.5",
            expected_score=40,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_IP, CHECK_ID_KEYWORDS},
        )

    def test_tier3_pair_13_ip_and_special_chars(self, pipeline_runner):
        url = "https://visitor@172.16.0.1/dashboard"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="172.16.0.1",
            expected_score=40,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_IP, CHECK_ID_SPECIAL_CHARS},
        )

    def test_tier3_pair_14_keywords_and_special_chars(self, pipeline_runner):
        url = "https://admin@example.org/account"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="example.org",
            expected_score=30,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_KEYWORDS, CHECK_ID_SPECIAL_CHARS},
        )

    def test_tier3_pair_15_keywords_and_hyphens(self, pipeline_runner):
        url = "https://fast-direct-express-access.org/wallet"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="fast-direct-express-access.org",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_KEYWORDS, CHECK_ID_HYPHENS},
        )

    def test_tier3_pair_16_keywords_and_subdomains(self, pipeline_runner):
        url = "https://ns1.corp.infra.cloud.example.net/signin"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="ns1.corp.infra.cloud.example.net",
            expected_score=30,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_KEYWORDS, CHECK_ID_SUBDOMAINS},
        )

    def test_tier3_pair_17_special_chars_and_hyphens(self, pipeline_runner):
        url = "https://member@north-south-east-west.com/profile"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="north-south-east-west.com",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_SPECIAL_CHARS, CHECK_ID_HYPHENS},
        )

    def test_tier3_pair_18_special_chars_and_subdomains(self, pipeline_runner):
        url = "https://guest@lab.node.cluster.edge.example.org/view"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="lab.node.cluster.edge.example.org",
            expected_score=30,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_SPECIAL_CHARS, CHECK_ID_SUBDOMAINS},
        )

    def test_tier3_pair_19_hyphens_and_subdomains(self, pipeline_runner):
        url = "https://a.b.c.d.tech-media-news-hub.com/page"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="a.b.c.d.tech-media-news-hub.com",
            expected_score=25,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HYPHENS, CHECK_ID_SUBDOMAINS},
        )

    def test_tier3_triple_boundary_50_medium_risk(self, pipeline_runner):
        # HTTP (10) + IP (25) + Keyword 'verify' (15) = 50 -> exact upper boundary of MEDIUM RISK
        url = "http://10.0.0.1/verify"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="10.0.0.1",
            expected_score=50,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_IP, CHECK_ID_KEYWORDS},
        )

    def test_tier3_triple_boundary_55_high_risk(self, pipeline_runner):
        # IP (25) + Keyword 'verify' (15) + SpecialChar '@' (15) = 55 -> crosses into HIGH RISK
        url = "https://user@10.0.0.1/verify"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="10.0.0.1",
            expected_score=55,
            expected_level=RiskLevel.HIGH,
            expected_triggered_checks={CHECK_ID_IP, CHECK_ID_KEYWORDS, CHECK_ID_SPECIAL_CHARS},
        )


# ============================================================================
# Tier 4: Real-World Phishing & Legitimate Scenarios (Scenarios 1 to 9)
# ============================================================================

class TestTier4RealWorldPhishingScenarios:
    """Tier 4: Verification of 9 realistic phishing and legitimate application scenarios."""

    def test_tier4_scenario_1_legitimate_search_engine(self, pipeline_runner, tmp_path):
        url = "https://www.google.com/search?q=cybersecurity"
        res = pipeline_runner(url, data_dir=tmp_path)
        res.assert_success(
            expected_hostname="www.google.com",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )
        assert "q=cybersecurity" not in res.report.sanitized_url
        assert res.report.sanitized_url == "https://www.google.com/search"

    def test_tier4_scenario_2_unencrypted_corporate_portal(self, pipeline_runner):
        url = "http://intranet.company.local/"
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="intranet.company.local",
            expected_score=10,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks={CHECK_ID_HTTPS},
        )

    def test_tier4_scenario_3_direct_ip_phishing_link(self, pipeline_runner):
        # Primary: HTTP (10) + IP (25) + Keywords 'login','bank' (15) = 50
        url = "http://192.168.1.105:8080/bank/login"
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="192.168.1.105",
            expected_score=50,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_IP, CHECK_ID_KEYWORDS},
        )

        # Extended: HTTP (10) + Length (10) + IP (25) + Keywords (15) = 60 (HIGH RISK)
        url_extended = "http://192.168.1.105:8080/bank/login/session/auth/verify/customer/account/credentials.html"
        assert len(url_extended) > 75
        res_ext = pipeline_runner(url_extended)
        res_ext.assert_success(
            expected_hostname="192.168.1.105",
            expected_score=60,
            expected_level=RiskLevel.HIGH,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_LENGTH, CHECK_ID_IP, CHECK_ID_KEYWORDS},
        )

    def test_tier4_scenario_4_brand_spoofing_with_at(self, pipeline_runner):
        # 3-Hyphen Variant: HTTP (10) + Keywords (15) + SpecialChar '@' (15) + Hyphens (10) = 50
        url = "http://paypal.com@account-verify-update-alert.phish.com/auth"
        assert len(url) <= 75
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="account-verify-update-alert.phish.com",
            expected_score=50,
            expected_level=RiskLevel.MEDIUM,
            expected_triggered_checks={CHECK_ID_HTTPS, CHECK_ID_KEYWORDS, CHECK_ID_SPECIAL_CHARS, CHECK_ID_HYPHENS},
        )
        assert "paypal.com@" not in res.report.sanitized_url

        # Extended High-Risk variant (> 75 chars -> 60 pts -> HIGH RISK)
        url_ext = "http://paypal.com@account-verify-update-alert.phish.com/auth/login-verification-redirect"
        assert len(url_ext) == 88
        res_ext = pipeline_runner(url_ext)
        assert res_ext.risk.total_score == 60
        assert res_ext.risk.risk_level == RiskLevel.HIGH

    def test_tier4_scenario_5_complex_chained_phishing_url(self, pipeline_runner):
        # Extended URL: HTTP (10) + Length (10) + Hyphens (10) + Subdomains (15) + Keywords (15) = 60
        url = "http://secure.login.banking.portal.my-bank-update-alert.com/signin/customer/verification"
        assert len(url) == 88
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="secure.login.banking.portal.my-bank-update-alert.com",
            expected_score=60,
            expected_level=RiskLevel.HIGH,
            expected_triggered_checks={
                CHECK_ID_HTTPS,
                CHECK_ID_LENGTH,
                CHECK_ID_KEYWORDS,
                CHECK_ID_HYPHENS,
                CHECK_ID_SUBDOMAINS,
            },
        )

    def test_tier4_scenario_6_scheme_less_input(self, pipeline_runner):
        url = "github.com/torvalds/linux"
        res = pipeline_runner(url)
        res.assert_success(
            expected_hostname="github.com",
            expected_score=0,
            expected_level=RiskLevel.LOW,
            expected_triggered_checks=set(),
        )
        assert res.validation.has_explicit_scheme is False
        assert res.parsed.effective_scheme == "http"

    def test_tier4_scenario_7_malformed_url_rejection(self, pipeline_runner):
        malformed_urls = [
            "javascript:alert('xss')",
            "example.com:99999",
            "",
            "   ",
            "file:///etc/passwd",
            "http://",
            "http://example.com:abc",
        ]
        for bad_url in malformed_urls:
            res = pipeline_runner(bad_url)
            assert res.validation.is_valid is False
            assert res.parsed is None
            assert res.risk is None
            assert res.report is None

    def test_tier4_scenario_8_privacy_redaction_verification(self, pipeline_runner, tmp_path):
        url = "https://portal.bank.com/transfer?account=12345&otp=9999#confirm"
        res = pipeline_runner(url, data_dir=tmp_path)
        assert res.validation.is_valid is True
        assert res.report.sanitized_url == "https://portal.bank.com/transfer"
        assert "12345" not in res.report.sanitized_url
        assert "9999" not in res.report.sanitized_url
        assert "confirm" not in res.report.sanitized_url

        if STORAGE_AVAILABLE:
            csv_path = tmp_path / "scan_history.csv"
            if csv_path.exists():
                content = csv_path.read_text(encoding="utf-8")
                assert "12345" not in content
                assert "9999" not in content
                assert "otp" not in content
                assert "confirm" not in content

    def test_tier4_scenario_9_maximum_score_stress_test(self, pipeline_runner):
        # Trigger 6 rules simultaneously via URL:
        # HTTP (10) + Length (10) + Keywords (15) + SpecialChar '@' (15) + Hyphens (10) + Subdomains (15) = 75
        url = "http://userinfo@a.b.c.d.secure-login-bank-portal.com/update/verify-credentials-session-token-long-url-stress-test"
        assert len(url) > 75
        res = pipeline_runner(url)
        assert res.risk.total_score == 75
        assert res.risk.risk_level == RiskLevel.HIGH

        # Verify strict capping with synthetic 7-check configuration exceeding 100
        synthetic_all_checks = [
            CheckResult(check_id="check_https", check_name="HTTPS", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_length", check_name="Length", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_ip", check_name="IP", detected=True, points=25, explanation="", evidence=""),
            CheckResult(check_id="check_keywords", check_name="Keywords", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="check_special_chars", check_name="SpecialChar", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="check_hyphens", check_name="Hyphens", detected=True, points=10, explanation="", evidence=""),
            CheckResult(check_id="check_subdomains", check_name="Subdomains", detected=True, points=15, explanation="", evidence=""),
            CheckResult(check_id="check_bonus", check_name="Extra", detected=True, points=30, explanation="", evidence=""),
        ]
        stress_risk = calculate_risk(synthetic_all_checks)
        assert stress_risk.raw_score == 130
        assert stress_risk.total_score == 100
        assert stress_risk.risk_level == RiskLevel.HIGH


# ============================================================================
# Storage and Persistence E2E Tests (M2 Integration)
# ============================================================================

@pytest.mark.skipif(not STORAGE_AVAILABLE, reason="M2 storage/history_manager.py module pending")
class TestStorageAndPersistenceE2E:
    """Storage & persistence E2E tests guarded by STORAGE_AVAILABLE flag."""

    def test_storage_save_and_retrieve_scan_record(self, pipeline_runner, tmp_path):
        res = pipeline_runner("https://example.com/test", data_dir=tmp_path)
        assert res.saved_successfully is True

        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        record = history[0]
        assert record["hostname"] == "example.com"
        assert int(record["risk_score"]) == 0
        assert record["risk_classification"] == "LOW RISK"
        assert "scan_date_time" in record

    def test_storage_clear_history_clears_records(self, pipeline_runner, tmp_path):
        pipeline_runner("https://example.com/first", data_dir=tmp_path)
        pipeline_runner("https://example.com/second", data_dir=tmp_path)
        assert len(get_history(data_dir=tmp_path)) == 2

        clear_success = clear_history(data_dir=tmp_path)
        assert clear_success is True
        assert len(get_history(data_dir=tmp_path)) == 0

    def test_storage_export_csv_formatting_and_headers(self, pipeline_runner, tmp_path):
        pipeline_runner("https://first-test.com/", data_dir=tmp_path)
        pipeline_runner("http://second-test.com/", data_dir=tmp_path)

        csv_text = export_history_csv(data_dir=tmp_path)
        assert "scan_date_time,hostname,risk_score,risk_classification" in csv_text
        assert "first-test.com" in csv_text
        assert "second-test.com" in csv_text

    def test_storage_nonexistent_directory_handled_gracefully(self, tmp_path):
        non_existent = tmp_path / "does_not_exist"
        history = get_history(data_dir=non_existent)
        assert history == []

    def test_storage_empty_csv_file_handled_gracefully(self, tmp_path):
        csv_file = tmp_path / "scan_history.csv"
        csv_file.write_text("", encoding="utf-8")
        history = get_history(data_dir=tmp_path)
        assert history == []

    def test_storage_privacy_redaction_in_saved_csv(self, pipeline_runner, tmp_path):
        sensitive_url = "https://secure-bank.example.com/auth?token=supersecret123&session=xyz#dashboard"
        res = pipeline_runner(sensitive_url, data_dir=tmp_path)
        assert res.saved_successfully is True

        csv_text = export_history_csv(data_dir=tmp_path)
        assert "supersecret123" not in csv_text
        assert "xyz" not in csv_text
        assert "token" not in csv_text
        assert "session" not in csv_text
        assert "dashboard" not in csv_text
        assert "secure-bank.example.com" in csv_text
