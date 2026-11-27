"""
Unit tests for core/validator.py (URL Validation Module).
Tests positive, negative, boundary, and edge-case scenarios.
"""

import pytest
from core.validator import validate_url, ValidationResult
from core.parser import parse_url
from core.detector import (
    run_detection_checks,
    CHECK_ID_HTTPS,
    CHECK_ID_IP,
    CHECK_ID_KEYWORDS,
    CHECK_ID_SPECIAL_CHARS,
)
from core.risk_calculator import calculate_risk, RiskLevel


class TestURLValidator:
    """Test suite for URL formatting, scheme, authority, port, and host validation."""

    def test_empty_string_rejected(self):
        result = validate_url("")
        assert result.is_valid is False
        assert "cannot be empty" in result.error_message

    def test_whitespace_only_rejected(self):
        result = validate_url("   \t  \n  ")
        assert result.is_valid is False
        assert "cannot be empty" in result.error_message

    def test_non_string_input_rejected(self):
        # Even if typed, robust function checks isinstance
        result = validate_url(None)  # type: ignore
        assert result.is_valid is False
        assert "must be a string" in result.error_message

    def test_max_length_exceeded_rejected(self):
        long_url = "http://example.com/" + "a" * 4100
        result = validate_url(long_url)
        assert result.is_valid is False
        assert "exceeds maximum allowed limit" in result.error_message

    def test_valid_length_boundary(self):
        valid_len_url = "http://example.com/" + "a" * (4096 - len("http://example.com/"))
        result = validate_url(valid_len_url)
        assert result.is_valid is True

    def test_control_characters_rejected(self):
        assert validate_url("http://example.com\n").is_valid is False
        assert validate_url("http://example.com\x00/path").is_valid is False
        assert validate_url("http://example.com\x1f").is_valid is False
        assert validate_url("http://example.com\x7f").is_valid is False

    def test_valid_https_url(self):
        result = validate_url("https://www.example.com/path?query=val#sec")
        assert result.is_valid is True
        assert result.has_explicit_scheme is True
        assert result.raw_scheme == "https"
        assert result.error_message is None

    def test_valid_http_url(self):
        result = validate_url("http://insecure.example.com/index.html")
        assert result.is_valid is True
        assert result.has_explicit_scheme is True
        assert result.raw_scheme == "http"

    def test_case_insensitive_scheme(self):
        result = validate_url("HTTP://EXAMPLE.COM/PATH")
        assert result.is_valid is True
        assert result.has_explicit_scheme is True
        assert result.raw_scheme == "http"

    def test_missing_scheme_accepted_and_normalized(self):
        result = validate_url("example.com/login")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input.startswith("http://example.com")

    def test_missing_scheme_with_port(self):
        result = validate_url("example.com:8080/dashboard")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input == "http://example.com:8080/dashboard"

    def test_missing_scheme_localhost(self):
        result = validate_url("localhost:3000")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input == "http://localhost:3000"

    def test_missing_scheme_ipv4(self):
        result = validate_url("192.168.1.1:8080")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input == "http://192.168.1.1:8080"

    def test_missing_scheme_bare_ipv6(self):
        result = validate_url("::1")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input == "http://[::1]"

    def test_bare_ipv6_starting_with_hex_letter(self):
        for addr in ["fe80::1", "beef::1", "dead:beef::1", "c001::1", "aaaa::1"]:
            res = validate_url(addr)
            assert res.is_valid is True, f"Failed for {addr}: {res.error_message}"
            assert res.has_explicit_scheme is False
            assert res.raw_scheme is None
            assert res.normalized_input == f"http://[{addr}]"

    def test_protocol_relative_url(self):
        result = validate_url("//example.com/test")
        assert result.is_valid is True
        assert result.has_explicit_scheme is False
        assert result.raw_scheme is None
        assert result.normalized_input == "http://example.com/test"

    @pytest.mark.parametrize("scheme_url", [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<b>hello</b>",
        "ftp://ftp.example.com/file.txt",
        "mailto:user@example.com",
        "ssh://user@server.com",
        "ws://echo.websocket.org",
    ])
    def test_unsupported_schemes_rejected(self, scheme_url):
        result = validate_url(scheme_url)
        assert result.is_valid is False
        assert "Unsupported URL scheme" in result.error_message

    def test_missing_hostname_rejected(self):
        assert validate_url("http://").is_valid is False
        assert validate_url("https:///only/a/path").is_valid is False
        assert validate_url("http://:8080").is_valid is False

    @pytest.mark.parametrize("port_url,expected_valid", [
        ("http://example.com:0", True),
        ("http://example.com:80", True),
        ("http://example.com:443", True),
        ("http://example.com:8080", True),
        ("http://example.com:65535", True),
        ("http://example.com:65536", False),
        ("http://example.com:70000", False),
        ("http://example.com:-1", False),
        ("http://example.com:abc", False),
        ("http://example.com:", False),
    ])
    def test_port_validation(self, port_url, expected_valid):
        result = validate_url(port_url)
        assert result.is_valid is expected_valid
        if not expected_valid:
            assert ("Invalid port" in result.error_message or "Malformed port" in result.error_message)

    def test_ipv4_host_valid(self):
        assert validate_url("http://127.0.0.1").is_valid is True
        assert validate_url("http://192.168.1.1:8080").is_valid is True
        assert validate_url("http://0.0.0.0").is_valid is True
        assert validate_url("http://255.255.255.255").is_valid is True

    def test_ipv4_host_invalid_octets(self):
        res = validate_url("http://999.999.999.999")
        assert res.is_valid is False
        assert "Invalid IPv4 address" in res.error_message

    def test_ipv4_host_leading_zero(self):
        res = validate_url("http://192.168.01.1")
        assert res.is_valid is False
        assert "Invalid IPv4 address" in res.error_message

    def test_ipv6_host_valid(self):
        assert validate_url("http://[::1]").is_valid is True
        assert validate_url("http://[2001:db8::1]:8080/path").is_valid is True
        assert validate_url("https://[fe80::1ff:fe23:4567:890a]").is_valid is True

    def test_ipv6_host_invalid(self):
        res1 = validate_url("http://[::gggg]")
        assert res1.is_valid is False
        assert ("Invalid IPv6" in res1.error_message or "Malformed URL" in res1.error_message)

        res2 = validate_url("http://[::1")
        assert res2.is_valid is False

    def test_fqdn_trailing_dot_supported(self):
        result = validate_url("http://example.com./")
        assert result.is_valid is True

    def test_fqdn_label_validation(self):
        assert validate_url("http://-bad.com").is_valid is False
        assert validate_url("http://bad-.com").is_valid is False
        assert validate_url("http://bad..com").is_valid is False
        assert validate_url("http://example.123").is_valid is False

    def test_fqdn_label_max_length(self):
        overlength_label = "a" * 64
        result = validate_url(f"http://{overlength_label}.com")
        assert result.is_valid is False
        assert "Invalid domain label" in result.error_message

    def test_punycode_and_unicode_domains(self):
        assert validate_url("http://xn--fsqu00a.xn--0zwm56d").is_valid is True
        assert validate_url("http://münchen.de").is_valid is True

    def test_embedded_credentials_allowed_in_validation(self):
        # Credentials are valid RFC 3986 syntax, though flagged by detector
        result = validate_url("http://admin:secret@example.com:8080/panel")
        assert result.is_valid is True

    @pytest.mark.parametrize("ipv6_cred_url", [
        "http://user:pass@[::1]:8080/path",
        "http://admin@[2001:db8::1]/path",
        "https://user:pass@[fe80::1ff:fe23:4567:890a]:443/login",
        "http://paypal.com@[fe80::1]/login",
        "http://admin@[::ffff:192.0.2.128]:8080",
        "http://user:p@ss@[::1]:8080/path",
    ])
    def test_bracketed_ipv6_with_user_credentials_valid(self, ipv6_cred_url):
        result = validate_url(ipv6_cred_url)
        assert result.is_valid is True, f"Failed for {ipv6_cred_url}: {result.error_message}"
        assert result.error_message is None

    @pytest.mark.parametrize("invalid_ipv6_cred_url", [
        "http://user:pass@[::gggg]:8080/path",
        "http://user:pass@[192.168.1.1]:8080/path",
        "http://admin@[bad:ipv6:address:::1]",
    ])
    def test_bracketed_ipv6_with_credentials_invalid_rejection(self, invalid_ipv6_cred_url):
        result = validate_url(invalid_ipv6_cred_url)
        assert result.is_valid is False
        assert any(term in result.error_message for term in ("Malformed URL", "Invalid IPv6", "not a valid IPv6"))

    def test_bracketed_ipv6_with_credentials_pipeline_flow(self):
        url = "http://user:pass@[::1]:8080/path"
        v = validate_url(url)
        assert v.is_valid is True

        parsed = parse_url(url, v)
        assert parsed.hostname == "::1"
        assert parsed.is_ip is True
        assert parsed.ip_version == 6
        assert parsed.port == 8080
        assert parsed.username == "user"
        assert parsed.password == "pass"
        assert parsed.sanitized_url == "http://[::1]:8080/path"
        assert "user" not in parsed.sanitized_url
        assert "pass" not in parsed.sanitized_url

        checks = run_detection_checks(parsed)
        check_dict = {c.check_id: c for c in checks}
        assert check_dict[CHECK_ID_IP].detected is True
        assert check_dict[CHECK_ID_IP].points == 25
        assert check_dict[CHECK_ID_SPECIAL_CHARS].detected is True
        assert check_dict[CHECK_ID_SPECIAL_CHARS].points == 15

    def test_phishing_authority_credentials_ipv6_pipeline_flow(self):
        url = "http://paypal.com@[fe80::1]/login"
        v = validate_url(url)
        assert v.is_valid is True

        parsed = parse_url(url, v)
        assert parsed.hostname == "fe80::1"
        assert parsed.is_ip is True
        assert parsed.ip_version == 6
        assert parsed.username == "paypal.com"
        assert parsed.sanitized_url == "http://[fe80::1]/login"
        assert "paypal.com@" not in parsed.sanitized_url

        checks = run_detection_checks(parsed)
        check_dict = {c.check_id: c for c in checks}
        assert check_dict[CHECK_ID_HTTPS].detected is True
        assert check_dict[CHECK_ID_HTTPS].points == 10
        assert check_dict[CHECK_ID_IP].detected is True
        assert check_dict[CHECK_ID_IP].points == 25
        assert check_dict[CHECK_ID_KEYWORDS].detected is True
        assert check_dict[CHECK_ID_KEYWORDS].points == 15
        assert check_dict[CHECK_ID_SPECIAL_CHARS].detected is True
        assert check_dict[CHECK_ID_SPECIAL_CHARS].points == 15

        risk = calculate_risk(checks)
        assert risk.total_score >= 65
        assert risk.risk_level == RiskLevel.HIGH
