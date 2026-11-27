"""
Unit tests for core/parser.py (URL Parsing and Component Extraction Module).
Tests component decomposition, IDN, 2-part ccTLDs, IP handling, and URL sanitization.
"""

import pytest
from core.validator import validate_url, ValidationResult
from core.parser import parse_url, ParsedURL


class TestURLParser:
    """Test suite for URL parsing and normalization."""

    def test_invalid_validation_result_raises_error(self):
        val = ValidationResult(False, "Some error", False, None, "")
        with pytest.raises(ValueError, match="Cannot parse invalid URL"):
            parse_url("invalid", val)

    def test_complete_component_extraction(self):
        url = "https://user:secret123@portal.example.com:8443/dashboard/overview?session=abc&ref=home#top"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.raw_url == url
        assert parsed.has_explicit_scheme is True
        assert parsed.explicit_scheme == "https"
        assert parsed.effective_scheme == "https"
        assert parsed.netloc == "user:secret123@portal.example.com:8443"
        assert parsed.hostname == "portal.example.com"
        assert parsed.domain == "example.com"
        assert parsed.subdomain == "portal"
        assert parsed.subdomain_labels == ["portal"]
        assert parsed.port == 8443
        assert parsed.path == "/dashboard/overview"
        assert parsed.query == "session=abc&ref=home"
        assert parsed.fragment == "top"
        assert parsed.username == "user"
        assert parsed.password == "secret123"
        assert parsed.is_ip is False
        assert parsed.ip_version is None

    def test_sanitized_url_strips_credentials_and_query(self):
        url = "https://admin:pass@secure.bank.com:9000/transfer?token=private_key#step2"
        val = validate_url(url)
        parsed = parse_url(url, val)

        # Sanitized URL must have no credentials, no query string, no fragment
        assert parsed.sanitized_url == "https://secure.bank.com:9000/transfer"
        assert "pass" not in parsed.sanitized_url
        assert "private_key" not in parsed.sanitized_url
        assert "step2" not in parsed.sanitized_url

    def test_missing_scheme_handling(self):
        url = "login.mybank.com/auth"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.has_explicit_scheme is False
        assert parsed.explicit_scheme is None
        assert parsed.effective_scheme == "http"
        assert parsed.hostname == "login.mybank.com"
        assert parsed.domain == "mybank.com"
        assert parsed.subdomain == "login"
        assert parsed.subdomain_labels == ["login"]
        assert parsed.sanitized_url == "http://login.mybank.com/auth"

    def test_idn_punycode_decoding(self):
        url = "http://xn--fsqu00a.xn--0zwm56d/path"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.is_idn is True
        assert parsed.hostname == "例子.测试"
        assert parsed.ascii_hostname == "xn--fsqu00a.xn--0zwm56d"

    def test_unicode_domain_normalization(self):
        url = "http://münchen.de/info"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.is_idn is True
        assert parsed.hostname == "münchen.de"
        assert parsed.ascii_hostname == "xn--mnchen-3ya.de"

    def test_ipv4_decomposition(self):
        url = "http://192.168.1.100:8080/admin"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.is_ip is True
        assert parsed.ip_version == 4
        assert parsed.hostname == "192.168.1.100"
        assert parsed.domain == "192.168.1.100"
        assert parsed.subdomain == ""
        assert parsed.subdomain_labels == []
        assert parsed.port == 8080
        assert parsed.sanitized_url == "http://192.168.1.100:8080/admin"

    def test_ipv6_decomposition(self):
        url = "http://[2001:db8::1]:8080/test"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.is_ip is True
        assert parsed.ip_version == 6
        assert parsed.hostname == "2001:db8::1"
        assert parsed.domain == "2001:db8::1"
        assert parsed.subdomain == ""
        assert parsed.subdomain_labels == []
        assert parsed.port == 8080
        # Brackets must be restored in sanitized URL for valid IPv6 URI
        assert parsed.sanitized_url == "http://[2001:db8::1]:8080/test"

    def test_2part_cctld_co_uk(self):
        url = "https://sub.portal.example.co.uk/page"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.domain == "example.co.uk"
        assert parsed.subdomain == "sub.portal"
        assert parsed.subdomain_labels == ["sub", "portal"]

    def test_2part_cctld_com_au(self):
        url = "https://a.b.c.service.com.au"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.domain == "service.com.au"
        assert parsed.subdomain == "a.b.c"
        assert parsed.subdomain_labels == ["a", "b", "c"]

    def test_standard_tld_multiple_subdomains(self):
        url = "https://a.b.c.d.example.com/test"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.domain == "example.com"
        assert parsed.subdomain == "a.b.c.d"
        assert parsed.subdomain_labels == ["a", "b", "c", "d"]

    def test_trailing_dot_and_casing_normalization(self):
        url = "HTTP://SUB.EXAMPLE.COM./PATH"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.hostname == "sub.example.com"
        assert parsed.domain == "example.com"
        assert parsed.subdomain == "sub"
        assert parsed.effective_scheme == "http"

    def test_single_label_localhost(self):
        url = "http://localhost:5000/api"
        val = validate_url(url)
        parsed = parse_url(url, val)

        assert parsed.hostname == "localhost"
        assert parsed.domain == "localhost"
        assert parsed.subdomain == ""
        assert parsed.subdomain_labels == []
