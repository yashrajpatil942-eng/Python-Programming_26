"""
core/detector.py - Suspicious Feature Detection Engine for URL Guard.

Implements the 7 independent phishing detection rules defined in Section 6
of the project specification. Evaluates ParsedURL instances and produces
standardized CheckResult dataclasses.
"""

from dataclasses import dataclass
from typing import Any, List, Optional
import ipaddress
import re

from core.parser import ParsedURL


# ============================================================================
# Canonical Check Identifiers and Names
# ============================================================================

CHECK_ID_HTTPS = "check_https"
CHECK_ID_LENGTH = "check_length"
CHECK_ID_IP = "check_ip"
CHECK_ID_KEYWORDS = "check_keywords"
CHECK_ID_SPECIAL_CHARS = "check_special_chars"
CHECK_ID_HYPHENS = "check_hyphens"
CHECK_ID_SUBDOMAINS = "check_subdomains"

CHECK_NAME_HTTPS = "HTTPS Protocol Check"
CHECK_NAME_LENGTH = "URL Length Analysis"
CHECK_NAME_IP = "IP Address Hostname Detection"
CHECK_NAME_KEYWORDS = "Suspicious Keyword Detection"
CHECK_NAME_SPECIAL_CHARS = "Special Characters / Authority @ Detection"
CHECK_NAME_HYPHENS = "Excessive Hostname Hyphens Check"
CHECK_NAME_SUBDOMAINS = "Subdomain Complexity Analysis"

# Threshold Constants
URL_LENGTH_THRESHOLD = 75
HOSTNAME_HYPHEN_THRESHOLD = 3
SUBDOMAIN_LABEL_THRESHOLD = 3

# 13 Canonical Phishing Keywords from Specification
SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "account",
    "secure",
    "banking",
    "password",
    "update",
    "confirm",
    "wallet",
    "signin",
    "support",
    "bonus",
    "free",
)

# Regex matching keywords on non-alphanumeric boundaries
KEYWORD_REGEX = re.compile(
    r"(?<![a-zA-Z0-9])(" + "|".join(SUSPICIOUS_KEYWORDS) + r")(?![a-zA-Z0-9])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CheckResult:
    """Immutable result structure for an individual detection check."""
    check_id: str
    check_name: str
    detected: bool
    points: int
    explanation: str
    evidence: Any


def check_https(parsed: ParsedURL) -> CheckResult:
    """
    Check 1: HTTPS Detection (+10 pts if HTTP, 0 pts if HTTPS or missing scheme).
    
    Distinguishes between missing scheme and explicitly provided HTTP or HTTPS.
    """
    check_id = CHECK_ID_HTTPS
    check_name = CHECK_NAME_HTTPS

    if not parsed.has_explicit_scheme or not parsed.explicit_scheme:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=(
                "No URL scheme was explicitly provided. HTTPS was not verified on input; "
                "the URL was inspected without assuming encryption."
            ),
            evidence={"scheme": None, "explicit": False},
        )

    scheme_clean = parsed.explicit_scheme.lower().strip()
    if scheme_clean == "http":
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=10,
            explanation=(
                "The URL explicitly uses unencrypted HTTP. Data sent over HTTP is transmitted "
                "in cleartext and can be intercepted, read, or modified by attackers."
            ),
            evidence={"scheme": "http", "explicit": True},
        )
    elif scheme_clean == "https":
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=(
                "The URL uses HTTPS encryption. Note: HTTPS encrypts communication, "
                "but its presence alone does not prove that a website is legitimate."
            ),
            evidence={"scheme": "https", "explicit": True},
        )
    else:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=10,
            explanation=f"The URL uses an unverified non-standard scheme ('{scheme_clean}').",
            evidence={"scheme": scheme_clean, "explicit": True},
        )


def check_url_length(parsed: ParsedURL) -> CheckResult:
    """
    Check 2: URL Length Analysis (+10 pts if length > 75 characters, 0 pts otherwise).
    """
    check_id = CHECK_ID_LENGTH
    check_name = CHECK_NAME_LENGTH

    url_str = parsed.raw_url or ""
    length = len(url_str)

    if length > URL_LENGTH_THRESHOLD:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=10,
            explanation=(
                f"URL length is {length} characters, exceeding the threshold of "
                f"{URL_LENGTH_THRESHOLD} characters. Excessively long URLs are commonly used "
                "in phishing attacks to hide malicious destination parameters or obscure the real host."
            ),
            evidence=length,
        )
    else:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=(
                f"URL length is {length} characters, which is within the standard acceptable range "
                f"(<= {URL_LENGTH_THRESHOLD} characters)."
            ),
            evidence=length,
        )


def check_ip_address(parsed: ParsedURL) -> CheckResult:
    """
    Check 3: IP Address Hostname Detection (+25 pts if hostname is IPv4/IPv6, 0 pts if domain).
    """
    check_id = CHECK_ID_IP
    check_name = CHECK_NAME_IP

    hostname = (parsed.hostname or "").strip("[]")
    is_ip = False
    detected_ip: Optional[str] = None

    if getattr(parsed, "is_ip", False) and parsed.hostname:
        is_ip = True
        detected_ip = str(parsed.hostname).strip("[]")
    elif hostname:
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip = True
            detected_ip = str(ip_obj)
        except ValueError:
            is_ip = False
            detected_ip = None

    if is_ip and detected_ip:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=25,
            explanation=(
                f"The URL uses a raw IP address ({detected_ip}) as its hostname instead of a registered domain name. "
                "Legitimate institutions almost universally use registered domain names; direct IP usage is a strong phishing indicator."
            ),
            evidence=detected_ip,
        )
    else:
        domain_name = parsed.hostname or "domain"
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=f"The URL uses a standard domain name ('{domain_name}') rather than a raw IP address.",
            evidence=None,
        )


def check_suspicious_keywords(parsed: ParsedURL) -> CheckResult:
    """
    Check 4: Suspicious Keyword Detection (+15 pts flat if any of the 13 keywords appear, 0 pts otherwise).
    
    Searches the entire URL case-insensitively using non-alphanumeric boundary matching to prevent
    false positives on words like 'carefree' or 'freeze'. Points are strictly flat (+15) and deduplicated.
    """
    check_id = CHECK_ID_KEYWORDS
    check_name = CHECK_NAME_KEYWORDS

    target = (parsed.raw_url or "").lower()
    matches = list(dict.fromkeys(m.group(0).lower() for m in KEYWORD_REGEX.finditer(target)))

    if matches:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=15,  # Flat points!
            explanation=(
                f"Detected {len(matches)} suspicious keyword(s) commonly associated with phishing attacks: "
                f"{', '.join(matches)}. Phishing links often employ these terms to create a false sense of urgency "
                "or spoof authentication and banking pages. (Note: Keywords are risk indicators, not definitive proof)."
            ),
            evidence=matches,
        )
    else:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation="No suspicious phishing-related keywords were detected in the URL.",
            evidence=[],
        )


def check_special_characters(parsed: ParsedURL) -> CheckResult:
    """
    Check 5: Special Characters / Deceptive @ in Authority (+15 pts if @ in authority, 0 pts otherwise).
    
    Inspects the authority/userinfo component. Does NOT flag @ in query strings or URL paths.
    """
    check_id = CHECK_ID_SPECIAL_CHARS
    check_name = CHECK_NAME_SPECIAL_CHARS

    netloc = parsed.netloc or ""
    has_at_in_authority = "@" in netloc
    userinfo: Optional[str] = None

    if has_at_in_authority:
        userinfo = netloc.split("@", 1)[0]
    elif getattr(parsed, "username", None):
        userinfo = parsed.username
        if getattr(parsed, "password", None):
            userinfo = f"{userinfo}:{parsed.password}"
        has_at_in_authority = True

    if has_at_in_authority:
        evidence_str = userinfo if userinfo else "@"
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=15,
            explanation=(
                f"Deceptive '@' character or embedded credentials detected in URL authority ({evidence_str}@...). "
                "Browsers navigate to the domain after the '@' while ignoring the preceding text. "
                "Attackers use this technique to make deceptive links appear to point to trusted brands."
            ),
            evidence=evidence_str,
        )
    else:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation="No deceptive '@' character or embedded credentials found in the URL authority component.",
            evidence=None,
        )


def check_excessive_hyphens(parsed: ParsedURL) -> CheckResult:
    """
    Check 6: Excessive Hyphens in Hostname (+10 pts if hyphens in hostname >= 3, 0 pts otherwise).
    """
    check_id = CHECK_ID_HYPHENS
    check_name = CHECK_NAME_HYPHENS

    hostname = parsed.hostname or ""
    hyphen_count = hostname.count("-")
    positions = [i for i, ch in enumerate(hostname) if ch == "-"]
    evidence = {"count": hyphen_count, "positions": positions}

    if hyphen_count >= HOSTNAME_HYPHEN_THRESHOLD:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=10,
            explanation=(
                f"The hostname contains {hyphen_count} hyphens (threshold is >= {HOSTNAME_HYPHEN_THRESHOLD}). "
                "Phishing attackers frequently chain hyphens in domain names to concatenate brand names and deceptive words."
            ),
            evidence=evidence,
        )
    else:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=(
                f"The hostname contains {hyphen_count} hyphen(s), which is within normal limits "
                f"(< {HOSTNAME_HYPHEN_THRESHOLD})."
            ),
            evidence=evidence,
        )


def check_subdomain_complexity(parsed: ParsedURL) -> CheckResult:
    """
    Check 7: Subdomain Complexity Analysis (+15 pts if subdomain labels > 3, 0 pts otherwise).
    
    Evaluates parsed subdomain labels from ParsedURL. IP hostnames always evaluate to 0 labels.
    """
    check_id = CHECK_ID_SUBDOMAINS
    check_name = CHECK_NAME_SUBDOMAINS

    is_ip = getattr(parsed, "is_ip", False)
    if is_ip:
        labels: List[str] = []
    else:
        labels = list(parsed.subdomain_labels) if parsed.subdomain_labels else []

    subdomain_count = len(labels)
    evidence = {"labels": labels, "count": subdomain_count}

    if subdomain_count > SUBDOMAIN_LABEL_THRESHOLD:
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=True,
            points=15,
            explanation=(
                f"The hostname contains {subdomain_count} subdomain labels ({', '.join(labels)}), "
                f"exceeding the threshold of {SUBDOMAIN_LABEL_THRESHOLD}. Excessive subdomain depth is frequently "
                "used in phishing attacks to construct misleading domain prefixes while obscuring the true apex domain. "
                "(Note: This check uses an offline domain-label heuristic)."
            ),
            evidence=evidence,
        )
    else:
        explanation = (
            f"The hostname contains {subdomain_count} subdomain label(s), which is within standard expectations "
            f"(<= {SUBDOMAIN_LABEL_THRESHOLD})."
            if subdomain_count > 0
            else "No subdomain labels detected on the hostname."
        )
        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            detected=False,
            points=0,
            explanation=explanation,
            evidence=evidence,
        )


def run_detection_checks(parsed: ParsedURL) -> List[CheckResult]:
    """
    Execute all 7 detection checks against a ParsedURL instance in canonical order.

    Returns:
        List[CheckResult]: Ordered list of exactly 7 CheckResult objects corresponding to
        Check 1 (HTTPS), Check 2 (Length), Check 3 (IP), Check 4 (Keywords),
        Check 5 (Special Chars), Check 6 (Hyphens), and Check 7 (Subdomains).
    """
    return [
        check_https(parsed),
        check_url_length(parsed),
        check_ip_address(parsed),
        check_suspicious_keywords(parsed),
        check_special_characters(parsed),
        check_excessive_hyphens(parsed),
        check_subdomain_complexity(parsed),
    ]
