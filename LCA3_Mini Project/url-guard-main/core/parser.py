"""
URL Guard - Parsing Module
Extracts and normalizes URL components, performs 2-part ccTLD heuristic
domain/subdomain decomposition, and generates privacy-safe sanitized URLs.
Offline, standard-library-only implementation.
"""

from dataclasses import dataclass
from typing import Optional, List
import ipaddress
import urllib.parse
from core.validator import ValidationResult


@dataclass(frozen=True)
class ParsedURL:
    """Comprehensive decomposition and normalization of a validated URL."""
    raw_url: str
    has_explicit_scheme: bool
    explicit_scheme: Optional[str]
    effective_scheme: str
    netloc: str
    hostname: str
    domain: str
    subdomain: str
    subdomain_labels: List[str]
    port: Optional[int]
    path: str
    query: str
    fragment: str
    username: Optional[str]
    password: Optional[str]
    is_ip: bool
    ip_version: Optional[int]
    is_idn: bool
    ascii_hostname: str
    sanitized_url: str


# Curated set of standard second-level ccTLD categories
CCTLD_SECOND_LEVELS = {
    'co', 'com', 'org', 'net', 'gov', 'gob', 'edu', 'ac', 'ne', 'go',
    'res', 'govt', 'mil', 'nom', 'gen', 'firm', 'store', 'web', 'arts',
    'rec', 'info', 'biz'
}


def parse_url(raw_url: str, validation: ValidationResult) -> ParsedURL:
    """
    Parses a validated URL into structured components.
    Precondition: validation.is_valid must be True.
    """
    if not validation.is_valid:
        raise ValueError(f"Cannot parse invalid URL: {validation.error_message}")

    split_res = urllib.parse.urlsplit(validation.normalized_input)

    effective_scheme = split_res.scheme.lower()
    explicit_scheme = validation.raw_scheme.lower() if validation.raw_scheme else None
    has_explicit_scheme = validation.has_explicit_scheme

    netloc = split_res.netloc
    raw_host = split_res.hostname or ""
    port = split_res.port
    path = split_res.path
    query = split_res.query
    fragment = split_res.fragment
    username = split_res.username
    password = split_res.password

    # Clean hostname: strip brackets, trailing dot, lowercase
    clean_host = raw_host.strip("[]").rstrip(".").lower()

    # Detect whether host is IPv4 or IPv6
    is_ip = False
    ip_version = None
    try:
        ip = ipaddress.ip_address(clean_host)
        is_ip = True
        ip_version = ip.version
    except ValueError:
        pass

    # IDN detection and Punycode decoding
    is_idn = False
    ascii_hostname = clean_host
    normalized_hostname = clean_host

    if not is_ip:
        try:
            if any(lbl.startswith("xn--") for lbl in clean_host.split(".")):
                is_idn = True
                normalized_hostname = clean_host.encode("ascii").decode("idna")
                ascii_hostname = clean_host
            elif any(ord(c) > 127 for c in clean_host):
                is_idn = True
                normalized_hostname = clean_host
                ascii_hostname = clean_host.encode("idna").decode("ascii")
            else:
                is_idn = False
                normalized_hostname = clean_host
                ascii_hostname = clean_host
        except Exception:
            normalized_hostname = clean_host
            ascii_hostname = clean_host

    # Domain and Subdomain Extraction
    if is_ip:
        domain = normalized_hostname
        subdomain = ""
        subdomain_labels = []
    else:
        labels = normalized_hostname.split(".")
        if len(labels) <= 1:
            domain = normalized_hostname
            subdomain = ""
            subdomain_labels = []
        else:
            # 2-part ccTLD heuristic:
            # If last label is 2 letters (ccTLD) and penultimate label is a recognized
            # category (e.g. .co.uk, .gov.in, .com.au) or <= 2 letters:
            is_2part = False
            if len(labels) >= 3 and len(labels[-1]) == 2:
                if labels[-2].lower() in CCTLD_SECOND_LEVELS or len(labels[-2]) <= 2:
                    is_2part = True

            if is_2part:
                domain = ".".join(labels[-3:])
                subdomain_parts = labels[:-3]
            else:
                domain = ".".join(labels[-2:])
                subdomain_parts = labels[:-2]

            subdomain = ".".join(subdomain_parts)
            subdomain_labels = subdomain_parts

    # Construct Sanitized URL:
    # 1. Strip username and password credentials.
    # 2. Bracket IPv6 host.
    # 3. Include port if non-default.
    # 4. Include clean path.
    # 5. Omit query parameters and fragment entirely for privacy.
    host_display = f"[{normalized_hostname}]" if (is_ip and ip_version == 6) else normalized_hostname
    netloc_sanitized = f"{host_display}:{port}" if port is not None else host_display
    clean_path = path if path else ""
    if clean_path and not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    sanitized_url = f"{effective_scheme}://{netloc_sanitized}{clean_path}"

    return ParsedURL(
        raw_url=raw_url,
        has_explicit_scheme=has_explicit_scheme,
        explicit_scheme=explicit_scheme,
        effective_scheme=effective_scheme,
        netloc=netloc,
        hostname=normalized_hostname,
        domain=domain,
        subdomain=subdomain,
        subdomain_labels=subdomain_labels,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        username=username,
        password=password,
        is_ip=is_ip,
        ip_version=ip_version,
        is_idn=is_idn,
        ascii_hostname=ascii_hostname,
        sanitized_url=sanitized_url
    )
