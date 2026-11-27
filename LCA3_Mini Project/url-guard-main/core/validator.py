"""
URL Guard - Validation Module
Validates URL formatting, scheme, authority, port, and hostname syntax.
Offline, standard-library-only implementation.
"""

from dataclasses import dataclass
from typing import Optional
import ipaddress
import re
import urllib.parse


@dataclass(frozen=True)
class ValidationResult:
    """Result of URL syntactic validation."""
    is_valid: bool
    error_message: Optional[str]
    has_explicit_scheme: bool
    raw_scheme: Optional[str]
    normalized_input: str


# Known non-hierarchical or unsupported schemes to explicitly reject
KNOWN_UNSUPPORTED_SCHEMES = {
    'javascript', 'data', 'file', 'mailto', 'tel', 'blob', 'about', 'urn',
    'ws', 'wss', 'ftp', 'ftps', 'ssh', 'sftp', 'ldap', 'gopher'
}

MAX_URL_LENGTH = 4096
MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63


def validate_url(raw_url: str) -> ValidationResult:
    """
    Validates user URL input for length, scheme, port, and hostname structure.
    Returns ValidationResult containing validation status, diagnostic message,
    and normalized string suitable for downstream parsing.
    """
    if not isinstance(raw_url, str):
        return ValidationResult(False, "URL must be a string.", False, None, "")

    stripped = raw_url.strip(" ")
    if not stripped or not raw_url.strip():
        return ValidationResult(False, "URL cannot be empty or whitespace-only.", False, None, "")

    if len(stripped) > MAX_URL_LENGTH:
        return ValidationResult(
            False,
            f"URL length ({len(stripped)}) exceeds maximum allowed limit of {MAX_URL_LENGTH} characters.",
            False,
            None,
            stripped
        )

    # Reject control characters (0-31, 127)
    if any(ord(c) < 32 or ord(c) == 127 for c in stripped):
        return ValidationResult(False, "URL contains invalid control characters.", False, None, stripped)

    # Scheme detection and extraction
    has_explicit = False
    raw_scheme = None
    normalized_for_parsing = stripped

    # Check first if bare IPv4 or IPv6 address without scheme was entered
    is_bare_ip = False
    try:
        ip = ipaddress.ip_address(stripped)
        is_bare_ip = True
        has_explicit = False
        raw_scheme = None
        if ip.version == 6:
            normalized_for_parsing = f"http://[{stripped}]"
        else:
            normalized_for_parsing = f"http://{stripped}"
    except ValueError:
        pass

    if not is_bare_ip:
        if "://" in stripped:
            scheme_part, _ = stripped.split("://", 1)
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*$", scheme_part):
                has_explicit = True
                raw_scheme = scheme_part.lower()
                normalized_for_parsing = stripped
        elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", stripped):
            match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$", stripped)
            if match:
                candidate_scheme = match.group(1).lower()
                remainder = match.group(2)
                if candidate_scheme in KNOWN_UNSUPPORTED_SCHEMES:
                    has_explicit = True
                    raw_scheme = candidate_scheme
                    normalized_for_parsing = stripped
                elif re.match(r"^\d+(?:[/?#]|$)", remainder):
                    # Form of host:port without scheme, e.g. 'example.com:8080' or 'localhost:3000'
                    has_explicit = False
                    raw_scheme = None
                    normalized_for_parsing = "http://" + stripped
                else:
                    has_explicit = True
                    raw_scheme = candidate_scheme
                    normalized_for_parsing = stripped
            else:
                has_explicit = False
                raw_scheme = None
                normalized_for_parsing = "http://" + stripped
        elif stripped.startswith("//"):
            has_explicit = False
            raw_scheme = None
            normalized_for_parsing = "http:" + stripped
        else:
            has_explicit = False
            raw_scheme = None
            normalized_for_parsing = "http://" + stripped

    # Enforce supported schemes whitelist
    if has_explicit and raw_scheme not in ("http", "https"):
        return ValidationResult(
            False,
            f"Unsupported URL scheme '{raw_scheme}'. Only HTTP and HTTPS are supported.",
            has_explicit,
            raw_scheme,
            normalized_for_parsing
        )

    # Perform structural splitting with urllib.parse
    try:
        split_result = urllib.parse.urlsplit(normalized_for_parsing)
    except ValueError as e:
        return ValidationResult(False, f"Malformed URL structure: {e}", has_explicit, raw_scheme, normalized_for_parsing)

    # Validate port number
    try:
        _ = split_result.port
    except ValueError as e:
        return ValidationResult(False, f"Invalid port in URL: {e}", has_explicit, raw_scheme, normalized_for_parsing)

    netloc_without_creds = split_result.netloc
    if "@" in netloc_without_creds:
        netloc_without_creds = netloc_without_creds.rsplit("@", 1)[-1]
    if netloc_without_creds.endswith(":"):
        return ValidationResult(False, "Malformed port: trailing colon without port number.", has_explicit, raw_scheme, normalized_for_parsing)

    # Validate hostname presence
    raw_host = split_result.hostname
    if not raw_host:
        return ValidationResult(False, "URL must contain a valid hostname.", has_explicit, raw_scheme, normalized_for_parsing)

    # Validate host syntax (IPv6, IPv4, or FQDN)
    host_clean = raw_host.strip("[]").rstrip(".")
    if raw_host.startswith("[") or (netloc_without_creds.startswith("[") and "]" in netloc_without_creds):
        try:
            ip = ipaddress.ip_address(host_clean)
            if ip.version != 6:
                return ValidationResult(False, f"Bracketed host '{raw_host}' is not a valid IPv6 address.", has_explicit, raw_scheme, normalized_for_parsing)
        except ValueError as e:
            return ValidationResult(False, f"Invalid IPv6 address '{raw_host}': {e}", has_explicit, raw_scheme, normalized_for_parsing)
    else:
        labels = host_clean.split(".")
        if all(lbl.isdigit() for lbl in labels):
            try:
                ip = ipaddress.ip_address(host_clean)
                if ip.version != 4:
                    return ValidationResult(False, f"Invalid IPv4 address: {host_clean}", has_explicit, raw_scheme, normalized_for_parsing)
            except ValueError as e:
                return ValidationResult(False, f"Invalid IPv4 address '{host_clean}': {e}", has_explicit, raw_scheme, normalized_for_parsing)
        else:
            if len(host_clean) > MAX_HOSTNAME_LENGTH:
                return ValidationResult(
                    False,
                    f"Hostname exceeds maximum DNS length of {MAX_HOSTNAME_LENGTH} characters (length: {len(host_clean)}).",
                    has_explicit,
                    raw_scheme,
                    normalized_for_parsing
                )

            # Pre-validate label lengths before IDNA encoding
            for lbl in host_clean.split("."):
                if len(lbl) > MAX_LABEL_LENGTH:
                    return ValidationResult(
                        False,
                        f"Invalid domain label '{lbl[:15]}...' in hostname: exceeds {MAX_LABEL_LENGTH} characters.",
                        has_explicit,
                        raw_scheme,
                        normalized_for_parsing
                    )

            try:
                ascii_host = host_clean.encode("idna").decode("ascii")
            except Exception as e:
                return ValidationResult(False, f"Invalid international domain name encoding: {e}", has_explicit, raw_scheme, normalized_for_parsing)

            domain_labels = ascii_host.split(".")
            if len(domain_labels) == 1:
                lbl = domain_labels[0]
                if not (1 <= len(lbl) <= MAX_LABEL_LENGTH and re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$", lbl) and not lbl.isdigit()):
                    return ValidationResult(False, f"Invalid single-label hostname '{host_clean}'.", has_explicit, raw_scheme, normalized_for_parsing)
            else:
                if domain_labels[-1].isdigit():
                    return ValidationResult(False, f"Top-level domain cannot be numeric: '{domain_labels[-1]}'.", has_explicit, raw_scheme, normalized_for_parsing)
                label_re = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
                for lbl in domain_labels:
                    if not (1 <= len(lbl) <= MAX_LABEL_LENGTH) or not label_re.match(lbl):
                        return ValidationResult(False, f"Invalid domain label '{lbl}' in hostname.", has_explicit, raw_scheme, normalized_for_parsing)

    return ValidationResult(True, None, has_explicit, raw_scheme, normalized_for_parsing)
