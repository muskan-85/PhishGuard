"""Input validation and normalisation for submitted URLs.

Nothing in this module (or anywhere in PhishGuard) opens, resolves or fetches
the submitted URL. It is only ever treated as text.
"""

import re
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CONTROL_OR_SPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")


class InvalidURLError(ValueError):
    """Raised with a message that is safe to show to the user."""


def normalize_url(url: str) -> str:
    """Strip whitespace and add https:// when no scheme is given.

    https is used as the default because the training data contains both
    schemes and a bare "example.com" is most likely a normal web address.
    """
    url = url.strip()
    if not _SCHEME_RE.match(url):
        url = "https://" + url
    return url


def validate_url(raw) -> str:
    """Return the normalised URL, or raise InvalidURLError."""
    if raw is None or not str(raw).strip():
        raise InvalidURLError("Please enter a URL to analyze.")

    raw = str(raw).strip()
    if len(raw) > MAX_URL_LENGTH:
        raise InvalidURLError(f"The URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if _CONTROL_OR_SPACE_RE.search(raw):
        raise InvalidURLError("The URL must not contain spaces or control characters.")

    match = _SCHEME_RE.match(raw)
    if match and match.group(1).lower() not in ("http", "https"):
        raise InvalidURLError("Only http:// and https:// addresses can be analyzed.")

    url = normalize_url(raw)

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        parsed.port  # raises ValueError for an invalid port
    except ValueError:
        raise InvalidURLError("This does not look like a valid URL (invalid host or port).")

    if not hostname:
        raise InvalidURLError("The URL has no domain name. Example: https://example.com")

    if _IPV4_RE.match(hostname):
        if any(int(part) > 255 for part in hostname.split(".")):
            raise InvalidURLError("The IP address in the URL is not valid.")
        return url

    labels = hostname.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise InvalidURLError("The domain name looks incomplete. Example: https://example.com")
    if len(hostname) > 253 or not all(_HOST_LABEL_RE.match(label) for label in labels):
        raise InvalidURLError("The domain name contains invalid characters.")
    if not re.match(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$", labels[-1], re.IGNORECASE):
        raise InvalidURLError("The domain ending (TLD) looks invalid. Example: .com, .org, .in")

    return url
