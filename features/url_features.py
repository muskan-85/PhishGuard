"""Readable URL structure details (used for the "URL anatomy" panel).

These values are NOT fed to the machine-learning model. The classifier only
sees character TF-IDF features; these numbers just describe the URL to the user.
"""

import re
from urllib.parse import urlparse

from utils.validation import normalize_url

SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy", "cutt.ly",
}

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def extract_features(url):
    parsed = urlparse(normalize_url(url))
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    labels = hostname.split(".") if hostname else []

    try:
        port = parsed.port
    except ValueError:
        port = None

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "number_of_dots": hostname.count("."),
        "number_of_subdomains": 0 if _IPV4.match(hostname) else max(0, len(labels) - 2),
        "number_of_hyphens": url.count("-"),
        "number_of_digits": sum(c.isdigit() for c in url),
        "number_of_special_characters": len(re.findall(r"[^a-zA-Z0-9]", path + query)),
        "number_of_at_symbols": url.count("@"),
        "has_ip_address": int(bool(_IPV4.match(hostname))),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_custom_port": int(port is not None and port not in (80, 443)),
        "has_shortening_service": int(hostname.removeprefix("www.") in SHORTENING_DOMAINS),
        "has_encoded_characters": int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
    }
