"""Rule-based, human-readable URL indicators.

Every indicator is computed from the submitted URL text and reports the exact
evidence it matched. These checks are INDEPENDENT of the machine-learning
classifier: they do not change the verdict or the risk score. They exist to give
the user understandable reasons to be careful.

No single indicator proves that a URL is phishing, and the absence of
indicators does not prove that a URL is safe.
"""

import re
from urllib.parse import urlparse

from features.url_features import SHORTENING_DOMAINS

# severity: "high" > "medium" > "info"
SECURITY_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "password", "banking", "wallet",
    "authenticate", "authorization",
)
_WORD_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(w) for w in SECURITY_WORDS) + r")(?![a-z0-9])", re.IGNORECASE)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SQL_RE = re.compile(
    r"(\bunion\b.*\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
    r"\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|--|/\*)", re.IGNORECASE)
_RISKY_EXTENSIONS = (".exe", ".scr", ".zip", ".bat", ".js", ".jar", ".apk")


def _ind(code, severity, title, evidence=None):
    return {"code": code, "severity": severity, "title": title, "evidence": evidence}


def analyze_indicators(url):
    """Return a list of triggered indicators for a normalised URL."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    out = []

    is_ip = bool(_IPV4.match(hostname))
    if is_ip:
        out.append(_ind("ip_host", "high", "Web address uses a raw IP address instead of a domain name", hostname))

    if parsed.scheme.lower() == "http":
        out.append(_ind("no_https", "info", "Connection is not encrypted (http instead of https)", "http://"))

    if "@" in (parsed.netloc or ""):
        out.append(_ind("at_symbol", "high",
                        "Contains '@' in the address part, which can hide the real destination", parsed.netloc))

    if hostname.removeprefix("www.") in SHORTENING_DOMAINS:
        out.append(_ind("shortener", "medium", "Link-shortening service hides the final destination", hostname))

    if "xn--" in hostname:
        out.append(_ind("punycode", "medium",
                        "Domain uses punycode (xn--), which can disguise look-alike characters", hostname))

    labels = hostname.split(".")
    if not is_ip and len(labels) - 2 >= 3:
        out.append(_ind("many_subdomains", "medium",
                        f"Unusually many sub-domain levels ({len(labels) - 2})", hostname))

    # Security-related words, reported with where they were found.
    in_host = list(dict.fromkeys(w.lower() for w in _WORD_RE.findall(hostname)))
    in_rest = list(dict.fromkeys(w.lower() for w in _WORD_RE.findall(path + "?" + query)))
    if in_host:
        out.append(_ind("words_in_domain", "medium",
                        "Security-related words appear in the domain name (common in look-alike sites, but also in real ones)",
                        ", ".join(in_host[:5])))
    if in_rest:
        out.append(_ind("words_in_path", "info",
                        "Security-related words appear in the path or query (normal on genuine login pages too)",
                        ", ".join(in_rest[:5])))

    if hostname.count("-") >= 3:
        out.append(_ind("hyphens_in_domain", "info",
                        f"Domain contains many hyphens ({hostname.count('-')})", hostname))

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None and port not in (80, 443):
        out.append(_ind("custom_port", "medium", "Uses a non-standard network port", str(port)))

    if len(url) >= 150:
        out.append(_ind("very_long", "info", f"Unusually long URL ({len(url)} characters)"))
    elif len(url) >= 100:
        out.append(_ind("long", "info", f"Long URL ({len(url)} characters)"))

    encoded = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(encoded) >= 4:
        out.append(_ind("encoded", "info", f"Many percent-encoded characters ({len(encoded)})"))

    digits = sum(c.isdigit() for c in hostname)
    if not is_ip and digits >= 5:
        out.append(_ind("digits_in_domain", "info", f"Domain contains many digits ({digits})", hostname))

    if _SQL_RE.search(path + "?" + query):
        out.append(_ind("sql_like", "medium", "Path or query contains an injection-style pattern",
                        _SQL_RE.search(path + "?" + query).group(0)[:40]))

    if "//" in path:
        out.append(_ind("double_slash", "info", "Unusual double slash inside the path", path[:60]))

    if path.lower().endswith(_RISKY_EXTENSIONS):
        out.append(_ind("risky_extension", "medium", "Link points directly to a downloadable or executable file",
                        path.rsplit("/", 1)[-1][:60]))

    return out
