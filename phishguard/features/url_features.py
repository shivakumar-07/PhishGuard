"""Lexical URL feature extraction.

Every feature is computed offline from the URL string alone (no network
look-ups), so extraction is deterministic and fast enough for real-time
scoring (< 1 ms per URL).

The 30 features below follow the lexical families used in the hybrid
phishing-URL literature (length statistics, character distributions,
token/keyword signals, host structure and entropy).
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse

import numpy as np

# ------------------------------------------------------------------ lexicons
SUSPICIOUS_WORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "password", "credential", "wallet",
    "webscr", "ebayisapi", "lucky", "bonus", "free", "prize", "winner", "urgent",
    "suspend", "unlock", "invoice", "payment", "refund", "alert", "limited",
)

BRAND_NAMES = (
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "chase", "wellsfargo",
    "bankofamerica", "hsbc", "icici", "hdfc", "sbi", "dhl", "fedex", "usps",
)

SHORTENER_DOMAINS = (
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "lnkd.in",
)

SUSPICIOUS_TLDS = (
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "link",
    "country", "stream", "download", "racing", "online", "loan", "win", "bid",
    "vip", "icu", "rest", "fit", "cam", "monster", "quest", "zip", "mov",
)

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")


URL_FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_question_marks", "num_equals", "num_at", "num_ampersands",
    "num_percent", "num_digits", "digit_ratio", "letter_ratio",
    "num_subdomains", "has_ip_host", "has_port", "has_at_symbol",
    "has_double_slash_path", "has_https_token", "hyphen_in_domain",
    "is_shortened", "suspicious_tld", "num_suspicious_words",
    "brand_outside_domain", "num_hex_encodings", "url_entropy",
    "hostname_entropy",
]


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme so urlparse behaves predictably."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _registered_domain(hostname: str) -> str:
    """Best-effort registered domain (last two labels; last three for ccSLDs)."""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    cc_slds = {"co", "com", "org", "net", "gov", "ac", "edu", "bank", "fin"}
    if parts[-2] in cc_slds and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_url_features(url: str) -> np.ndarray:
    """Return the 30-dim lexical feature vector for one URL."""
    raw = (url or "").strip()
    norm = normalize_url(raw)
    try:
        parsed = urlparse(norm)
    except ValueError:
        parsed = urlparse("http://invalid.invalid")

    try:
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        hostname = ""
    try:
        port = parsed.port
    except ValueError:
        port = -1  # malformed port string — treat as non-standard
    path = parsed.path or ""
    query = parsed.query or ""
    lower = raw.lower()

    host_no_port = hostname
    reg_domain = _registered_domain(host_no_port)
    tld = host_no_port.rsplit(".", 1)[-1] if "." in host_no_port else ""

    n = max(len(raw), 1)
    num_digits = sum(ch.isdigit() for ch in raw)
    num_letters = sum(ch.isalpha() for ch in raw)

    subdomain_part = host_no_port[: -len(reg_domain)].rstrip(".") if host_no_port.endswith(reg_domain) else ""
    path_query = (path + "?" + query).lower()

    brand_outside = 0
    for brand in BRAND_NAMES:
        in_reg = brand in reg_domain
        if not in_reg and (brand in subdomain_part or brand in path_query):
            brand_outside = 1
            break

    feats = [
        len(raw),                                          # url_length
        len(hostname),                                     # hostname_length
        len(path),                                         # path_length
        len(query),                                        # query_length
        raw.count("."),                                    # num_dots
        raw.count("-"),                                    # num_hyphens
        raw.count("_"),                                    # num_underscores
        raw.count("/"),                                    # num_slashes
        raw.count("?"),                                    # num_question_marks
        raw.count("="),                                    # num_equals
        raw.count("@"),                                    # num_at
        raw.count("&"),                                    # num_ampersands
        raw.count("%"),                                    # num_percent
        num_digits,                                        # num_digits
        num_digits / n,                                    # digit_ratio
        num_letters / n,                                   # letter_ratio
        max(host_no_port.count(".") - 1, 0),               # num_subdomains
        1 if _IP_RE.match(host_no_port or "") else 0,      # has_ip_host
        1 if port not in (None, 80, 443) else 0,           # has_port
        1 if "@" in raw else 0,                            # has_at_symbol
        1 if "//" in path else 0,                          # has_double_slash_path
        1 if ("https" in host_no_port or "http" in path.lower()) else 0,  # has_https_token
        1 if "-" in reg_domain.split(".")[0] else 0,       # hyphen_in_domain
        1 if any(host_no_port.endswith(s) or host_no_port == s for s in SHORTENER_DOMAINS) else 0,  # is_shortened
        1 if tld in SUSPICIOUS_TLDS else 0,                # suspicious_tld
        sum(w in lower for w in SUSPICIOUS_WORDS),         # num_suspicious_words
        brand_outside,                                     # brand_outside_domain
        len(_HEX_RE.findall(raw)),                         # num_hex_encodings
        _entropy(raw),                                     # url_entropy
        _entropy(host_no_port),                            # hostname_entropy
    ]
    return np.asarray(feats, dtype=np.float32)


def extract_url_features_batch(urls) -> np.ndarray:
    """Vectorised helper: list[str] -> (n, 30) float32 matrix."""
    return np.vstack([extract_url_features(u) for u in urls])
