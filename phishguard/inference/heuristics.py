"""Heuristic rule layer with global three-tier domain trust.

A transparent, explainable rule engine that runs *alongside* the ML
ensemble. Each triggered rule contributes a weighted score (0-100) and a
human-readable reason shown on the dashboard / extension.

Trust tiers (phishguard.trust — PSL registered domains + top-1M Bloom):
  curated  — verified critical domains / restricted registries:
             pattern rules suppressed entirely
  popular  — top-1M most-visited registered domains: noisy pattern rules
             (keywords, length, subdomains, TLD) suppressed; brand
             impersonation and structural rules stay active
  unknown  — everything else: all rules, plus a "not a top-1M domain"
             signal (fresh phishing domains are never popular)

Brand and keyword rules examine only attacker-controlled parts of the URL
(host + path) — never the query string, which carries user content such
as search terms ("?q=sbi+online+login").
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from phishguard import trust
from phishguard.features.email_features import email_structural_signals
from phishguard.features.url_features import (SHORTENER_DOMAINS,
                                              SUSPICIOUS_TLDS,
                                              SUSPICIOUS_WORDS, BRAND_NAMES,
                                              normalize_url)

_IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Famous names attackers imitate with misspellings / look-alike characters.
TYPO_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "twitter",
    "linkedin", "microsoft", "outlook", "office", "windows", "apple", "icloud",
    "amazon", "netflix", "spotify", "paypal", "walmart", "dropbox", "adobe",
    "telegram", "snapchat", "tiktok", "discord", "github", "reddit", "wikipedia",
    "yahoo", "chrome", "android", "samsung", "mastercard", "chase", "citibank",
    "wellsfargo", "barclays", "santander", "americanexpress", "westernunion",
    "moneygram", "coinbase", "binance", "blockchain", "metamask", "flipkart",
    "paytm", "phonepe", "myntra", "snapdeal", "irctc", "makemytrip", "zomato",
    "swiggy", "hdfcbank", "icicibank", "axisbank", "kotak", "onlinesbi",
    "airtel", "vodafone", "incometax", "uidai", "bluedart", "delhivery",
    "indiapost", "fedex", "aramex", "interac", "venmo", "zelle", "cashapp",
    "steam", "roblox", "fortnite", "booking", "airbnb", "expedia", "aliexpress",
]

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                             "6": "b", "7": "t", "8": "b", "9": "g",
                             "@": "a", "$": "s"})


def _de_homoglyph(s: str) -> str:
    return s.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance, effectively capped at small values."""
    if abs(len(a) - len(b)) > 2:
        return 3
    la, lb = len(a), len(b)
    d = [[i + j if i * j == 0 else 0 for j in range(lb + 1)] for i in range(la + 1)]
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def look_alike(reg: str) -> dict | None:
    """Look-alike analysis of the registered domain's core label (unknown tier)."""
    core = reg.split(".")[0] if reg else ""
    if len(core) < 4:
        return None
    norm = _de_homoglyph(core)
    for brand in TYPO_BRANDS:
        if core == brand:
            return {"weight": 30, "severity": "high", "floor": 72,
                    "rule": f"Official-looking name '{brand}' on an unofficial domain ending"}
        if norm == brand:
            return {"weight": 35, "severity": "high", "floor": 72,
                    "rule": f"Disguised spelling of '{brand}' using look-alike characters"}
        if len(brand) >= 5 and _edit_distance(core, brand) == 1:
            return {"weight": 30, "severity": "high", "floor": 68,
                    "rule": f"One-letter-off misspelling of '{brand}'"}
        if (len(brand) >= 5 and len(core) > len(brand)
                and re.search(rf"(^|[-_0-9]){re.escape(brand)}([-_0-9]|$)", core)):
            return {"weight": 25, "severity": "high", "floor": 55,
                    "rule": f"Brand '{brand}' embedded in an unofficial domain name"}
    return None


def _rule(reasons: list, score: float, weight: float, reason: str, severity: str) -> float:
    reasons.append({"rule": reason, "severity": severity, "weight": weight})
    return score + weight


def score_url(url: str) -> dict:
    """Return {'score': 0-100, 'reasons': [...], 'tier': ..., 'trusted_domain': bool}."""
    reasons: list[dict] = []
    score = 0.0

    try:
        parsed = urlparse(normalize_url(url))
    except ValueError:
        parsed = urlparse("http://invalid.invalid")
    try:
        host = (parsed.hostname or "").lower()
    except ValueError:
        host = ""
    try:
        port = parsed.port
    except ValueError:
        port = -1

    path = parsed.path or ""
    reg = trust.registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    tier = trust.trust_tier(reg)
    host_path = (host + " " + path).lower()

    # ---- structural rules: always active, every tier --------------------
    if _IP_HOST_RE.match(host):
        score = _rule(reasons, score, 35, "URL uses a raw IP address instead of a domain name", "high")
    if host.startswith("xn--") or ".xn--" in host:
        score = _rule(reasons, score, 30, "Punycode-encoded (lookalike) domain", "high")
    if "@" in (url or ""):
        score = _rule(reasons, score, 25, "'@' symbol in URL — browser ignores everything before it", "high")
    if port not in (None, 80, 443):
        score = _rule(reasons, score, 15, f"Non-standard port {port if port != -1 else '(malformed)'}", "medium")
    if "//" in path:
        score = _rule(reasons, score, 10, "Double slash inside URL path (redirect trick)", "medium")

    # ---- brand impersonation: active unless curated ----------------------
    # host+path only — the query string carries user content (search terms)
    if tier != "curated":
        sub_part = host[: -len(reg)].rstrip(".") if reg and host.endswith(reg) else host
        sub_and_path = (sub_part + " " + path).lower()
        for brand in BRAND_NAMES:
            if brand not in reg and brand in sub_and_path:
                score = _rule(reasons, score, 30,
                              f"Brand name '{brand}' outside the registered domain (possible impersonation)",
                              "high")
                break

    # ---- pattern rules: unknown domains only ------------------------------
    risk_floor = 0
    if tier == "unknown":
        la = look_alike(reg)
        if la:
            score = _rule(reasons, score, la["weight"], la["rule"], la["severity"])
            risk_floor = la["floor"]
        if any(host == s or host.endswith("." + s) for s in SHORTENER_DOMAINS):
            score = _rule(reasons, score, 15, "Link-shortener domain hides the real destination", "medium")
        if tld in SUSPICIOUS_TLDS:
            score = _rule(reasons, score, 15, f"Suspicious top-level domain '.{tld}'", "medium")
        if max(host.count(".") - 1, 0) >= 3:
            score = _rule(reasons, score, 12, "Excessive number of subdomains", "medium")
        if "-" in reg.split(".")[0]:
            score = _rule(reasons, score, 8, "Hyphenated registered domain", "low")

        sus_hits = [w for w in SUSPICIOUS_WORDS if w in host_path]
        if len(sus_hits) >= 2:
            score = _rule(reasons, score, 15,
                          f"Multiple phishing keywords in URL: {', '.join(sus_hits[:4])}", "medium")
        elif len(sus_hits) == 1:
            score = _rule(reasons, score, 7, f"Phishing keyword in URL: '{sus_hits[0]}'", "low")

        if len(url or "") > 100:
            score = _rule(reasons, score, 8, f"Unusually long URL ({len(url)} characters)", "low")
        if ("https" in host) or ("http" in path.lower()):
            score = _rule(reasons, score, 12, "'http(s)' token embedded in domain/path to fake security", "medium")
        if "." in reg:
            score = _rule(reasons, score, 8,
                          "Domain is not among the 1M most-visited websites (new or little-known)", "low")

    if tier == "curated" and not reasons:
        reasons.append({"rule": f"'{reg}' is on the verified trusted allowlist",
                        "severity": "info", "weight": 0})
    elif tier == "popular" and not reasons:
        reasons.append({"rule": f"'{reg}' is among the world's 1M most-visited websites",
                        "severity": "info", "weight": 0})

    return {"score": min(score, 100.0), "reasons": reasons, "tier": tier,
            "trusted_domain": tier != "unknown", "risk_floor": risk_floor}


def score_email(subject: str, body: str, sender: str = "") -> dict:
    """Return {'score': 0-100, 'reasons': [...], 'signals': {...}}."""
    reasons: list[dict] = []
    score = 0.0
    sig = email_structural_signals(subject, body, sender)

    if sig["credential_hits"]:
        score = _rule(reasons, score, min(12 * len(sig["credential_hits"]), 30),
                      f"Requests credentials/sensitive data: {', '.join(sig['credential_hits'][:3])}", "high")
    if sig["urgency_hits"]:
        score = _rule(reasons, score, min(8 * len(sig["urgency_hits"]), 20),
                      f"Urgency pressure language: {', '.join(sig['urgency_hits'][:3])}", "medium")
    if sig["reward_hits"]:
        score = _rule(reasons, score, min(8 * len(sig["reward_hits"]), 20),
                      f"Too-good-to-be-true reward language: {', '.join(sig['reward_hits'][:3])}", "medium")
    if sig["has_ip_link"]:
        score = _rule(reasons, score, 25, "Contains a link pointing to a raw IP address", "high")
    if sig["freemail_sender_brand_claim"]:
        score = _rule(reasons, score, 25, "Free-mail sender claiming to be a known brand", "high")
    if sig["generic_greeting"]:
        score = _rule(reasons, score, 8, "Generic greeting ('Dear customer' …)", "low")
    if sig["all_caps_subject"]:
        score = _rule(reasons, score, 6, "ALL-CAPS subject line", "low")
    if sig["excessive_exclaims"]:
        score = _rule(reasons, score, 5, "Excessive exclamation marks", "low")
    if sig["html_form_hint"]:
        score = _rule(reasons, score, 20, "Embedded HTML form / password field", "high")
    if sig["num_links"] >= 5:
        score = _rule(reasons, score, 8, f"High number of links ({sig['num_links']})", "low")

    return {"score": min(score, 100.0), "reasons": reasons, "signals": sig}
