"""Heuristic rule layer.

A transparent, explainable rule engine that runs *alongside* the ML ensemble.
Each triggered rule contributes a weighted score (0-100 scale) and a
human-readable reason shown on the dashboard. The final verdict blends
ML probability and heuristic score (see config.ML_WEIGHT).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from phishguard import config
from phishguard.features.email_features import email_structural_signals
from phishguard.features.url_features import (SHORTENER_DOMAINS,
                                              SUSPICIOUS_TLDS,
                                              SUSPICIOUS_WORDS, BRAND_NAMES,
                                              _registered_domain,
                                              normalize_url)

_IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _rule(reasons: list, score: float, weight: float, reason: str, severity: str) -> float:
    reasons.append({"rule": reason, "severity": severity, "weight": weight})
    return score + weight


def score_url(url: str) -> dict:
    """Return {'score': 0-100, 'reasons': [...], 'trusted_domain': bool}."""
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
    reg = _registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    lower = url.lower()

    trusted = reg in config.TRUSTED_DOMAINS or any(
        reg.endswith("." + t) or reg == t for t in config.TRUSTED_DOMAINS)

    if _IP_HOST_RE.match(host):
        score = _rule(reasons, score, 35, "URL uses a raw IP address instead of a domain name", "high")
    if host.startswith("xn--") or ".xn--" in host:
        score = _rule(reasons, score, 30, "Punycode-encoded (lookalike) domain", "high")
    if "@" in url:
        score = _rule(reasons, score, 25, "'@' symbol in URL — browser ignores everything before it", "high")
    if port not in (None, 80, 443):
        score = _rule(reasons, score, 15, f"Non-standard port {port if port != -1 else '(malformed)'}", "medium")
    if any(host == s or host.endswith("." + s) for s in SHORTENER_DOMAINS):
        score = _rule(reasons, score, 15, "Link-shortener domain hides the real destination", "medium")
    if tld in SUSPICIOUS_TLDS:
        score = _rule(reasons, score, 15, f"Suspicious top-level domain '.{tld}'", "medium")
    if max(host.count(".") - 1, 0) >= 3:
        score = _rule(reasons, score, 12, "Excessive number of subdomains", "medium")
    if "-" in reg.split(".")[0] and not trusted:
        score = _rule(reasons, score, 8, "Hyphenated registered domain", "low")

    sus_hits = [w for w in SUSPICIOUS_WORDS if w in lower]
    if len(sus_hits) >= 2:
        score = _rule(reasons, score, 15,
                      f"Multiple phishing keywords in URL: {', '.join(sus_hits[:4])}", "medium")
    elif len(sus_hits) == 1:
        score = _rule(reasons, score, 7, f"Phishing keyword in URL: '{sus_hits[0]}'", "low")

    if not trusted:
        sub_and_path = (host[: -len(reg)] + " " + (parsed.path or "") + " " + (parsed.query or "")).lower()
        for brand in BRAND_NAMES:
            if brand not in reg and brand in sub_and_path:
                score = _rule(reasons, score, 30,
                              f"Brand name '{brand}' outside the registered domain (possible impersonation)",
                              "high")
                break

    if "//" in (parsed.path or ""):
        score = _rule(reasons, score, 10, "Double slash inside URL path (redirect trick)", "medium")
    if len(url) > 100:
        score = _rule(reasons, score, 8, f"Unusually long URL ({len(url)} characters)", "low")
    if ("https" in host) or ("http" in (parsed.path or "").lower()):
        score = _rule(reasons, score, 12, "'http(s)' token embedded in domain/path to fake security", "medium")

    if trusted and not reasons:
        reasons.append({"rule": f"Registered domain '{reg}' is on the trusted allowlist",
                        "severity": "info", "weight": 0})

    return {"score": min(score, 100.0), "reasons": reasons, "trusted_domain": trusted}


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
