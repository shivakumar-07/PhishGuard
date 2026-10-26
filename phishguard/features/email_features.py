"""Email text preprocessing and structural signal extraction.

The ML pipeline consumes `clean_email_text` output (subject + body merged,
with volatile tokens generalised so the model learns *patterns*, not
addresses). `email_structural_signals` feeds the heuristic rule layer and
the explanation panel on the dashboard.
"""
from __future__ import annotations

import re

_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_NUM_RE = re.compile(r"\b\d{4,}\b")
_WS_RE = re.compile(r"\s+")

URGENCY_WORDS = (
    "urgent", "immediately", "act now", "expire", "expiring", "suspended",
    "suspend", "deactivate", "verify now", "final notice", "last warning",
    "within 24 hours", "within 48 hours", "right away", "asap", "limited time",
)

CREDENTIAL_WORDS = (
    "password", "login", "log in", "sign in", "signin", "verify your account",
    "confirm your account", "update your account", "billing information",
    "credit card", "debit card", "ssn", "social security", "otp", "cvv",
    "bank account", "security question", "credentials", "pin number",
)

REWARD_WORDS = (
    "congratulations", "winner", "won", "prize", "lottery", "reward", "claim",
    "gift card", "free iphone", "cash prize", "inheritance", "million",
    "beneficiary", "donation", "jackpot",
)

GENERIC_GREETINGS = (
    "dear customer", "dear user", "dear member", "dear client",
    "dear account holder", "dear sir", "dear madam", "valued customer",
)


def clean_email_text(subject: str, body: str) -> str:
    """Merge subject+body and generalise volatile tokens for TF-IDF."""
    text = f"{subject or ''} {body or ''}".lower()
    text = _URL_RE.sub(" urltoken ", text)
    text = _EMAIL_RE.sub(" emailtoken ", text)
    text = _NUM_RE.sub(" numtoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return _WS_RE.sub(" ", text).strip()


def email_structural_signals(subject: str, body: str, sender: str = "") -> dict:
    """Human-readable structural signals used by the heuristic layer."""
    text = f"{subject or ''} {body or ''}".lower()
    sender = (sender or "").lower()

    urls = _URL_RE.findall(f"{subject or ''} {body or ''}")
    ip_links = [u for u in urls if re.search(r"https?://(\d{1,3}\.){3}\d{1,3}", u)]

    signals = {
        "num_links": len(urls),
        "has_ip_link": len(ip_links) > 0,
        "urgency_hits": [w for w in URGENCY_WORDS if w in text],
        "credential_hits": [w for w in CREDENTIAL_WORDS if w in text],
        "reward_hits": [w for w in REWARD_WORDS if w in text],
        "generic_greeting": any(g in text for g in GENERIC_GREETINGS),
        "all_caps_subject": bool(subject) and subject.isupper() and len(subject) > 8,
        "excessive_exclaims": text.count("!") >= 3,
        "freemail_sender_brand_claim": False,
        "html_form_hint": "<form" in text or "type=\"password\"" in text,
    }

    freemail = ("@gmail.", "@yahoo.", "@hotmail.", "@outlook.", "@aol.")
    brands = ("paypal", "bank", "apple", "microsoft", "amazon", "netflix", "sbi", "hdfc", "icici")
    if any(f in sender for f in freemail) and any(b in text or b in sender for b in brands):
        signals["freemail_sender_brand_claim"] = True

    return signals
