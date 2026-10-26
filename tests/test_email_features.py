"""Unit tests for email preprocessing and heuristics."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.features.email_features import (clean_email_text,
                                                email_structural_signals)
from phishguard.inference.heuristics import score_email


def test_clean_generalises_tokens():
    t = clean_email_text("Hi", "visit https://evil.example/x or mail a@b.com ref 123456")
    assert "urltoken" in t and "emailtoken" in t and "numtoken" in t
    assert "https://" not in t


def test_structural_signals():
    sig = email_structural_signals(
        "URGENT ACTION REQUIRED",
        "Dear customer, verify your password at http://10.0.0.1/login now!!!",
        "alerts@gmail.com")
    assert sig["has_ip_link"]
    assert sig["generic_greeting"]
    assert sig["credential_hits"]
    assert sig["urgency_hits"]


def test_phishy_email_scores_high():
    r = score_email(
        "Your account will be suspended",
        "Dear customer, confirm your credit card and password at "
        "http://192.168.1.4/verify immediately!!! You have won a prize.",
        "support@gmail.com")
    assert r["score"] >= 50


def test_benign_email_scores_low():
    r = score_email("Lunch tomorrow?",
                    "Hey, want to grab lunch at noon tomorrow? The usual place.")
    assert r["score"] <= 15
