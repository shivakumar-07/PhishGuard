"""Unit tests for the URL lexical feature extractor and heuristics."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.features.url_features import (URL_FEATURE_NAMES,
                                              extract_url_features,
                                              normalize_url)
from phishguard.inference.heuristics import score_url


def test_feature_vector_shape_and_finite():
    v = extract_url_features("http://example.com/path?q=1")
    assert v.shape == (len(URL_FEATURE_NAMES),)
    assert np.isfinite(v).all()


@pytest.mark.parametrize("url", [
    "", "a", "google.com", "http://192.168.2.1: /broken-port",
    "https://user@host:99999/x", "ftp://files.example.org/a b c",
    "http://xn--pple-43d.com/signin", "nota url at all !!",
    "http://" + "a" * 500 + ".com",
])
def test_extractor_never_crashes(url):
    v = extract_url_features(url)
    assert v.shape == (len(URL_FEATURE_NAMES),)
    assert np.isfinite(v).all()


def test_normalize_adds_scheme():
    assert normalize_url("example.com").startswith("http://")
    assert normalize_url("https://x.com") == "https://x.com"


def test_ip_host_detected():
    v = extract_url_features("http://192.168.0.1/login")
    assert v[URL_FEATURE_NAMES.index("has_ip_host")] == 1


def test_brand_spoof_detected():
    v = extract_url_features("http://paypal.secure-login.tk/verify")
    assert v[URL_FEATURE_NAMES.index("brand_outside_domain")] == 1


def test_heuristics_flag_obvious_phish():
    r = score_url("http://paypal.account-verify.tk:8080/login?confirm=1")
    assert r["score"] >= 50
    assert any(x["severity"] == "high" for x in r["reasons"])


def test_heuristics_trust_allowlist():
    r = score_url("https://www.google.com/search?q=hello")
    assert r["trusted_domain"] is True
    assert r["score"] <= 20
