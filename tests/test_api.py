"""API integration tests (require trained models in models/)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard import config

pytestmark = pytest.mark.skipif(
    not (config.URL_MODEL_PATH.exists() and config.EMAIL_MODEL_PATH.exists()),
    reason="trained models not present — run the training scripts first")

from fastapi.testclient import TestClient  # noqa: E402
from phishguard.api.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_phishing_url():
    r = client.post("/api/scan/url",
                    json={"url": "http://paypal.account-verify.tk/webscr/login"})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in ("phishing", "suspicious")
    assert 0 <= data["risk_score"] <= 100
    assert data["per_model"]


def test_scan_safe_url():
    r = client.post("/api/scan/url", json={"url": "https://www.wikipedia.org/"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "safe"


def test_scan_phishing_email():
    r = client.post("/api/scan/email", json={
        "subject": "URGENT: verify your account now",
        "body": "Dear customer, your password expires today. Confirm your "
                "credit card at http://192.168.3.2/verify immediately!!!",
        "sender": "security@gmail.com"})
    assert r.status_code == 200
    assert r.json()["verdict"] in ("phishing", "suspicious")


def test_stats_and_history():
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/scans").status_code == 200


def test_validation_rejects_empty():
    assert client.post("/api/scan/url", json={"url": "x"}).status_code == 422
