"""Stage 4 — Real-time prediction.

Loads the trained hybrid ensembles once and scores incoming URLs / emails in
milliseconds. Every verdict is explainable:

  risk = ML_WEIGHT * P(phishing | ensemble) * 100
       + HEURISTIC_WEIGHT * heuristic_rule_score

  verdict:  risk >= 65  -> phishing
            risk >= 40  -> suspicious
            else        -> safe

The per-model probabilities, triggered heuristic rules and top ML tokens
are returned alongside the verdict and rendered on the dashboard.
"""
from __future__ import annotations

import time
from functools import lru_cache

import joblib
import numpy as np
import pandas as pd

from phishguard import config
from phishguard.features.email_features import clean_email_text
from phishguard.features.url_features import (URL_FEATURE_NAMES,
                                              extract_url_features)
from phishguard.inference import heuristics


# ------------------------------------------------------------------ loading
@lru_cache(maxsize=1)
def _load(kind: str):
    path = config.URL_MODEL_PATH if kind == "url" else config.EMAIL_MODEL_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"Model file {path} not found — run the training scripts first "
            "(python phishguard/training/train_url.py / train_email.py)")
    return joblib.load(path)


def models_ready() -> dict:
    return {"url": config.URL_MODEL_PATH.exists(),
            "email": config.EMAIL_MODEL_PATH.exists()}


# ------------------------------------------------------------------ verdict
def _verdict(risk: float) -> str:
    if risk >= config.THRESHOLD_PHISHING:
        return "phishing"
    if risk >= config.THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _blend(ml_prob: float, heuristic_score: float) -> float:
    return round(config.ML_WEIGHT * ml_prob * 100
                 + config.HEURISTIC_WEIGHT * heuristic_score, 2)


# ------------------------------------------------------------------ URL
def _url_design_row(url: str) -> pd.DataFrame:
    feats = extract_url_features(url)
    row = pd.DataFrame([feats], columns=URL_FEATURE_NAMES)
    row.insert(0, "url", [url])
    return row


def _top_url_tokens(bundle, row: pd.DataFrame, k: int = 6) -> list[dict]:
    """Top character n-grams + numeric features pushing the LR verdict."""
    try:
        pipe = bundle["models"]["logistic_regression"]
        prep = pipe.named_steps["prep"]
        clf = pipe.named_steps["clf"]
        X = prep.transform(row)
        coefs = clf.coef_[0]
        contrib = X.toarray()[0] * coefs
        names = prep.get_feature_names_out()
        idx = np.argsort(-np.abs(contrib))[:k]
        out = []
        for i in idx:
            if abs(contrib[i]) < 1e-6:
                continue
            name = names[i].split("__", 1)[-1]
            out.append({"token": name.strip(),
                        "direction": "phishing" if contrib[i] > 0 else "legitimate",
                        "weight": round(float(contrib[i]), 3)})
        return out
    except Exception:
        return []


def predict_url(url: str, explain: bool = True) -> dict:
    t0 = time.perf_counter()
    url = (url or "").strip()
    bundle = _load("url")
    row = _url_design_row(url)

    per_model = {name: round(float(est.predict_proba(row)[0, 1]), 4)
                 for name, est in bundle["ensemble"].estimators}
    ml_prob = float(bundle["ensemble"].predict_proba(row)[0, 1])

    heur = heuristics.score_url(url)

    # tiered benign prior: verified domains strongest, top-1M softer
    if heur["tier"] == "curated":
        ml_prob = min(ml_prob, 0.15)
    elif heur["tier"] == "popular":
        ml_prob = min(ml_prob, 0.30)

    risk = _blend(ml_prob, heur["score"])

    # Brand look-alike domains carry a verdict floor: a disguised or
    # misspelled famous name on an unknown domain is decisive on its own.
    if heur.get("risk_floor"):
        risk = max(risk, heur["risk_floor"])

    # Two-factor verdict: a hard "phishing" block requires the rule layer to
    # corroborate the ML (any evidence beyond the not-popular signal). An
    # ML-only alarm on an unknown domain becomes a "suspicious" warning —
    # defense against training-distribution artifacts on small legit sites.
    if (heur["tier"] == "unknown" and heur["score"] <= 8
            and risk >= config.THRESHOLD_PHISHING):
        risk = 64.0
        heur["reasons"].append({
            "rule": "ML model is alarmed but no rule evidence corroborates it — "
                    "shown as a warning, never blocked on ML alone",
            "severity": "medium", "weight": 0})

    result = {
        "type": "url",
        "input": url,
        "verdict": _verdict(risk),
        "risk_score": risk,
        "ml_probability": round(ml_prob, 4),
        "heuristic_score": heur["score"],
        "per_model": per_model,
        "reasons": heur["reasons"],
        "trusted_domain": heur["trusted_domain"],
        "trust_tier": heur["tier"],
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
    if explain:
        result["top_tokens"] = _top_url_tokens(bundle, row)
    return result


# ------------------------------------------------------------------ email
def _top_email_tokens(bundle, text: str, k: int = 8) -> list[dict]:
    try:
        pipe = bundle["models"]["logistic_regression"]
        vec = pipe.named_steps["vec"]
        clf = pipe.named_steps["clf"]
        X = vec.transform([text])
        contrib = X.toarray()[0] * clf.coef_[0]
        names = vec.get_feature_names_out()
        idx = np.argsort(-np.abs(contrib))[:k * 2]
        out, seen = [], set()
        for i in idx:
            if abs(contrib[i]) < 1e-6:
                continue
            name = names[i].split("__", 1)[-1].strip()
            if len(name) < 3 or name in seen or name in ("urltoken", "numtoken", "emailtoken"):
                continue
            seen.add(name)
            out.append({"token": name,
                        "direction": "phishing" if contrib[i] > 0 else "legitimate",
                        "weight": round(float(contrib[i]), 3)})
            if len(out) >= k:
                break
        return out
    except Exception:
        return []


def predict_email(subject: str, body: str, sender: str = "", explain: bool = True) -> dict:
    t0 = time.perf_counter()
    bundle = _load("email")
    text = clean_email_text(subject, body)

    per_model = {name: round(float(est.predict_proba([text])[0, 1]), 4)
                 for name, est in bundle["ensemble"].estimators}
    ml_prob = float(bundle["ensemble"].predict_proba([text])[0, 1])

    heur = heuristics.score_email(subject, body, sender)
    risk = _blend(ml_prob, heur["score"])

    result = {
        "type": "email",
        "input": (subject or "(no subject)")[:120],
        "verdict": _verdict(risk),
        "risk_score": risk,
        "ml_probability": round(ml_prob, 4),
        "heuristic_score": heur["score"],
        "per_model": per_model,
        "reasons": heur["reasons"],
        "signals": {k: v for k, v in heur["signals"].items()
                    if not isinstance(v, list) or v},
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
    if explain:
        result["top_tokens"] = _top_email_tokens(bundle, text)
    return result
