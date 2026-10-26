"""Export the trained linear members (LR + calibrated Linear SVM) to a
compact JSON the browser extension evaluates fully on-device.

Why linear members only: their decision functions are dot products, so the
whole detector compresses to <2 MB of n-gram weights and runs in <1 ms of
JavaScript — no server, no network, no URL ever leaving the browser. The
Random-Forest member stays server-side (trees don't compress well); the
export therefore re-weights the remaining members (LR:1, SVM:4 — their
validation weights) and THIS script re-evaluates that exact on-device
model on the untouched test set, so the extension's published accuracy is
measured, not assumed.

Pruning: only the top-K n-grams by maximum absolute weight across the
exported members are kept (K=40,000 URL / 30,000 email). The pruned
document vector is re-normalised over the kept vocabulary — the evaluation
below reproduces exactly what the JavaScript engine computes.

Outputs:
    extension/model/url_model.json
    extension/model/email_model.json
    extension/model/parity_samples.json   (inputs + expected probabilities,
                                           asserted by tests/parity_test.js)
    results/extension_metrics.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scipy.special import expit
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from phishguard import config
from phishguard.features.url_features import URL_FEATURE_NAMES
from phishguard.training.train_url import build_design_matrix

EXT_MODEL_DIR = config.ROOT_DIR / "extension" / "model"
K_URL = 40_000
K_EMAIL = 30_000
R = 6  # float rounding (significant digits)


def _round(x) -> float:
    return float(f"{x:.{R}g}")


def _sigmoid_calibrated(d: np.ndarray, a: float, b: float) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(a * d + b))


# --------------------------------------------------------------------- URL
def export_url() -> dict:
    bundle = joblib.load(config.URL_MODEL_PATH)
    lr_pipe = bundle["models"]["logistic_regression"]
    svm_pipe = bundle["models"]["svm_linear"]
    prep = lr_pipe.named_steps["prep"]
    tfidf = prep.named_transformers_["tfidf"]
    scaler = prep.named_transformers_["num"]
    lr = lr_pipe.named_steps["clf"]
    svm = svm_pipe.named_steps["clf"]

    n_tfidf = len(tfidf.vocabulary_)
    folds = svm.calibrated_classifiers_
    w_lr = lr.coef_[0]
    w_s = [cc.estimator.coef_[0] for cc in folds]
    calib = [(float(cc.calibrators[0].a_), float(cc.calibrators[0].b_))
             for cc in folds]

    # ----- prune tfidf block
    mag = np.abs(w_lr[:n_tfidf])
    for w in w_s:
        mag = np.maximum(mag, np.abs(w[:n_tfidf]))
    keep = np.sort(np.argsort(-mag)[:K_URL])
    inv_vocab = {idx: tok for tok, idx in tfidf.vocabulary_.items()}
    idf = tfidf.idf_

    features = {
        inv_vocab[i]: [_round(idf[i]), _round(w_lr[i]),
                       _round(w_s[0][i]), _round(w_s[1][i])]
        for i in keep
    }

    model = {
        "kind": "url",
        "version": "1.1.0",
        "ngram": {"analyzer": "char_wb", "min": 3, "max": 5,
                  "sublinear_tf": True},
        "features": features,
        "lexical": {
            "names": URL_FEATURE_NAMES,
            "mean": [_round(x) for x in scaler.mean_],
            "scale": [_round(x) for x in scaler.scale_],
            "lr": [_round(x) for x in w_lr[n_tfidf:]],
            "svm0": [_round(x) for x in w_s[0][n_tfidf:]],
            "svm1": [_round(x) for x in w_s[1][n_tfidf:]],
        },
        "intercepts": {"lr": _round(lr.intercept_[0]),
                       "svm0": _round(folds[0].estimator.intercept_[0]),
                       "svm1": _round(folds[1].estimator.intercept_[0])},
        "calibration": {"svm0": [_round(calib[0][0]), _round(calib[0][1])],
                        "svm1": [_round(calib[1][0]), _round(calib[1][1])]},
        "ensemble_weights": {"lr": 1, "svm": 4},
    }

    # ----- honest evaluation of the pruned on-device model
    df = pd.read_parquet(config.DATA_PROCESSED / "urls.parquet")
    X = build_design_matrix(df["url"])
    y = df["label"].values
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y,
        random_state=config.RANDOM_STATE)

    V = tfidf.transform(X_test["url"])          # rows already L2-normalised
    Vk = V[:, keep]
    norms = np.sqrt(Vk.multiply(Vk).sum(axis=1)).A.ravel()
    norms[norms == 0] = 1.0
    S = scaler.transform(X_test[URL_FEATURE_NAMES])

    def decision(w_full):
        t = (Vk @ w_full[:n_tfidf][keep]) / norms
        return t + S @ w_full[n_tfidf:]

    d_lr = decision(w_lr) + lr.intercept_[0]
    p_lr = expit(d_lr)
    p_svm = np.mean([
        _sigmoid_calibrated(decision(w_s[k]) + folds[k].estimator.intercept_[0],
                            *calib[k])
        for k in range(2)], axis=0)
    p = (1 * p_lr + 4 * p_svm) / 5
    pred = (p >= 0.5).astype(int)

    metrics = {
        "model": "extension_on_device (pruned LR+SVM, 40K n-grams)",
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, p), 4),
        "kept_ngrams": int(len(keep)),
    }
    print("[url] on-device model:", metrics)

    # parity samples for the JS engine test
    sample_idx = np.random.RandomState(0).choice(len(X_test), 60, replace=False)
    samples = [{"url": X_test["url"].iloc[int(i)], "p": round(float(p[int(i)]), 6)}
               for i in sample_idx]
    return {"model": model, "metrics": metrics, "samples": samples}


# ------------------------------------------------------------------- email
def export_email() -> dict:
    bundle = joblib.load(config.EMAIL_MODEL_PATH)
    lr_pipe = bundle["models"]["logistic_regression"]
    vec = lr_pipe.named_steps["vec"]
    lr = lr_pipe.named_steps["clf"]

    word = dict(vec.transformer_list)["word"]
    char = dict(vec.transformer_list)["char"]
    n_word = len(word.vocabulary_)
    w = lr.coef_[0]

    mag = np.abs(w)
    keep = np.sort(np.argsort(-mag)[:K_EMAIL])
    keep_word = keep[keep < n_word]
    keep_char = keep[keep >= n_word] - n_word

    inv_w = {i: t for t, i in word.vocabulary_.items()}
    inv_c = {i: t for t, i in char.vocabulary_.items()}

    model = {
        "kind": "email",
        "version": "1.1.0",
        "word": {inv_w[int(i)]: [_round(word.idf_[int(i)]), _round(w[int(i)])]
                 for i in keep_word},
        "char": {inv_c[int(i)]: [_round(char.idf_[int(i)]), _round(w[n_word + int(i)])]
                 for i in keep_char},
        "intercept": _round(lr.intercept_[0]),
        "ngram_word": [1, 2],
        "ngram_char": [3, 5],
    }

    df = pd.read_parquet(config.DATA_PROCESSED / "emails.parquet")
    X, y = df["text"], df["label"].values
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y,
        random_state=config.RANDOM_STATE)

    def pruned_block(vectorizer, keep_local, texts):
        V = vectorizer.transform(texts)
        Vk = V[:, keep_local]
        norms = np.sqrt(Vk.multiply(Vk).sum(axis=1)).A.ravel()
        norms[norms == 0] = 1.0
        return Vk, norms

    Vw, nw = pruned_block(word, keep_word, X_test)
    Vc, nc = pruned_block(char, keep_char, X_test)
    d = (Vw @ w[keep_word]) / nw + (Vc @ w[n_word + keep_char]) / nc + lr.intercept_[0]
    p = expit(d)
    pred = (p >= 0.5).astype(int)

    metrics = {
        "model": "extension_on_device (pruned LR, 30K features)",
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, p), 4),
        "kept_features": int(len(keep)),
    }
    print("[email] on-device model:", metrics)

    sample_idx = np.random.RandomState(0).choice(len(X_test), 40, replace=False)
    texts_trunc = [X_test.iloc[int(i)][:1500] for i in sample_idx]
    Vw2, nw2 = pruned_block(word, keep_word, texts_trunc)
    Vc2, nc2 = pruned_block(char, keep_char, texts_trunc)
    d2 = (Vw2 @ w[keep_word]) / nw2 + (Vc2 @ w[n_word + keep_char]) / nc2 + lr.intercept_[0]
    p2 = expit(d2)
    samples = [{"text": t, "p": round(float(pp), 6)}
               for t, pp in zip(texts_trunc, p2)]
    return {"model": model, "metrics": metrics, "samples": samples}


def main() -> None:
    EXT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    url = export_url()
    email = export_email()

    (EXT_MODEL_DIR / "url_model.json").write_text(
        json.dumps(url["model"], separators=(",", ":")))
    (EXT_MODEL_DIR / "email_model.json").write_text(
        json.dumps(email["model"], separators=(",", ":")))
    (EXT_MODEL_DIR / "parity_samples.json").write_text(json.dumps(
        {"url": url["samples"], "email": email["samples"]}, indent=1))
    (config.RESULTS_DIR / "extension_metrics.json").write_text(json.dumps(
        {"url": url["metrics"], "email": email["metrics"]}, indent=2))

    for f in ("url_model.json", "email_model.json"):
        size = (EXT_MODEL_DIR / f).stat().st_size / 1e6
        print(f"[size] {f}: {size:.2f} MB")


if __name__ == "__main__":
    main()
