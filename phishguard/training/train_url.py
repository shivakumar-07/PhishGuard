"""Stage 3 (URLs) — Hybrid model training & evaluation.

Two complementary feature views are fed to three classifier families:

  view L (lexical statistics) : 30 hand-crafted numeric features
  view T (character patterns) : char 3-5-gram TF-IDF of the raw URL

  model A  Logistic Regression   on  T + L
  model B  Linear SVM (calibrated) on T + L
  model C  Random Forest          on  L
  model D  Decision Tree          on  L   (baseline, for comparison)

Final detector = soft-voting ensemble of A + B + C.
Outputs: models/url_ensemble.joblib, results/url_metrics.json, plots.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from phishguard import config
from phishguard.features.url_features import (URL_FEATURE_NAMES,
                                              extract_url_features_batch)
from phishguard.inference.ensemble import SoftVotingEnsemble
from phishguard.training.plots import (plot_confusion, plot_model_comparison,
                                       plot_roc_curves, plot_feature_importance)


def build_design_matrix(urls: pd.Series) -> pd.DataFrame:
    feats = extract_url_features_batch(urls.tolist())
    df = pd.DataFrame(feats, columns=URL_FEATURE_NAMES)
    df.insert(0, "url", urls.values)
    return df


def make_preprocessor(include_tfidf: bool) -> ColumnTransformer:
    transformers = []
    if include_tfidf:
        transformers.append((
            "tfidf",
            TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                            max_features=150_000, sublinear_tf=True,
                            dtype=np.float32),
            "url",
        ))
    transformers.append(("num", StandardScaler(), URL_FEATURE_NAMES))
    return ColumnTransformer(transformers)


def evaluate(name: str, model, X_test, y_test) -> dict:
    t0 = time.time()
    proba = model.predict_proba(X_test)[:, 1]
    latency_ms = (time.time() - t0) / len(y_test) * 1000
    pred = (proba >= 0.5).astype(int)
    m = {
        "model": name,
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
        "latency_ms_per_sample": round(latency_ms, 4),
    }
    print(f"  {name:28s} acc={m['accuracy']:.4f} prec={m['precision']:.4f} "
          f"rec={m['recall']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")
    return m


def main() -> None:
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/5] loading processed URL dataset ...")
    df = pd.read_parquet(config.DATA_PROCESSED / "urls.parquet")

    print("[2/5] extracting lexical features for", f"{len(df):,}", "URLs ...")
    X = build_design_matrix(df["url"])
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y,
        random_state=config.RANDOM_STATE)
    # carve a validation split out of TRAIN to tune ensemble weights
    # (the test set stays untouched until final evaluation)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.10, stratify=y_train,
        random_state=config.RANDOM_STATE)
    print(f"      fit={len(X_fit):,}  val={len(X_val):,}  test={len(X_test):,}")

    print("[3/5] training individual classifiers ...")
    models = {}

    # Fit each feature view ONCE and share it across models — identical
    # results to per-pipeline fitting, at a fraction of the cost.
    t0 = time.time()
    prep_full = make_preprocessor(include_tfidf=True).fit(X_fit)
    Xf_full = prep_full.transform(X_fit)
    Xv_full = prep_full.transform(X_val)
    print(f"      TF-IDF+lexical view fitted in {time.time()-t0:.1f}s "
          f"({Xf_full.shape[1]:,} features)")

    prep_num = make_preprocessor(include_tfidf=False).fit(X_fit)
    Xf_num = prep_num.transform(X_fit)
    Xv_num = prep_num.transform(X_val)

    t0 = time.time()
    lr = LogisticRegression(solver="liblinear", dual=True, C=1.0,
                            max_iter=3000, tol=1e-3,
                            random_state=config.RANDOM_STATE)
    lr.fit(Xf_full, y_fit)
    models["logistic_regression"] = Pipeline([("prep", prep_full), ("clf", lr)])
    print(f"      LR trained in {time.time()-t0:.1f}s")

    t0 = time.time()
    svm = CalibratedClassifierCV(
        LinearSVC(C=1.0, tol=1e-3, random_state=config.RANDOM_STATE), cv=2)
    svm.fit(Xf_full, y_fit)
    models["svm_linear"] = Pipeline([("prep", prep_full), ("clf", svm)])
    print(f"      SVM trained in {time.time()-t0:.1f}s")

    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=120, max_depth=24, min_samples_leaf=2,
        n_jobs=config.N_JOBS, random_state=config.RANDOM_STATE)
    rf.fit(Xf_num, y_fit)
    models["random_forest"] = Pipeline([("prep", prep_num), ("clf", rf)])
    print(f"      RF trained in {time.time()-t0:.1f}s")

    t0 = time.time()
    dt = DecisionTreeClassifier(max_depth=16, min_samples_leaf=4,
                                random_state=config.RANDOM_STATE)
    dt.fit(Xf_num, y_fit)
    models["decision_tree"] = Pipeline([("prep", prep_num), ("clf", dt)])
    print(f"      DT trained in {time.time()-t0:.1f}s")

    print("[4/5] building weighted soft-voting ensemble (LR + SVM + RF) ...")
    from sklearn.metrics import f1_score as _f1
    val_probas = [lr.predict_proba(Xv_full)[:, 1],
                  svm.predict_proba(Xv_full)[:, 1],
                  rf.predict_proba(Xv_num)[:, 1]]
    best_w, best_f1 = (1, 1, 1), -1.0
    for w in [(1, 1, 1), (1, 2, 1), (1, 3, 1), (2, 3, 1), (1, 2, 2),
              (2, 2, 1), (1, 4, 1), (2, 4, 1), (3, 4, 1), (1, 4, 2)]:
        p = np.average(val_probas, axis=0, weights=w)
        f1 = _f1(y_val, (p >= 0.5).astype(int))
        if f1 > best_f1:
            best_w, best_f1 = w, f1
    print(f"      validation-selected weights {best_w} (val F1={best_f1:.4f})")

    ensemble = SoftVotingEnsemble([
        ("logistic_regression", models["logistic_regression"]),
        ("svm_linear", models["svm_linear"]),
        ("random_forest", models["random_forest"]),
    ], weights=list(best_w))

    print("[5/5] evaluating on held-out test set ...")
    all_metrics = [evaluate(k, v, X_test, y_test) for k, v in models.items()]
    ens_metrics = evaluate("hybrid_ensemble", ensemble, X_test, y_test)
    all_metrics.append(ens_metrics)

    proba_ens = ensemble.predict_proba(X_test)[:, 1]
    pred_ens = (proba_ens >= 0.5).astype(int)
    cm = confusion_matrix(y_test, pred_ens).tolist()

    roc_points = {}
    for name, mdl in {**models, "hybrid_ensemble": ensemble}.items():
        p = mdl.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, p)
        idx = np.linspace(0, len(fpr) - 1, 200).astype(int)
        roc_points[name] = {"fpr": fpr[idx].round(4).tolist(),
                            "tpr": tpr[idx].round(4).tolist()}

    rf = models["random_forest"].named_steps["clf"]
    importances = sorted(zip(URL_FEATURE_NAMES, rf.feature_importances_.round(4)),
                         key=lambda t: -t[1])

    out = {
        "task": "url",
        "dataset_size": int(len(df)),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "class_balance": {"phishing": int(y.sum()), "legitimate": int(len(y) - y.sum())},
        "ensemble_weights": {"logistic_regression": best_w[0],
                             "svm_linear": best_w[1],
                             "random_forest": best_w[2]},
        "models": all_metrics,
        "ensemble_confusion_matrix": cm,
        "feature_importances": [{"feature": f, "importance": float(i)} for f, i in importances],
    }
    config.URL_METRICS_PATH.write_text(json.dumps(out, indent=2))

    plot_model_comparison(all_metrics, "URL models — test-set comparison",
                          config.RESULTS_DIR / "url_model_comparison.png")
    plot_roc_curves(roc_points, y_test, "URL detection — ROC curves",
                    config.RESULTS_DIR / "url_roc_curves.png")
    plot_confusion(cm, ["Legitimate", "Phishing"], "URL hybrid ensemble — confusion matrix",
                   config.RESULTS_DIR / "url_confusion_matrix.png")
    plot_feature_importance(importances[:15], "URL features — Random-Forest importance",
                            config.RESULTS_DIR / "url_feature_importance.png")

    joblib.dump({"ensemble": ensemble, "models": models,
                 "feature_names": URL_FEATURE_NAMES}, config.URL_MODEL_PATH,
                compress=3)
    size_mb = config.URL_MODEL_PATH.stat().st_size / 1e6
    print(f"[done] saved {config.URL_MODEL_PATH.name} ({size_mb:.1f} MB) + metrics + plots")


if __name__ == "__main__":
    main()
