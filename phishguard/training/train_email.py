"""Stage 3 (Emails) — NLP model training & evaluation.

Feature view: word 1-2-gram TF-IDF + char 3-5-gram TF-IDF (FeatureUnion)
over the cleaned subject+body text.

  model A  Logistic Regression
  model B  Linear SVM (calibrated)
  model C  Multinomial Naive Bayes   (classic text baseline)
  model D  Decision Tree             (baseline, for comparison)

Final detector = soft-voting ensemble of A + B + C.
Outputs: models/email_ensemble.joblib, results/email_metrics.json, plots.
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from phishguard import config
from phishguard.inference.ensemble import SoftVotingEnsemble
from phishguard.training.plots import (plot_confusion, plot_model_comparison,
                                       plot_roc_curves)


def make_vectorizer() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), max_features=100_000,
                                 sublinear_tf=True, min_df=2, dtype=np.float32)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                 max_features=100_000, sublinear_tf=True,
                                 min_df=2, dtype=np.float32)),
    ])


def evaluate(name: str, model, X_test, y_test) -> dict:
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    m = {
        "model": name,
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
    }
    print(f"  {name:28s} acc={m['accuracy']:.4f} prec={m['precision']:.4f} "
          f"rec={m['recall']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")
    return m


def main() -> None:
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/4] loading processed email dataset ...")
    df = pd.read_parquet(config.DATA_PROCESSED / "emails.parquet")
    X, y = df["text"], df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y,
        random_state=config.RANDOM_STATE)
    # validation split out of TRAIN for ensemble-weight tuning
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.10, stratify=y_train,
        random_state=config.RANDOM_STATE)
    print(f"      fit={len(X_fit):,}  val={len(X_val):,}  test={len(X_test):,}")

    print("[2/4] training individual classifiers ...")
    models = {}

    # Fit the TF-IDF view ONCE and share it across models.
    t0 = time.time()
    vec = make_vectorizer().fit(X_fit)
    Xf = vec.transform(X_fit)
    Xv = vec.transform(X_val)
    print(f"      TF-IDF view fitted in {time.time()-t0:.1f}s "
          f"({Xf.shape[1]:,} features)")

    for name, clf in [
        ("logistic_regression", LogisticRegression(solver="saga", C=4.0,
                                                   max_iter=100, tol=1e-3,
                                                   random_state=config.RANDOM_STATE)),
        ("svm_linear", CalibratedClassifierCV(
            LinearSVC(C=1.0, tol=1e-3, random_state=config.RANDOM_STATE), cv=3)),
        ("naive_bayes", MultinomialNB(alpha=0.1)),
        ("decision_tree", DecisionTreeClassifier(max_depth=32, min_samples_leaf=3,
                                                 random_state=config.RANDOM_STATE)),
    ]:
        t0 = time.time()
        clf.fit(Xf, y_fit)
        models[name] = Pipeline([("vec", vec), ("clf", clf)])
        print(f"      {name} trained in {time.time()-t0:.1f}s")

    print("[3/4] building weighted soft-voting ensemble (LR + SVM + NB) ...")
    from sklearn.metrics import f1_score as _f1
    member_names = ["logistic_regression", "svm_linear", "naive_bayes"]
    val_probas = [models[n].named_steps["clf"].predict_proba(Xv)[:, 1]
                  for n in member_names]
    best_w, best_f1 = (1, 1, 1), -1.0
    for w in [(1, 1, 1), (2, 2, 1), (1, 2, 1), (2, 1, 1), (3, 3, 1),
              (2, 3, 1), (3, 2, 1), (1, 3, 1), (4, 4, 1), (2, 2, 0)]:
        p = np.average(val_probas, axis=0, weights=w) if sum(w) else None
        if p is None:
            continue
        f1 = _f1(y_val, (p >= 0.5).astype(int))
        if f1 > best_f1:
            best_w, best_f1 = w, f1
    print(f"      validation-selected weights {best_w} (val F1={best_f1:.4f})")

    ensemble = SoftVotingEnsemble([
        (n, models[n]) for n in member_names
    ], weights=list(best_w))

    print("[4/4] evaluating on held-out test set ...")
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

    out = {
        "task": "email",
        "dataset_size": int(len(df)),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "class_balance": {"malicious": int(y.sum()), "legitimate": int(len(y) - y.sum())},
        "ensemble_weights": {"logistic_regression": best_w[0],
                             "svm_linear": best_w[1],
                             "naive_bayes": best_w[2]},
        "models": all_metrics,
        "ensemble_confusion_matrix": cm,
    }
    config.EMAIL_METRICS_PATH.write_text(json.dumps(out, indent=2))

    plot_model_comparison(all_metrics, "Email models — test-set comparison",
                          config.RESULTS_DIR / "email_model_comparison.png")
    plot_roc_curves(roc_points, y_test, "Email detection — ROC curves",
                    config.RESULTS_DIR / "email_roc_curves.png")
    plot_confusion(cm, ["Legitimate", "Phishing"],
                   "Email hybrid ensemble — confusion matrix",
                   config.RESULTS_DIR / "email_confusion_matrix.png")

    joblib.dump({"ensemble": ensemble, "models": models},
                config.EMAIL_MODEL_PATH, compress=3)
    size_mb = config.EMAIL_MODEL_PATH.stat().st_size / 1e6
    print(f"[done] saved {config.EMAIL_MODEL_PATH.name} ({size_mb:.1f} MB) + metrics + plots")


if __name__ == "__main__":
    main()
