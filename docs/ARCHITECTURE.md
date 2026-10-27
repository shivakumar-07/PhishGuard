# PhishGuard — System Architecture

![Architecture](images/architecture.png)

## Five-stage pipeline

### Stage 1 — Data Collection (`setup_data.py`, `phishguard/training/prepare_data.py`)
| Corpus | Size | Role |
|---|---|---|
| Malicious/benign URL corpus ([faizann24](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs)) | 411,242 URLs after cleaning | URL detector training |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (CC-BY-4.0) | 12,265 **real-world** phishing emails | malicious email class |
| [Enron spam/ham corpus](https://github.com/MWiechmann/enron_spam_data) | 16,545 ham + 8,000 sampled spam | legitimate class + deceptive-bulk augmentation |

Cleaning: dedup, length limits, label normalisation; emails are merged
(subject + body), lower-cased, and volatile tokens are generalised
(`urltoken`, `emailtoken`, `numtoken`) so models learn *patterns*, not
addresses. Output is written to `data/processed/*.parquet`.

### Stage 2 — Feature Extraction (`phishguard/features/`)
**URLs — two complementary views**
1. *Lexical statistics* (30 hand-crafted features): length stats, character
   counts, digit/letter ratios, subdomain depth, IP-host, non-standard port,
   `@` trick, double-slash redirect, `https` token spoof, hyphenated domain,
   shortener and suspicious-TLD lookups, phishing-keyword count,
   **brand-outside-registered-domain** impersonation check, hex encodings,
   Shannon entropy of URL and hostname.
2. *Character patterns*: char 3–5-gram TF-IDF (150K features) over the raw
   URL string — catches lookalike spellings (`paypa1`, `micros0ft`) that
   hand-crafted features miss.

**Emails** — word 1–2-gram TF-IDF (100K) + char 3–5-gram TF-IDF (100K) in a
`FeatureUnion` over the cleaned text.

### Stage 3 — Hybrid Model Training (`phishguard/training/`)
Per the hybrid approach of Karim et al. (IEEE Access, 2023), several
classifier families are trained and combined by **weighted soft voting**
(weighted average of calibrated probabilities; the weights are selected on
a 10% validation split carved out of the training data, so the test set
stays untouched):

| | URL detector | Email detector |
|---|---|---|
| A | Logistic Regression (TF-IDF + lexical) | Logistic Regression |
| B | Linear SVM, Platt-calibrated (TF-IDF + lexical) | Linear SVM, Platt-calibrated |
| C | Random Forest (lexical view) | Multinomial Naive Bayes |
| baseline | Decision Tree | Decision Tree |
| **final** | **soft vote A+B+C** | **soft vote A+B+C** |

Voting is implemented over *pre-fitted* pipelines
(`phishguard/inference/ensemble.py`) — equivalent to sklearn's
`VotingClassifier(voting="soft")` with weights, but each model trains
once and the heavy TF-IDF view is fitted once and shared.
Evaluation: stratified 80/20 hold-out (with a further 90/10 fit/validation
split inside the training portion); accuracy, precision, recall, F1,
ROC-AUC, confusion matrices, ROC curves and RF feature importances are
saved to `results/`.

### Stage 4 — Real-Time Prediction (`phishguard/inference/predictor.py`)
Models are loaded once (LRU-cached) and score an input in ~1–40 ms. The ML
probability is blended with a transparent **heuristic rule layer**
(`heuristics.py`, 16 rules with weights and human-readable reasons):

```
risk = 0.75 · P(phishing | ensemble) · 100 + 0.25 · rule_score
verdict = phishing (risk ≥ 65) | suspicious (risk ≥ 40) | safe
```

A small trusted-domain allowlist caps the ML probability for well-known
registered domains, cutting false positives on popular sites. Every
response carries per-model probabilities, triggered rules, and the top
TF-IDF tokens pushing the LR member's decision — full explainability.

### Stage 5 — Dashboard & Alerts (`phishguard/api/`)
* **FastAPI** REST API (`/api/scan/url`, `/api/scan/email`, `/api/scans`,
  `/api/stats`, `/api/model-info`, `/health`) with OpenAPI docs at `/docs`.
* **SQLite** scan history (stdlib, thread-safe).
* **WebSocket** `/ws/live` broadcasts each verdict to all connected
  dashboards instantly.
* **Dashboard** (vanilla JS + vendored Chart.js, fully offline): scan
  console with risk dial and evidence panel, verdict tiles, activity
  timeline, verdict distribution, live threat feed.

### Stage 5½ — Global domain trust (`phishguard/trust.py`, `scripts/build_trust_assets.py`)
A reputation layer that generalises the allowlist to the whole internet,
offline. `build_trust_assets.py` compiles two research-grade datasets:
the **Mozilla Public Suffix List** (exact/wildcard/exception rules →
`psl.json`, correct registered-domain parsing for every TLD) and the
**Chrome UX Report global top-1M origins**, reduced to 760K unique
registered domains and packed into a **1.4 MB Bloom filter**
(`topdomains.bloom`; FNV-1a + djb2|1 Kirsch-Mitzenmacher double hashing,
k=10, FP≈0.1%). At scan time the registered domain maps to a tier:
*curated* (verified critical domains, restricted registries — ML capped
at 0.15, pattern rules off), *popular* (top-1M — ML capped at 0.30,
noisy rules off), or *unknown* (full rules + a "not in the top-1M"
signal). Brand/keyword rules read host+path only — query strings are
user content. The same two asset files ship byte-identical in the
Python package and the browser extension, and a cross-language parity
test covers PSL wildcards, exceptions, IDN hosts and Bloom lookups.

### Stage 6 — On-device delivery (`extension/`, `phishguard/export/`)
The linear members (LR + both calibrated SVM folds) compress to pure dot
products, so `export_js_model.py` prunes the TF-IDF vocabulary to the
top-weighted n-grams (40K URL / 30K email), re-normalises over the kept
vocabulary, and emits 2.7 MB of JSON. `extension/lib/engine.js` is an
exact JavaScript port of the pipeline (char_wb/word TF-IDF, 30 lexical
features, heuristics, risk blend) — parity with Python is asserted to
~1e-6 by `extension/tests/parity_test.mjs`, and the pruned model is
re-evaluated on the held-out test sets (URL 98.49% / email 99.30%
accuracy; `results/extension_metrics.json`). The Manifest-V3 extension
scores every navigation in ~1 ms, blocks phishing verdicts behind a
warning interstitial, outlines dangerous links on pages, and scans pasted
emails — with **zero network calls**, which is simultaneously the
privacy story and the scalability story (no server in the loop).

## Design decisions
* **Lexical-only URL features** (no WHOIS/domain-age look-ups): keeps
  scoring offline, deterministic and <1 ms; live reputation checks are
  listed as future work.
* **Two-view hybrid** rather than one deep model: interpretable, trains in
  minutes on CPU, and matches the referenced literature.
* **Rule layer separate from ML**: rules give evidence users can read, and
  they catch structural red flags (raw-IP links, punycode) that are
  under-represented in training data.
* **Vendored Chart.js**: the demo works with no internet access.

## Repository layout
```
PhishGuard/
├── setup_data.py              # Stage 1: dataset downloads
├── phishguard/
│   ├── config.py              # paths, thresholds, weights
│   ├── features/              # Stage 2: url_features, email_features
│   ├── training/              # Stages 1–3: prepare_data, train_url, train_email, plots
│   ├── inference/             # Stage 4: predictor, heuristics, ensemble
│   └── api/                   # Stage 5: FastAPI app, SQLite db, static dashboard
├── models/                    # trained ensembles (.joblib)
├── results/                   # metrics JSON + evaluation plots
├── scripts/                   # train_all.sh, demo_requests.py
├── tests/                     # pytest suite (features, heuristics, API)
└── docs/                      # report, architecture, viva Q&A, images
```
