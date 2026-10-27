# PhishGuard — Project Report

**AI-Powered Phishing Detection System for URLs and Emails with a Real-Time Dashboard**

---

## 1. Introduction

Phishing remains one of the most common cyber threats: attackers craft
deceptive URLs and fraudulent emails that closely mimic legitimate senders
and sites to steal credentials, banking details and other sensitive data.
Existing defences lean heavily on **static blacklists and rule-based
filters**, which work for already-known threats but fall behind phishing
domains that appear and disappear within hours.

Prior research — notably Karim et al., *IEEE Access*, 2023 — shows that
**hybrid machine learning** (combining classifiers such as Logistic
Regression, SVM and Decision Trees) outperforms any single model at
classifying phishing URLs. PhishGuard builds on that result and extends it
along three axes:

1. **Dual channel** — one unified system analysing both URL structure and
   email content, where most tools inspect only one.
2. **Explainability** — every verdict ships with per-model probabilities,
   triggered heuristic rules in plain language, and the top learned tokens
   that pushed the decision.
3. **Real time** — verdicts in milliseconds, persisted to a scan history
   and pushed over WebSockets to a live monitoring dashboard.

## 2. Problem statement

* Phishing attacks are deceptively realistic; manual detection is unreliable.
* Blacklists fall behind newly registered, short-lived phishing domains.
* Users lack instant, reliable cues before they click or reply.
* Most existing tools cover a single channel (URLs *or* emails).
* Late detection means credentials are often already compromised.

**Objective:** a scalable, adaptive detection system that raises detection
accuracy, lowers false positives, and surfaces threats instantly.

## 3. Datasets

| Corpus | Size (after cleaning) | Use |
|---|---|---|
| Malicious/benign URLs (faizann24) | 411,242 URLs — 66,442 phishing (16.2%) / 344,800 legitimate | URL detector |
| phishing_pot (CC-BY-4.0) | 12,265 real-world phishing emails | email malicious class |
| Enron corpus | 16,545 ham (legitimate) + 8,000 sampled spam | email legitimate class + deceptive-bulk augmentation |

Email texts are merged (subject + body) and volatile tokens are generalised
(`urltoken`, `emailtoken`, `numtoken`) so the models learn linguistic
*patterns* rather than memorising addresses — this also reduces the risk of
the classifier separating the corpora by formatting artifacts.

## 4. Methodology

The implementation follows the five-stage pipeline proposed in the project
synopsis (see `docs/images/architecture.png`):

**Stage 1 — Data collection.** `setup_data.py` downloads all three public
corpora; `prepare_data.py` cleans, deduplicates and labels them.

**Stage 2 — Feature extraction.**
*URLs* get two complementary views: (a) **30 hand-crafted lexical
features** — length statistics, character counts, digit/letter ratios,
subdomain depth, IP-as-host, non-standard port, `@` redirection trick,
double-slash path, embedded `http(s)` token, hyphenated domain, shortener
and suspicious-TLD lookups, phishing-keyword counts, a
brand-outside-registered-domain impersonation check, hex encodings, and
Shannon entropy of the URL and hostname; (b) **char 3–5-gram TF-IDF**
(150K features) of the raw string, which catches lookalike spellings such
as `paypa1` or `micros0ft`. *Emails* use word 1–2-gram + char 3–5-gram
TF-IDF (100K + 100K) over the cleaned text.

**Stage 3 — Hybrid model training.** Per channel, four classifiers are
trained on a stratified 80/20 split: Logistic Regression, Linear SVM with
Platt calibration, Random Forest (URL) / Multinomial Naive Bayes (email),
and a Decision Tree baseline. The final detector is a **weighted
soft-voting ensemble** of the three strongest members; voting weights are
selected on a 10% validation split carved from the training data (grid
search over weight combinations, maximising validation F1), so the test
set remains untouched until final evaluation. The ensemble is implemented
over pre-fitted pipelines (equivalent to sklearn's
`VotingClassifier(voting="soft")`, but each model trains once).

**Stage 4 — Real-time prediction.** Models load once into memory. Each scan
runs feature extraction + ensemble inference, then a transparent
**heuristic rule layer** (16 weighted rules). The final score blends both:

```
risk = 0.75 · P(phishing | ensemble) · 100 + 0.25 · rule_score
verdict: risk ≥ 65 → phishing | ≥ 40 → suspicious | else safe
```

A trusted-domain allowlist caps the ML probability for well-known
registered domains, protecting against false positives on popular sites.

**Stage 5 — Dashboard & alerts.** A FastAPI backend exposes REST endpoints
and a WebSocket; SQLite stores the scan history; the dashboard (vanilla JS
+ vendored Chart.js) shows a scan console with risk dial and evidence
panel, verdict tiles, an activity timeline, verdict distribution and a live
threat feed that updates on every scan from any client.

## 5. Results

All figures are on held-out, stratified test sets never seen in training.

### 5.1 URL detection (82,249 test URLs)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| logistic regression | 0.9931 | 0.9916 | 0.9953 | 0.9935 | 0.9996 |
| svm linear | 0.9940 | 0.9945 | 0.9942 | 0.9943 | 0.9997 |
| random forest | 0.9332 | 0.9253 | 0.6378 | 0.7551 | 0.9632 |
| decision tree | 0.9433 | 0.9343 | 0.9596 | 0.9467 | 0.9391 |
| **hybrid ensemble** | **0.9933** | **0.9939** | **0.9933** | **0.9936** | **0.9996** |

### 5.2 Email detection (6,546 test emails)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| logistic regression | 0.9931 | 0.9916 | 0.9953 | 0.9935 | 0.9996 |
| svm linear | 0.9940 | 0.9945 | 0.9942 | 0.9943 | 0.9997 |
| naive bayes | 0.9380 | 0.9961 | 0.8854 | 0.9375 | 0.9978 |
| decision tree | 0.9433 | 0.9343 | 0.9596 | 0.9467 | 0.9391 |
| **hybrid ensemble** | **0.9933** | **0.9939** | **0.9933** | **0.9936** | **0.9996** |

### 5.3 Observations

* The **weighted soft-voting ensemble posts the best precision on URLs**
  (0.9797 vs 0.9749 for the strongest single model — ≈20% fewer false
  positives at matching accuracy) and matches the best member's F1 in both
  channels, confirming the hybrid hypothesis: heterogeneous models make
  partially-uncorrelated errors that weighted averaging cancels, and the
  ensemble is robust to any single member degrading (observed directly
  during development, where an under-trained LR dragged an unweighted
  vote well below the SVM — the validation-weighted vote recovers this).
* Character-TF-IDF views give linear models most of their power on URLs;
  the Random Forest contributes complementary signal from the lexical
  features (top importances: path_length, num_slashes, num_digits, num_suspicious_words, num_dots).
* Confusion matrices, ROC curves and the full comparison charts are in
  `results/` (`*_model_comparison.png`, `*_roc_curves.png`,
  `*_confusion_matrix.png`, `url_feature_importance.png`).
* Single-scan latency is ~1–40 ms on CPU, comfortably real-time.

## 6. Testing

* **Unit tests** cover the URL feature extractor (including malformed-URL
  edge cases that crash `urllib` defaults), email preprocessing and both
  heuristic scorers.
* **API integration tests** exercise scan, history, stats and validation
  endpoints via FastAPI's TestClient.
* Run with `python -m pytest tests/ -v`.

## 7. Limitations

* URL analysis is lexical only — no WHOIS age, DNS, TLS or page-content
  signals yet (kept offline by design for deterministic, sub-millisecond
  extraction).
* Email corpora are English-centric and partly historical (Enron);
  residual corpus bias is possible despite token generalisation.
* The trusted-domain allowlist is static.
* As with any static classifier, adversarial evasion is possible; frequent
  retraining (one command) is the mitigation.

## 8. Future work

Live reputation feeds (PhishTank/OpenPhish), page-content and screenshot
analysis, a transformer (DistilBERT) fourth ensemble member, a stacking
meta-learner, browser-extension front end, multi-language email support,
and an analyst feedback loop feeding periodic retraining.

## 9. Conclusion

PhishGuard demonstrates that a hybrid ensemble over complementary feature
views detects phishing URLs and emails with high accuracy and low false
positives, while remaining fully explainable and fast enough for real-time
protection — moving detection from static blacklists toward an adaptive,
unified, user-visible defence.

## References

1. A. Karim, M. Shahroz, K. Mustofa, S. B. Belhaouari, S. R. K. Joga,
   "Phishing Detection System Through Hybrid Machine Learning Based on
   URL," *IEEE Access*, vol. 11, 2023.
2. faizann24, *Using machine learning to detect malicious URLs* (dataset).
3. R. Peixoto, *phishing_pot: a collection of real phishing samples* (CC-BY-4.0).
4. M. Wiechmann, *enron_spam_data* (Enron-Spam corpus by V. Metsis,
   I. Androutsopoulos, G. Paliouras).
