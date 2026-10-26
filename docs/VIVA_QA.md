# PhishGuard — Viva / Review Q&A Preparation

Likely examiner questions with crisp answers. Numbers refer to
`results/url_metrics.json` and `results/email_metrics.json`.

### 1. Why hybrid ML instead of a single model?
Different classifier families make different mistakes: linear models (LR,
SVM) excel on sparse high-dimensional TF-IDF patterns, tree ensembles (RF)
capture non-linear interactions among numeric lexical features. Averaging
calibrated probabilities (soft voting) cancels uncorrelated errors, which
raises F1 and reduces variance — the core finding of Karim et al. (IEEE
Access, 2023) that this project builds on.

### 2. Why soft voting and not stacking?
Weighted soft voting is nearly parameter-free (one small weight grid tuned
on a validation split), robust with a few strong calibrated base models,
and keeps every member interpretable. Stacking adds a meta-learner that
needs out-of-fold predictions (≈3–5× training cost) for a marginal gain on
these datasets. Stacking is noted as future work.

### 2b. How are the voting weights chosen — isn't that test leakage?
No: a 10% validation split is carved out of the *training* portion; models
fit on the remaining 90%, a small weight grid is scored on the validation
split by F1, and only then is the frozen ensemble evaluated once on the
untouched test set.

### 3. How do you handle class imbalance in the URL dataset (≈16% phishing)?
Stratified train/test split preserves the ratio; we report precision,
recall, F1 and ROC-AUC rather than accuracy alone; the final verdict
threshold on the blended risk score is tunable in `config.py` to trade
precision against recall.

### 4. What stops a legitimate site like google.com being flagged?
Three layers: the ML models themselves (trained on 344K legitimate URLs), a
trusted-domain allowlist that caps the ML probability for well-known
registered domains, and the three-band verdict (safe / suspicious /
phishing) so borderline scores are surfaced as "suspicious" instead of a
hard block.

### 5. Why both hand-crafted features AND character TF-IDF for URLs?
Hand-crafted features encode *domain knowledge* (IP hosts, @ tricks, brand
spoofing) and stay meaningful on out-of-distribution URLs; char n-grams
learn *string patterns* like `paypa1` or `-secure-` automatically. Ablation
in training logs shows the combination outperforms either view alone.

### 6. Your email data mixes phishing_pot and Enron — isn't that distribution shift?
Yes, deliberately mitigated: subjects+bodies are cleaned and volatile tokens
(URLs, addresses, long numbers) are replaced by placeholder tokens so the
model can't separate corpora by formatting artifacts. phishing_pot supplies
*real modern phishing*; Enron ham supplies real corporate legitimate mail;
a sample of Enron spam widens the malicious class so the detector also
catches scam/spam-style lures. Residual corpus bias is acknowledged in the
report's limitations section.

### 7. How is the system "real-time"?
Models are loaded once into memory; a scan is pure in-memory feature
extraction + matrix multiplication (~1–40 ms). Each verdict is persisted to
SQLite and pushed over a WebSocket to every open dashboard instantly — no
polling.

### 8. What is the heuristic layer for if ML already works?
(1) Explainability — each rule is a human-readable reason shown on the
dashboard; (2) safety net for structural red flags (raw-IP link, punycode,
embedded password form) that are rare in training data; (3) it lets the
system degrade gracefully: even with no model loaded the rules still score.

### 9. How would this scale to an enterprise mailbox?
The API is stateless (models in memory, history in a DB), so it scales
horizontally behind a load balancer; SQLite swaps for Postgres; the scan
endpoint can be called by a mail-gateway hook (e.g., Postfix milter or a
Microsoft 365 connector). The Dockerfile makes each node reproducible.

### 10. Limitations you would state honestly?
* Lexical-only URL analysis — no WHOIS age, DNS, TLS or page-content
  signals yet.
* English-centric email corpora.
* Static trusted-domain list.
* Attackers adapt: models need periodic retraining (the pipeline is one
  command, `scripts/train_all.sh`).

### 11. Future work?
Live reputation feeds (PhishTank/OpenPhish), page-content and screenshot
analysis, transformer embeddings (DistilBERT) as a fourth ensemble member,
stacking meta-learner, browser extension front-end, multi-language support,
feedback loop (analyst marks false positives → periodic re-training).

### 12. Why FastAPI?
Async (WebSockets + non-blocking scans via `asyncio.to_thread`), automatic
OpenAPI docs for examiners to try the API at `/docs`, Pydantic request
validation, and production-grade `uvicorn` server — all in very little code.

### 13. What exactly does "risk = 0.75·ML + 0.25·rules" mean?
The ensemble outputs P(phishing)∈[0,1]; the rule layer outputs 0–100.
The blend `0.75·100·P + 0.25·rules` keeps ML primary while letting strong
structural evidence lift borderline cases over the verdict thresholds
(≥65 phishing, ≥40 suspicious). Weights/thresholds live in `config.py` and
were sanity-checked against the held-out test sets.

### 14. How do you know the model isn't overfitting?
Stratified 80/20 hold-out never seen in training; near-identical
train/validation behaviour across CV folds inside calibration; multiple
model families agreeing (ensemble members' individual test metrics are all
reported); depth/leaf regularisation on trees; `min_df` and `max_features`
caps on TF-IDF.

### 14b. How does the browser extension run the model without a server?
Both strong members are linear, so each decision is a dot product:
`export_js_model.py` exports the TF-IDF vocabulary (pruned to the
top-weighted 40K/30K n-grams), idf values, scaler statistics, coefficients
and Platt-calibration parameters as JSON, and `extension/lib/engine.js`
recomputes the exact same pipeline in JavaScript (~1 ms per URL). The
pruned model is re-evaluated on the held-out test set (URL 98.49%, email
99.30% accuracy), and a parity test asserts JS and Python agree to ~1e-6.
On-device inference is also the privacy feature: no URL or email ever
leaves the browser.

### 15. Could an attacker evade PhishGuard?
Adversarial evasion is possible against any static classifier — e.g.
hosting on a reputable compromised domain. Mitigations: ensemble of
heterogeneous views raises evasion cost, heuristics catch structural
tricks, and the retraining pipeline incorporates new samples quickly. This
is discussed under limitations/future work.
