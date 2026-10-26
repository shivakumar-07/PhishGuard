# PhishGuard — Demo-Day Guide

A 5-minute script for presenting the working system to reviewers.

## Before the session

```bash
cd PhishGuard
pip install -r requirements.txt     # once
uvicorn phishguard.api.main:app --port 8000
```

Open **http://localhost:8000** in a full-screen browser tab.
(Trained models ship in `models/` — no training needed to demo.)

Optional second terminal, ready to run:

```bash
python scripts/demo_requests.py     # streams 20 scripted scans
```

## Suggested flow

1. **Open on the dashboard** (10s). Point out the live pill (WebSocket
   connected), the model-accuracy badges in the header, and the empty feed.

2. **Scan a phishing URL** (60s). Click *phishy example* → **Scan URL**.
   Walk through the verdict card top-to-bottom:
   * risk dial and three-band verdict;
   * ML ensemble vs rule-layer split;
   * the three per-model probability bars — "this is the hybrid ensemble,
     three models voting";
   * the evidence list — brand-spoof rule, suspicious TLD, keywords;
   * the token chips — "these are the exact character patterns the
     Logistic Regression member learned from 411,000 URLs."

3. **Scan a safe URL** (20s). *safe example* → point out the trusted-domain
   reason and the low dial.

4. **Scan a phishing email** (45s). Switch to *Email*, *phishy example* →
   urgency language, credential request, raw-IP link, free-mail sender
   claiming a brand — all caught by NLP + rules together.

5. **Go real-time** (45s). Run `python scripts/demo_requests.py` in the
   second terminal. The feed, tiles and charts update live with no refresh
   — "this is the monitoring view a security team would keep open."

6. **Show the engineering** (30s). Open http://localhost:8000/docs
   (auto-generated OpenAPI). Mention the test suite
   (`python -m pytest tests/ -v`, all green) and the one-command retraining
   pipeline (`scripts/train_all.sh`).

7. **Close on results** (30s). Open `results/url_model_comparison.png` —
   "every individual model is strong, the soft-voting hybrid is stronger;
   that is the thesis of the project, verified on a held-out test set."

## If asked "can it fail?"

Yes — say so confidently: lexical-only URL analysis, English-centric email
corpora, adversarial evasion. Then point to `docs/VIVA_QA.md` Q10/Q15 and
the retraining pipeline. Honest limitations + a mitigation path read far
better than claimed perfection.
