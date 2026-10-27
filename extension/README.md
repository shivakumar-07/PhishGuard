# PhishGuard Browser Extension

**On-device AI phishing protection. 100% offline. Your URLs never leave your browser.**

The complete hybrid ML detector — Logistic Regression + calibrated Linear
SVM over 40,000 learned character patterns and 30 lexical features, plus the
16-rule heuristic layer — compiled into 2.7 MB of JSON and evaluated in
about **1 millisecond of JavaScript**. No server, no API key, no telemetry.

v2 adds **global domain trust, still fully offline**: the Mozilla Public
Suffix List for correct registered-domain parsing on every TLD, and the
world's 1M most-visited registered domains (Chrome UX Report) packed into
a 1.4 MB Bloom filter. Verified and popular domains get a benign prior and
freedom from noisy pattern rules; unknown domains get full scrutiny plus a
"not a top-1M site" signal. Query strings are never treated as evidence,
so searching "sbi online login" can't trip the detector on any site.

| On-device model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| URL detector | 98.48% | 0.9730 | 0.9319 | 0.9520 | 0.9958 |
| Email detector | 99.30% | 0.9933 | 0.9933 | 0.9933 | 0.9996 |

*(measured on the project's held-out test sets — 82,249 URLs / 6,546 emails —
by `phishguard/export/export_js_model.py`, which exports the model and
re-evaluates the exact pruned form the extension runs)*

## What it does

- **Blocks phishing pages before they load** — every navigation is scored
  locally; a phishing verdict swaps the page for a warning interstitial
  with the evidence and a "proceed anyway" escape hatch (per-session).
- **Badge on every page** — green `OK`, or the risk score on a yellow/red
  badge.
- **Marks dangerous links on the page** — confirmed-phishing links get a
  red outline and an explanatory tooltip (conservative by design: only
  "phishing" verdicts are marked, never "suspicious").
- **Right-click → "Scan link with PhishGuard"** — full report for any link
  without visiting it.
- **Popup console** — verdict for the current page with risk dial and
  evidence, paste-a-link scanner, and a paste-an-email scanner.
- **Protection toggle & local stats** — scans / phishing / suspicious
  counters, stored only in your browser.

## Install (Chrome, Edge, Brave — any Chromium browser)

1. Download or clone this repository.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select this `extension/` folder.
5. Pin the shield icon. Done — you're protected.

## Privacy

See [PRIVACY.md](PRIVACY.md). Summary: the extension makes **zero network
requests**. Models ship inside the package; scoring, statistics and
settings all live in local browser storage. Nothing is collected,
transmitted, or shared — there is no server to send anything to.

## How it works

```
navigation / link / pasted email
        │
        ▼
 lib/engine.js  — exact JS port of the Python pipeline
   ├─ 30 lexical URL features (entropy, brand-spoof, IP-host, …)
   ├─ char 3–5-gram TF-IDF (40K kept n-grams)   ┐  LR ┐
   ├─ word+char TF-IDF for emails (30K)          ┘ SVM ┴─ weighted vote
   └─ 16 heuristic rules (explainable evidence)
        │
        ▼
 risk = 0.75·ML·100 + 0.25·rules → safe / suspicious / phishing
```

Parity with the Python-trained model is asserted to ~1e-6 by
`tests/parity_test.mjs` (run `node extension/tests/parity_test.mjs`).

## Chrome Web Store readiness checklist

- [x] Manifest V3, minimal permissions (`tabs`, `storage`, `contextMenus`)
- [x] Single-purpose description; no remote code; no analytics
- [x] Privacy policy (PRIVACY.md — host it at a public URL for the listing)
- [x] Icons 16/48/128
- [ ] Developer account ($5 one-time) + store listing screenshots
- [ ] Zip this folder: `cd extension && zip -r ../phishguard-extension.zip .`

## Known limits

- Lexical analysis only — a phishing page hosted on a trusted compromised
  domain can evade it (the heuristic layer still fires on structural
  tricks). Server-side PhishGuard adds the Random-Forest member; live
  reputation feeds are on the roadmap.
- The on-device email scanner uses the LR member (the strongest single
  email model at F1 0.9933).
