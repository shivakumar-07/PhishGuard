# PhishGuard — Product Vision

## The problem, in money

Online scams are one of the largest consumer crime categories on earth.
In India alone, cyber-fraud losses reported to the national helpline run
into thousands of crores of rupees a year — KYC "account blocked" texts,
courier-fee links, fake job fees, investment "doubling" groups, QR codes
that *take* money instead of receiving it, and OTP theft. Globally, the
FBI's IC3 reports billions of dollars in annual phishing/BEC losses. The
victims are not careless people; the lures are engineered to beat
attention. The pain is universal, recurring, and monetizable — people
already pay for antivirus that barely addresses this.

## Why PhishGuard wins

Every competitor checks URLs **by sending them to a server** — a privacy
cost users increasingly refuse, and a latency/availability cost. PhishGuard's
entire brain ships on-device:

1. **Privacy as the moat** — zero network calls, provable from the code.
   "We cannot see your data" beats "we promise not to look."
2. **Beyond links** — the scams that actually empty accounts arrive as
   *messages* and *QR codes*. PhishGuard reads them, names the scam, and
   says what to do — in plain words, in one second.
3. **Explainability** — every verdict shows its evidence. Trust compounds.
4. **Works offline, everywhere** — village connectivity, corporate
   networks, air-gapped machines. No account needed.

## Feature set (v3 "Scam Shield")

| Feature | The pain it kills |
|---|---|
| Phishing page blocking (hybrid ML + rules, 98.6% acc) | credential theft |
| Look-alike domain detection (homoglyph + edit distance vs famous brands) | `paypa1.com`, `arnazon.com`, `paypal.support` |
| Scam Message Analyzer — 10 scam families with tailored "what to do" advice | KYC blocks, lottery, job fees, investment, courier fees, utility threats, tech support, sextortion, family impersonation, OTP theft |
| QR checker with UPI decoding — shows who you'd *actually* pay | payment-QR fraud |
| Password-entry guard on little-known sites | credential reuse on fakes |
| Page-text scam scan | fake shops, prize pages |
| Global domain trust (PSL + top-1M Bloom filter) | false positives — the #1 uninstall reason |
| Live threat links marking on any page | one bad click in a feed |

## Who pays, and for what

Core protection stays **free forever** (distribution is the product's
oxygen). Revenue layers that respect the privacy promise:

- **PhishGuard Family (consumer subscription)** — protect parents and
  grandparents from their own device: shared protection status, "Dad just
  proceeded past a warning" alerts, one-tap "check this for me" forwarding.
  Elder-scam anxiety is a proven willingness-to-pay.
- **PhishGuard Business (per-seat)** — the existing FastAPI dashboard as a
  team console: fleet stats, custom allow/block lists, policy enforcement,
  SIEM export. SMBs pay for exactly this today.
- **Takedown & recovery assist (premium)** — guided reporting to
  cybercrime portals/banks with evidence bundles auto-prepared from scan
  history (stored locally, exported by the user).

## Award positioning

The submission story for product/security awards:

- **Measured, not claimed**: every number comes from held-out test sets;
  the on-device model is re-evaluated in its exact shipped form; JS↔Python
  parity is asserted to 1e-6 in CI-able tests.
- **Research-grade components**: Mozilla PSL, Chrome UX Report top-1M,
  Bloom-filter reputation (~15 bits/domain), Kirsch-Mitzenmacher hashing,
  calibrated ensembles — each a citable, defensible choice.
- **Human-centered security**: verdicts explain themselves; advice is
  actionable; ML alone can never take a page away from the user
  (two-factor verdicts); trusted sites are never nagged.
- **Privacy by architecture**: the strongest claim in the category, and
  auditable in ~2,000 lines of readable code.

## Roadmap

1. Chrome Web Store launch (free) → Firefox/Edge ports.
2. On-page overlay for webmail (Gmail/Outlook) marking scam emails inline.
3. Multilingual scam packs (Hindi, Telugu, Tamil, Bengali keyword sets).
4. Android share-target app: "Share → PhishGuard" from WhatsApp/SMS.
5. DistilBERT-class on-device model via WebGPU as a fourth ensemble member.
6. Family tier (encrypted, user-keyed sync — privacy promise intact).
