/* PhishGuard on-device inference engine.
 *
 * Exact JavaScript port of the Python pipeline:
 *   - sklearn char_wb / word TF-IDF (sublinear tf, idf, L2 over kept vocab)
 *   - 30 lexical URL features + StandardScaler
 *   - Logistic Regression + two-fold calibrated Linear SVM, weighted 1:4
 *   - 16-rule explainable heuristic layer
 *   - risk = 0.75·ML·100 + 0.25·rules;  verdict ≥65 phishing / ≥40 suspicious
 *
 * Everything runs locally — no network call is ever made.
 * Parity with the Python export is asserted by tests/parity_test.mjs.
 */

import { analyzeScam } from "./scamintel.js";

// ------------------------------------------------------------ lexicons
export const SUSPICIOUS_WORDS = [
  "login", "signin", "sign-in", "verify", "verification", "secure", "security",
  "account", "update", "confirm", "banking", "password", "credential", "wallet",
  "webscr", "ebayisapi", "lucky", "bonus", "free", "prize", "winner", "urgent",
  "suspend", "unlock", "invoice", "payment", "refund", "alert", "limited",
];

export const BRAND_NAMES = [
  "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
  "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "chase", "wellsfargo",
  "bankofamerica", "hsbc", "icici", "hdfc", "sbi", "dhl", "fedex", "usps",
];

export const SHORTENER_DOMAINS = [
  "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "lnkd.in",
];

export const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "link",
  "country", "stream", "download", "racing", "online", "loan", "win", "bid",
  "vip", "icu", "rest", "fit", "cam", "monster", "quest", "zip", "mov",
];

export const TRUSTED_DOMAINS = new Set([
  // global
  "google.com", "google.co.in", "youtube.com", "facebook.com",
  "microsoft.com", "bing.com", "msn.com", "apple.com", "amazon.com",
  "amazon.in", "wikipedia.org", "github.com", "linkedin.com", "twitter.com",
  "x.com", "instagram.com", "netflix.com", "office.com", "live.com",
  "yahoo.com", "duckduckgo.com", "paypal.com", "dropbox.com", "adobe.com",
  "zoom.us", "whatsapp.com", "telegram.org", "reddit.com",
  "stackoverflow.com", "mozilla.org", "cloudflare.com", "openai.com",
  "chatgpt.com", "anthropic.com", "claude.ai", "spotify.com",
  "discord.com", "slack.com", "canva.com", "ebay.com",
  // India
  "flipkart.com", "irctc.co.in", "rbi.org.in", "npci.org.in",
  "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
  "axisbank.com", "kotak.com", "pnbindia.in",
  // restricted registries: only verified institutions can register here.
  // bank.in is the RBI/NPCI-mandated domain space for Indian banks (2025+).
  "bank.in", "fin.in", "gov.in", "nic.in", "ac.in", "edu",
]);

// Famous names attackers imitate with misspellings / look-alike characters.
export const TYPO_BRANDS = [
  "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "twitter",
  "linkedin", "microsoft", "outlook", "office", "windows", "apple", "icloud",
  "amazon", "netflix", "spotify", "paypal", "walmart", "dropbox", "adobe",
  "telegram", "snapchat", "tiktok", "discord", "github", "reddit", "wikipedia",
  "yahoo", "chrome", "android", "samsung", "mastercard", "chase", "citibank",
  "wellsfargo", "barclays", "santander", "americanexpress", "westernunion",
  "moneygram", "coinbase", "binance", "blockchain", "metamask", "flipkart",
  "paytm", "phonepe", "myntra", "snapdeal", "irctc", "makemytrip", "zomato",
  "swiggy", "hdfcbank", "icicibank", "axisbank", "kotak", "onlinesbi",
  "airtel", "vodafone", "incometax", "uidai", "bluedart", "delhivery",
  "indiapost", "fedex", "aramex", "interac", "venmo", "zelle", "cashapp",
  "steam", "roblox", "fortnite", "booking", "airbnb", "expedia", "aliexpress",
];

const HOMOGLYPHS = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                     "6": "b", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s" };

export function deHomoglyph(s) {
  let out = "";
  for (const ch of s) out += HOMOGLYPHS[ch] || ch;
  return out.replace(/rn/g, "m").replace(/vv/g, "w");
}

/** Optimal-string-alignment (Damerau-Levenshtein) distance, capped at 2. */
export function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const la = a.length, lb = b.length;
  const d = Array.from({ length: la + 1 }, (_, i) => [i, ...Array(lb).fill(0)]);
  for (let j = 0; j <= lb; j++) d[0][j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1])
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[la][lb];
}

/** Look-alike analysis of the registered domain's core label.
 *  Returns {rule, severity, weight} or null. Only called for unknown tier. */
export function lookAlike(reg) {
  const core = (reg.split(".")[0] || "");
  if (core.length < 4) return null;
  const norm = deHomoglyph(core);
  for (const brand of TYPO_BRANDS) {
    if (core === brand)
      return { weight: 30, severity: "high", floor: 72,
               rule: `Official-looking name '${brand}' on an unofficial domain ending` };
    if (norm === brand)
      return { weight: 35, severity: "high", floor: 72,
               rule: `Disguised spelling of '${brand}' using look-alike characters` };
    if (brand.length >= 5 && editDistance(core, brand) === 1)
      return { weight: 30, severity: "high", floor: 68,
               rule: `One-letter-off misspelling of '${brand}'` };
    if (brand.length >= 5 && core.length > brand.length &&
        new RegExp(`(^|[-_0-9])${brand}([-_0-9]|$)`).test(core))
      return { weight: 25, severity: "high", floor: 55,
               rule: `Brand '${brand}' embedded in an unofficial domain name` };
  }
  return null;
}

const ML_WEIGHT = 0.75;
const HEURISTIC_WEIGHT = 0.25;
const THRESHOLD_PHISHING = 65.0;
const THRESHOLD_SUSPICIOUS = 40.0;

// ------------------------------------------------------------ URL parsing
export function normalizeUrl(url) {
  url = (url || "").trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)) url = "http://" + url;
  return url;
}

/** Mimics Python urllib.parse.urlparse for the fields we use. */
export function parseUrl(norm) {
  let rest = norm;
  const m = rest.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  if (m) rest = rest.slice(m[0].length);

  let end = rest.length;
  for (const ch of ["/", "?", "#"]) {
    const i = rest.indexOf(ch);
    if (i !== -1 && i < end) end = i;
  }
  const netloc = rest.slice(0, end);
  let after = rest.slice(end);

  const hi = after.indexOf("#");
  if (hi !== -1) after = after.slice(0, hi);
  let query = "";
  const qi = after.indexOf("?");
  if (qi !== -1) { query = after.slice(qi + 1); after = after.slice(0, qi); }
  const path = after;

  let hostport = netloc;
  const at = netloc.lastIndexOf("@");
  if (at !== -1) hostport = netloc.slice(at + 1);

  let hostname = hostport.toLowerCase();
  let port = null;
  const ci = hostport.lastIndexOf(":");
  if (ci !== -1 && hostport.indexOf("]") < ci) {
    hostname = hostport.slice(0, ci).toLowerCase();
    const ps = hostport.slice(ci + 1);
    if (ps.length === 0) port = null;
    else if (/^\d+$/.test(ps)) port = parseInt(ps, 10);
    else port = -1; // malformed, like Python wrapper
  }
  return { hostname, port, path, query };
}

// ------------------------------------------------------------ global trust
// Public Suffix List + top-1M Bloom filter, loaded once via loadTrust().
let PSL = null;    // { r: Set, w: Set, e: Set }
let BLOOM = null;  // { m, k, bitmap: Uint8Array }
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

export function loadTrust(pslJson, bloomBytes) {
  PSL = { r: new Set(pslJson.r), w: new Set(pslJson.w), e: new Set(pslJson.e) };
  const dv = new DataView(bloomBytes.buffer, bloomBytes.byteOffset, 16);
  BLOOM = { m: dv.getUint32(4, true), k: dv.getUint32(8, true),
            bitmap: bloomBytes.subarray(16) };
}

function publicSuffixLabels(labels) {
  const n = labels.length;
  let best = 0;
  for (let i = 0; i < n; i++) {
    const cand = labels.slice(i).join(".");
    if (PSL.e.has(cand)) return n - i - 1;
    if (PSL.r.has(cand) && n - i > best) best = n - i;
    if (i + 1 < n && PSL.w.has(labels.slice(i + 1).join(".")) && n - i > best) best = n - i;
  }
  return best || 1;
}

export function registeredDomain(hostname) {
  let host = (hostname || "").toLowerCase().replace(/\.+$/, "");
  if (!host || IPV4_RE.test(host)) return host;
  if (!PSL) { // legacy fallback when trust data is unavailable
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    const cc = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "bank", "fin"]);
    if (cc.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2)
      return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }
  const labels = host.split(".");
  const psN = publicSuffixLabels(labels);
  if (labels.length <= psN) return host;
  return labels.slice(-(psN + 1)).join(".");
}

function fnv1a(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i) & 0xff;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function djb2(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(h, 33) + (s.charCodeAt(i) & 0xff)) >>> 0;
  }
  return h >>> 0;
}

export function isPopular(reg) {
  if (!BLOOM || !reg) return false;
  const h1 = fnv1a(reg);
  const h2 = (djb2(reg) | 1) >>> 0; // >>>0: keep unsigned (|1 coerces to signed int32)
  for (let i = 0; i < BLOOM.k; i++) {
    const idx = (h1 + i * h2) % BLOOM.m;
    if (!(BLOOM.bitmap[idx >> 3] & (1 << (idx & 7)))) return false;
  }
  return true;
}

export function trustTier(reg) {
  if (TRUSTED_DOMAINS.has(reg)) return "curated";
  for (const t of TRUSTED_DOMAINS) if (reg.endsWith("." + t)) return "curated";
  if (isPopular(reg)) return "popular";
  return "unknown";
}

function entropy(s) {
  if (!s) return 0.0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  const n = [...s].length;
  let e = 0.0;
  for (const c of counts.values()) e -= (c / n) * Math.log2(c / n);
  return e;
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const HEX_RE = /%[0-9a-fA-F]{2}/g;

function countChar(s, ch) {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s[i] === ch) n++;
  return n;
}

// ------------------------------------------------------------ lexical features
export function extractUrlFeatures(url) {
  const raw = (url || "").trim();
  const norm = normalizeUrl(raw);
  const parsed = parseUrl(norm);
  const hostname = parsed.hostname || "";
  const path = parsed.path || "";
  const query = parsed.query || "";
  const lower = raw.toLowerCase();

  const reg = registeredDomain(hostname);
  const tld = hostname.includes(".") ? hostname.slice(hostname.lastIndexOf(".") + 1) : "";

  const n = Math.max(raw.length, 1);
  let numDigits = 0, numLetters = 0;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c >= "0" && c <= "9") numDigits++;
    else if (/[a-zA-Z]/.test(c)) numLetters++;
  }

  const subdomainPart = hostname.endsWith(reg)
    ? hostname.slice(0, hostname.length - reg.length).replace(/\.+$/, "")
    : "";
  const pathQuery = (path + "?" + query).toLowerCase();

  let brandOutside = 0;
  for (const brand of BRAND_NAMES) {
    const inReg = reg.includes(brand);
    if (!inReg && (subdomainPart.includes(brand) || pathQuery.includes(brand))) {
      brandOutside = 1;
      break;
    }
  }

  let susWords = 0;
  for (const w of SUSPICIOUS_WORDS) if (lower.includes(w)) susWords++;

  const hexMatches = raw.match(HEX_RE);

  return [
    raw.length,                                             // url_length
    hostname.length,                                        // hostname_length
    path.length,                                            // path_length
    query.length,                                           // query_length
    countChar(raw, "."),                                    // num_dots
    countChar(raw, "-"),                                    // num_hyphens
    countChar(raw, "_"),                                    // num_underscores
    countChar(raw, "/"),                                    // num_slashes
    countChar(raw, "?"),                                    // num_question_marks
    countChar(raw, "="),                                    // num_equals
    countChar(raw, "@"),                                    // num_at
    countChar(raw, "&"),                                    // num_ampersands
    countChar(raw, "%"),                                    // num_percent
    numDigits,                                              // num_digits
    numDigits / n,                                          // digit_ratio
    numLetters / n,                                         // letter_ratio
    Math.max(countChar(hostname, ".") - 1, 0),              // num_subdomains
    IP_RE.test(hostname) ? 1 : 0,                           // has_ip_host
    (parsed.port !== null && parsed.port !== 80 && parsed.port !== 443) ? 1 : 0, // has_port
    raw.includes("@") ? 1 : 0,                              // has_at_symbol
    path.includes("//") ? 1 : 0,                            // has_double_slash_path
    (hostname.includes("https") || path.toLowerCase().includes("http")) ? 1 : 0, // has_https_token
    reg.split(".")[0].includes("-") ? 1 : 0,                // hyphen_in_domain
    SHORTENER_DOMAINS.some((s) => hostname.endsWith(s) || hostname === s) ? 1 : 0, // is_shortened
    SUSPICIOUS_TLDS.includes(tld) ? 1 : 0,                  // suspicious_tld
    susWords,                                               // num_suspicious_words
    brandOutside,                                           // brand_outside_domain
    hexMatches ? hexMatches.length : 0,                     // num_hex_encodings
    entropy(raw),                                           // url_entropy
    entropy(hostname),                                      // hostname_entropy
  ];
}

// ------------------------------------------------------------ TF-IDF
/** sklearn char_wb n-grams (3..5) with its exact short-word behaviour. */
export function charWbNgrams(text, minN, maxN) {
  const doc = text.toLowerCase().replace(/\s\s+/g, " ");
  const grams = [];
  for (const word of doc.split(/\s+/)) {
    if (!word) continue;
    const w = " " + word + " ";
    const wLen = w.length;
    for (let nn = minN; nn <= maxN; nn++) {
      let offset = 0;
      grams.push(w.slice(0, nn));
      while (offset + nn < wLen) {
        offset += 1;
        grams.push(w.slice(offset, offset + nn));
      }
      if (offset === 0) break; // short word counted once
    }
  }
  return grams;
}

/** sklearn word tokenizer \b\w\w+\b plus bigrams. */
export function wordNgrams(text) {
  const tokens = text.toLowerCase().match(/\b\w\w+\b/g) || [];
  const grams = tokens.slice();
  for (let i = 0; i + 1 < tokens.length; i++) grams.push(tokens[i] + " " + tokens[i + 1]);
  return grams;
}

/** counts -> sublinear tf * idf -> L2 normalise -> dot each weight column. */
function tfidfDots(grams, features, nWeights) {
  const counts = new Map();
  for (const g of grams) {
    if (features[g] !== undefined) counts.set(g, (counts.get(g) || 0) + 1);
  }
  const dots = new Array(nWeights).fill(0);
  let sumsq = 0;
  for (const [g, c] of counts) {
    const row = features[g]; // [idf, w1, w2, ...]
    const v = (1 + Math.log(c)) * row[0];
    sumsq += v * v;
    for (let k = 0; k < nWeights; k++) dots[k] += v * row[k + 1];
  }
  const norm = Math.sqrt(sumsq) || 1;
  return dots.map((d) => d / norm);
}

const sigmoid = (d) => 1 / (1 + Math.exp(-d));

// ------------------------------------------------------------ ML scoring
export function mlScoreUrl(model, url) {
  const [tLr, tS0, tS1] = tfidfDots(
    charWbNgrams((url || "").trim(), model.ngram.min, model.ngram.max),
    model.features, 3);

  const feats = extractUrlFeatures(url);
  const lex = model.lexical;
  let nLr = 0, nS0 = 0, nS1 = 0;
  for (let i = 0; i < feats.length; i++) {
    const z = (feats[i] - lex.mean[i]) / lex.scale[i];
    nLr += z * lex.lr[i];
    nS0 += z * lex.svm0[i];
    nS1 += z * lex.svm1[i];
  }

  const pLr = sigmoid(tLr + nLr + model.intercepts.lr);
  const [a0, b0] = model.calibration.svm0;
  const [a1, b1] = model.calibration.svm1;
  const d0 = tS0 + nS0 + model.intercepts.svm0;
  const d1 = tS1 + nS1 + model.intercepts.svm1;
  const pSvm = (1 / (1 + Math.exp(a0 * d0 + b0)) + 1 / (1 + Math.exp(a1 * d1 + b1))) / 2;

  const w = model.ensemble_weights;
  const p = (w.lr * pLr + w.svm * pSvm) / (w.lr + w.svm);
  return { p, perModel: { logistic_regression: pLr, svm_linear: pSvm } };
}

export function cleanEmailText(subject, body) {
  let t = `${subject || ""} ${body || ""}`.toLowerCase();
  t = t.replace(/https?:\/\/\S+|www\.\S+/gi, " urltoken ");
  t = t.replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, " emailtoken ");
  t = t.replace(/\b\d{4,}\b/g, " numtoken ");
  t = t.replace(/[^a-z0-9\s]/g, " ");
  return t.replace(/\s+/g, " ").trim();
}

export function mlScoreEmail(model, subject, body) {
  const text = cleanEmailText(subject, body);
  const [dw] = tfidfDots(wordNgrams(text), model.word, 1);
  const [dc] = tfidfDots(charWbNgrams(text, model.ngram_char[0], model.ngram_char[1]),
                         model.char, 1);
  const p = sigmoid(dw + dc + model.intercept);
  return { p, perModel: { logistic_regression: p } };
}

// ------------------------------------------------------------ heuristic rules
function rule(reasons, score, weight, text, severity) {
  reasons.push({ rule: text, severity, weight });
  return score + weight;
}

export function heuristicsUrl(url) {
  const reasons = [];
  let score = 0;
  const parsed = parseUrl(normalizeUrl(url));
  const host = parsed.hostname || "";
  const path = parsed.path || "";
  const reg = registeredDomain(host);
  const tld = host.includes(".") ? host.slice(host.lastIndexOf(".") + 1) : "";
  const tier = trustTier(reg);
  const hostPath = (host + " " + path).toLowerCase();

  // ---- structural rules: always active, every tier --------------------
  if (IP_RE.test(host))
    score = rule(reasons, score, 35, "URL uses a raw IP address instead of a domain name", "high");
  if (host.startsWith("xn--") || host.includes(".xn--"))
    score = rule(reasons, score, 30, "Punycode-encoded (lookalike) domain", "high");
  if ((url || "").includes("@"))
    score = rule(reasons, score, 25, "'@' symbol in URL — browser ignores everything before it", "high");
  if (parsed.port !== null && parsed.port !== 80 && parsed.port !== 443)
    score = rule(reasons, score, 15, `Non-standard port ${parsed.port === -1 ? "(malformed)" : parsed.port}`, "medium");
  if (path.includes("//"))
    score = rule(reasons, score, 10, "Double slash inside URL path (redirect trick)", "medium");

  // ---- brand impersonation: active unless curated ----------------------
  // host+path only — the query string carries user content (search terms)
  if (tier !== "curated") {
    const subPart = reg && host.endsWith(reg)
      ? host.slice(0, host.length - reg.length).replace(/\.+$/, "") : host;
    const subAndPath = (subPart + " " + path).toLowerCase();
    for (const brand of BRAND_NAMES) {
      if (!reg.includes(brand) && subAndPath.includes(brand)) {
        score = rule(reasons, score, 30,
          `Brand name '${brand}' outside the registered domain (possible impersonation)`, "high");
        break;
      }
    }
  }

  // ---- pattern rules: unknown domains only ------------------------------
  let riskFloor = 0;
  if (tier === "unknown") {
    const la = lookAlike(reg);
    if (la) { score = rule(reasons, score, la.weight, la.rule, la.severity); riskFloor = la.floor; }
    if (SHORTENER_DOMAINS.some((s) => host === s || host.endsWith("." + s)))
      score = rule(reasons, score, 15, "Link-shortener domain hides the real destination", "medium");
    if (SUSPICIOUS_TLDS.includes(tld))
      score = rule(reasons, score, 15, `Suspicious top-level domain '.${tld}'`, "medium");
    if (Math.max(countChar(host, ".") - 1, 0) >= 3)
      score = rule(reasons, score, 12, "Excessive number of subdomains", "medium");
    if (reg.split(".")[0].includes("-"))
      score = rule(reasons, score, 8, "Hyphenated registered domain", "low");

    const hits = SUSPICIOUS_WORDS.filter((w) => hostPath.includes(w));
    if (hits.length >= 2)
      score = rule(reasons, score, 15, `Multiple phishing keywords in URL: ${hits.slice(0, 4).join(", ")}`, "medium");
    else if (hits.length === 1)
      score = rule(reasons, score, 7, `Phishing keyword in URL: '${hits[0]}'`, "low");

    if ((url || "").length > 100)
      score = rule(reasons, score, 8, `Unusually long URL (${url.length} characters)`, "low");
    if (host.includes("https") || path.toLowerCase().includes("http"))
      score = rule(reasons, score, 12, "'http(s)' token embedded in domain/path to fake security", "medium");
    if (reg.includes("."))
      score = rule(reasons, score, 8,
        "Domain is not among the 1M most-visited websites (new or little-known)", "low");
  }

  if (tier === "curated" && reasons.length === 0)
    reasons.push({ rule: `'${reg}' is on the verified trusted allowlist`,
                   severity: "info", weight: 0 });
  else if (tier === "popular" && reasons.length === 0)
    reasons.push({ rule: `'${reg}' is among the world's 1M most-visited websites`,
                   severity: "info", weight: 0 });

  return { score: Math.min(score, 100), reasons, tier,
           trusted: tier !== "unknown", riskFloor };
}

const URGENCY = ["urgent", "immediately", "act now", "expire", "expiring", "suspended",
  "suspend", "deactivate", "verify now", "final notice", "last warning",
  "within 24 hours", "within 48 hours", "right away", "asap", "limited time"];
const CREDENTIAL = ["password", "login", "log in", "sign in", "signin",
  "verify your account", "confirm your account", "update your account",
  "billing information", "credit card", "debit card", "ssn", "social security",
  "otp", "cvv", "bank account", "security question", "credentials", "pin number"];
const REWARD = ["congratulations", "winner", "won", "prize", "lottery", "reward",
  "claim", "gift card", "free iphone", "cash prize", "inheritance", "million",
  "beneficiary", "donation", "jackpot"];
const GREETINGS = ["dear customer", "dear user", "dear member", "dear client",
  "dear account holder", "dear sir", "dear madam", "valued customer"];

export function heuristicsEmail(subject, body, sender) {
  const reasons = [];
  let score = 0;
  const text = `${subject || ""} ${body || ""}`.toLowerCase();
  const snd = (sender || "").toLowerCase();

  const urls = (`${subject || ""} ${body || ""}`).match(/https?:\/\/\S+|www\.\S+/gi) || [];
  const ipLinks = urls.filter((u) => /https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(u));

  const credHits = CREDENTIAL.filter((w) => text.includes(w));
  const urgHits = URGENCY.filter((w) => text.includes(w));
  const rewHits = REWARD.filter((w) => text.includes(w));

  if (credHits.length)
    score = rule(reasons, score, Math.min(12 * credHits.length, 30),
      `Requests credentials/sensitive data: ${credHits.slice(0, 3).join(", ")}`, "high");
  if (urgHits.length)
    score = rule(reasons, score, Math.min(8 * urgHits.length, 20),
      `Urgency pressure language: ${urgHits.slice(0, 3).join(", ")}`, "medium");
  if (rewHits.length)
    score = rule(reasons, score, Math.min(8 * rewHits.length, 20),
      `Too-good-to-be-true reward language: ${rewHits.slice(0, 3).join(", ")}`, "medium");
  if (ipLinks.length)
    score = rule(reasons, score, 25, "Contains a link pointing to a raw IP address", "high");

  const freemail = ["@gmail.", "@yahoo.", "@hotmail.", "@outlook.", "@aol."];
  const brands = ["paypal", "bank", "apple", "microsoft", "amazon", "netflix", "sbi", "hdfc", "icici"];
  if (freemail.some((f) => snd.includes(f)) &&
      brands.some((b) => text.includes(b) || snd.includes(b)))
    score = rule(reasons, score, 25, "Free-mail sender claiming to be a known brand", "high");

  if (GREETINGS.some((g) => text.includes(g)))
    score = rule(reasons, score, 8, "Generic greeting ('Dear customer' …)", "low");
  if (subject && subject === subject.toUpperCase() && subject.length > 8 && /[A-Z]/.test(subject))
    score = rule(reasons, score, 6, "ALL-CAPS subject line", "low");
  if ((text.match(/!/g) || []).length >= 3)
    score = rule(reasons, score, 5, "Excessive exclamation marks", "low");
  if (text.includes("<form") || text.includes('type="password"'))
    score = rule(reasons, score, 20, "Embedded HTML form / password field", "high");
  if (urls.length >= 5)
    score = rule(reasons, score, 8, `High number of links (${urls.length})`, "low");

  return { score: Math.min(score, 100), reasons };
}

// ------------------------------------------------------------ verdicts
function verdictOf(risk) {
  if (risk >= THRESHOLD_PHISHING) return "phishing";
  if (risk >= THRESHOLD_SUSPICIOUS) return "suspicious";
  return "safe";
}

export function scanUrl(model, url) {
  const t0 = Date.now();
  const { p, perModel } = mlScoreUrl(model, url);
  const heur = heuristicsUrl(url);
  let ml = p;
  if (heur.tier === "curated") ml = Math.min(p, 0.15);
  else if (heur.tier === "popular") ml = Math.min(p, 0.30);
  let risk = Math.round((ML_WEIGHT * ml * 100 + HEURISTIC_WEIGHT * heur.score) * 100) / 100;

  // Brand look-alike domains carry a verdict floor: a disguised or
  // misspelled famous name on an unknown domain is decisive on its own.
  if (heur.riskFloor) risk = Math.max(risk, heur.riskFloor);

  // Two-factor verdict: ML alone never hard-blocks. An unknown domain with
  // no corroborating rule evidence is downgraded to a "suspicious" warning.
  if (heur.tier === "unknown" && heur.score <= 8 && risk >= THRESHOLD_PHISHING) {
    risk = 64.0;
    heur.reasons.push({
      rule: "ML model is alarmed but no rule evidence corroborates it — " +
            "shown as a warning, never blocked on ML alone",
      severity: "medium", weight: 0,
    });
  }
  return {
    type: "url", input: url, verdict: verdictOf(risk), risk_score: risk,
    ml_probability: Math.round(ml * 1e4) / 1e4, heuristic_score: heur.score,
    per_model: perModel, reasons: heur.reasons, trusted_domain: heur.trusted,
    trust_tier: heur.tier,
    latency_ms: Date.now() - t0,
  };
}

export function scanEmail(urlModelUnused, emailModel, subject, body, sender) {
  const t0 = Date.now();
  const { p, perModel } = mlScoreEmail(emailModel, subject, body);
  const heur = heuristicsEmail(subject, body, sender);
  const intel = analyzeScam(subject, body);
  const heurScore = Math.min(heur.score + intel.boost, 100);
  if (intel.category)
    heur.reasons.unshift({
      rule: `Matches known scam pattern: ${intel.label} (${intel.hits.slice(0, 3).join("; ")})`,
      severity: "high", weight: intel.boost,
    });
  const risk = Math.round((ML_WEIGHT * p * 100 + HEURISTIC_WEIGHT * heurScore) * 100) / 100;
  return {
    type: "email", input: (subject || "(no subject)").slice(0, 120),
    verdict: verdictOf(risk), risk_score: risk,
    ml_probability: Math.round(p * 1e4) / 1e4, heuristic_score: heurScore,
    per_model: perModel, reasons: heur.reasons,
    scam_category: intel.category, scam_label: intel.label || null,
    advice: intel.advice || null,
    latency_ms: Date.now() - t0,
  };
}
