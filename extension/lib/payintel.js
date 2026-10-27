/* PhishGuard payment intelligence — understands what a scanned QR code
 * actually does before any money moves. Fully on-device.
 *
 * Handles UPI payment URIs (upi://pay?...), payment-ish links, and plain
 * text. The single most effective defense against QR scams is showing the
 * user, in plain words, WHO the payment really goes to.
 */

// Handles operated by real UPI payment service providers.
export const KNOWN_UPI_HANDLES = [
  "upi", "oksbi", "okaxis", "okhdfcbank", "okicici", "okbizaxis", "paytm",
  "ptsbi", "pthdfc", "ptaxis", "ptyes", "ybl", "ibl", "axl", "apl", "yapl",
  "rapl", "sbi", "hdfcbank", "icici", "axisbank", "axisb", "kotak", "kmbl",
  "yesbank", "idfcbank", "barodampay", "boi", "cnrb", "pnb", "uco", "unionbank",
  "indianbank", "iob", "federal", "fbl", "jupiteraxis", "freecharge", "mbk",
  "naviaxis", "sliceaxis", "tapicici", "timecosmos", "waaxis", "wahdfcbank",
  "waicici", "wasbi", "jio", "airtel", "superyes",
];

export function parseQrContent(text) {
  const t = (text || "").trim();
  if (/^upi:\/\//i.test(t)) return { kind: "upi", raw: t };
  if (/^(https?:\/\/|www\.)/i.test(t)) return { kind: "url", raw: t };
  if (/^[a-z]+:\/\//i.test(t)) return { kind: "other_uri", raw: t };
  return { kind: "text", raw: t };
}

/** Analyze a upi:// payment URI -> payee details + warnings + advice. */
export function analyzeUpi(uri) {
  const reasons = [];
  let score = 0;
  const q = {};
  const qs = uri.split("?", 2)[1] || "";
  for (const pair of qs.split("&")) {
    const [k, ...v] = pair.split("=");
    if (k) q[k.toLowerCase()] = decodeURIComponent(v.join("=") || "").trim();
  }
  const pa = (q.pa || "").toLowerCase();
  const pn = q.pn || "";
  const am = q.am || "";
  const handle = pa.includes("@") ? pa.split("@").pop() : "";

  const add = (w, rule, severity) => { reasons.push({ rule, severity, weight: w }); score += w; };

  if (!pa) add(45, "No payee ID (pa) in this QR — not a valid UPI payment code", "high");
  if (pa && !handle) add(30, "Payee ID has no @handle — malformed UPI address", "high");
  if (handle && !KNOWN_UPI_HANDLES.includes(handle))
    add(20, `Unusual UPI handle '@${handle}' — not a well-known payment provider`, "medium");
  if (q.url) add(25, "QR embeds a web link alongside the payment — classic bait-and-switch", "high");
  if (!pn) add(10, "No payee name in the QR — you can't tell who you're paying", "medium");
  if (am && parseFloat(am) > 0 && !q.tn)
    add(8, `Pre-filled amount of ₹${am} with no note — check you agreed to this exact amount`, "low");

  const verdict = score >= 45 ? "phishing" : score >= 20 ? "suspicious" : "safe";
  return {
    type: "upi",
    verdict,
    risk_score: Math.min(score, 100),
    payee: pa || "(missing)",
    payee_name: pn || "(not given)",
    amount: am || null,
    reasons,
    advice: [
      pn ? `This QR pays "${pn}" (${pa}). If that's not who you expect, do not pay.`
         : `This QR pays ${pa || "an unknown payee"}. If you can't verify who that is, do not pay.`,
      "Before confirming in your UPI app, check the name IT shows matches the shop/person in front of you.",
      "Remember: you never need to pay or scan anything to RECEIVE money. 'Scan to receive' is always a scam.",
    ],
  };
}
