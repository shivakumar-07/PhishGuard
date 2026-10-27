/* Tests for v3 Scam Shield features: look-alike domains, scam-type
 * intelligence, and UPI/QR payment analysis.
 * Run: node extension/tests/features_test.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { lookAlike, deHomoglyph, editDistance, loadTrust, scanUrl } from "../lib/engine.js";
import { analyzeScam } from "../lib/scamintel.js";
import { parseQrContent, analyzeUpi } from "../lib/payintel.js";

const here = dirname(fileURLToPath(import.meta.url));
const urlModel = JSON.parse(readFileSync(join(here, "../model/url_model.json")));
loadTrust(JSON.parse(readFileSync(join(here, "../model/psl.json"))),
          new Uint8Array(readFileSync(join(here, "../model/topdomains.bloom"))));

let fails = 0;
const check = (name, cond, extra = "") => {
  if (!cond) { fails++; console.error("FAIL", name, extra); }
  else console.log(" ok ", name);
};

// ---------------- look-alike domains
check("editDistance arnazon/amazon", editDistance("arnazon", "amazon") <= 2);
check("deHomoglyph paypa1 -> paypal", deHomoglyph("paypa1") === "paypal");
check("deHomoglyph arnazon -> amazon", deHomoglyph("arnazon") === "amazon");
check("homoglyph spoof paypa1.com", (lookAlike("paypa1.com") || {}).weight === 35);
check("homoglyph spoof faceb00k.net", (lookAlike("faceb00k.net") || {}).weight === 35);
check("typo netflik.com", (lookAlike("netflik.com") || {}).weight >= 30);
check("tld squat paypal.support", (lookAlike("paypal.support") || {}).weight === 30);
check("embedded secure-paypal.com", (lookAlike("secure-paypal.com") || {}).weight === 25);
check("no FP purchasehub.com", lookAlike("purchasehub.com") === null);
check("no FP uberlin.de", lookAlike("uberlin.de") === null);
check("no FP growvia.in", lookAlike("growvia.in") === null);

const spoofScan = scanUrl(urlModel, "https://paypa1.com/signin");
check("paypa1.com scores phishing", spoofScan.verdict === "phishing",
      `got ${spoofScan.verdict} ${spoofScan.risk_score}`);
const amazonReal = scanUrl(urlModel, "https://www.amazon.com/deals");
check("real amazon.com stays safe", amazonReal.verdict === "safe");

// ---------------- scam intelligence
const kyc = analyzeScam("", "Dear customer your SBI account will be blocked today. Complete re-KYC update using this link immediately");
check("KYC scam detected", kyc.category === "banking_kyc", kyc.category);
const otp = analyzeScam("", "Sir I am from the bank please share OTP verification code you received");
check("OTP theft detected", otp.category === "otp_theft", otp.category);
const job = analyzeScam("", "Work from home! Earn daily 5000. Small registration fee of 499. Part time job on telegram");
check("job scam detected", job.category === "job_offer", job.category);
const courier = analyzeScam("", "Your package could not be delivered, address is incomplete. Pay a small fee for redelivery");
check("courier scam detected", courier.category === "courier_customs", courier.category);
const invest = analyzeScam("", "Join our VIP group for guaranteed returns, double your money in 21 days with trading tips");
check("investment scam detected", invest.category === "investment", invest.category);
const benign = analyzeScam("Project review", "Hi team, the weekly review is moved to Thursday 3 pm. Bring the updated test results.");
check("benign message: no category", benign.category === null, benign.category);
check("advice present for scams", Array.isArray(kyc.advice) && kyc.advice.length >= 2);

// ---------------- UPI / QR intelligence
check("upi uri parsed", parseQrContent("upi://pay?pa=shop@oksbi&pn=Tea%20Stall").kind === "upi");
check("url qr parsed", parseQrContent("http://evil.tk/pay").kind === "url");
const goodUpi = analyzeUpi("upi://pay?pa=teastall@oksbi&pn=Chai%20Point&am=20&tn=tea");
check("legit UPI QR safe", goodUpi.verdict === "safe", JSON.stringify(goodUpi.reasons));
check("payee surfaced", goodUpi.payee === "teastall@oksbi" && goodUpi.payee_name === "Chai Point");
const badUpi = analyzeUpi("upi://pay?pa=refund@fakepsp&am=9999&url=http://evil.tk/claim");
check("shady UPI QR flagged", badUpi.verdict !== "safe", badUpi.verdict);
const noPa = analyzeUpi("upi://pay?pn=Prize");
check("missing payee flagged high", noPa.verdict === "phishing");

console.log(fails ? `FEATURES TEST FAILED (${fails})` : "FEATURES TEST PASSED");
process.exit(fails ? 1 : 0);
