/* Asserts the JS engine reproduces the Python-exported model's probabilities.
 * Run:  node extension/tests/parity_test.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mlScoreUrl, mlScoreEmail, scanUrl, scanEmail, loadTrust } from "../lib/engine.js";

const here = dirname(fileURLToPath(import.meta.url));
const urlModel = JSON.parse(readFileSync(join(here, "../model/url_model.json")));
const emailModel = JSON.parse(readFileSync(join(here, "../model/email_model.json")));
const samples = JSON.parse(readFileSync(join(here, "../model/parity_samples.json")));
loadTrust(JSON.parse(readFileSync(join(here, "../model/psl.json"))),
          new Uint8Array(readFileSync(join(here, "../model/topdomains.bloom"))));

const TOL = 2e-3;
let worstU = 0, worstE = 0, fails = 0;

for (const s of samples.url) {
  const { p } = mlScoreUrl(urlModel, s.url);
  const diff = Math.abs(p - s.p);
  worstU = Math.max(worstU, diff);
  if (diff > TOL) {
    fails++;
    console.error(`URL FAIL diff=${diff.toFixed(6)} js=${p.toFixed(6)} py=${s.p} ${s.url.slice(0, 80)}`);
  }
}

for (const s of samples.email) {
  // parity samples are pre-cleaned text; cleaning is idempotent
  const { p } = mlScoreEmail(emailModel, "", s.text);
  const diff = Math.abs(p - s.p);
  worstE = Math.max(worstE, diff);
  if (diff > TOL) {
    fails++;
    console.error(`EMAIL FAIL diff=${diff.toFixed(6)} js=${p.toFixed(6)} py=${s.p} ${s.text.slice(0, 60)}`);
  }
}

// smoke-test the full verdict path
const phish = scanUrl(urlModel, "http://paypal-secure.account-verify.tk/webscr/login?confirm=4852");
const safe = scanUrl(urlModel, "https://www.wikipedia.org/wiki/Machine_learning");
const email = scanEmail(null, emailModel,
  "URGENT: Your account will be suspended",
  "Dear customer, verify your password at http://192.168.4.21/verify now!!!",
  "support@gmail.com");

console.log(`url samples:   ${samples.url.length}  worst |Δp| = ${worstU.toExponential(2)}`);
console.log(`email samples: ${samples.email.length}  worst |Δp| = ${worstE.toExponential(2)}`);
console.log(`smoke: phishy URL -> ${phish.verdict} (risk ${phish.risk_score}), ` +
            `safe URL -> ${safe.verdict} (risk ${safe.risk_score}), ` +
            `phishy email -> ${email.verdict} (risk ${email.risk_score})`);

if (fails || phish.verdict === "safe" || safe.verdict !== "safe" || email.verdict === "safe") {
  console.error(`PARITY TEST FAILED (${fails} sample failures)`);
  process.exit(1);
}
console.log("PARITY TEST PASSED");
