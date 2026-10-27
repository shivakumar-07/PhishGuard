import { parseQrContent, analyzeUpi } from "../lib/payintel.js";

const $ = (id) => document.getElementById(id);
const ARC = Math.PI * 52;
const ICONS = { safe: "✔", suspicious: "⚠", phishing: "✖" };
const COLORS = { safe: "#0ca30c", suspicious: "#fab219", phishing: "#d03b3b" };
const LABELS = { safe: "Looks safe", suspicious: "Suspicious", phishing: "Phishing" };

const LINK_ADVICE = [
  "Do not open this link or enter any details on it.",
  "If it claims to be your bank or a service you use, reach that service through its official app instead.",
  "Delete the message that carried it, and warn the person who forwarded it.",
];

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}

function renderReasons(ul, reasons) {
  ul.innerHTML = "";
  for (const r of (reasons || []).slice(0, 5)) {
    const li = document.createElement("li");
    li.className = `sev-${r.severity}`;
    li.textContent = r.rule;
    ul.appendChild(li);
  }
}

function renderAdvice(advice) {
  const box = $("advice");
  const list = $("advice-list");
  list.innerHTML = "";
  if (!advice || !advice.length) { box.hidden = true; return; }
  for (const a of advice) {
    const li = document.createElement("li");
    li.textContent = a;
    list.appendChild(li);
  }
  box.hidden = false;
}

function renderPage(result) {
  const card = $("page-verdict").parentElement;
  if (!result) {
    $("page-label").textContent = "Nothing to check";
    $("page-host").textContent = "Open a website and click the shield again.";
    return;
  }
  card.className = `card v-${result.verdict}`;
  $("page-label").textContent = LABELS[result.verdict];
  try { $("page-host").textContent = new URL(result.input).hostname; }
  catch { $("page-host").textContent = String(result.input).slice(0, 60); }
  $("dial-num").textContent = Math.round(result.risk_score);
  const arc = $("dial-arc");
  arc.style.stroke = COLORS[result.verdict];
  arc.setAttribute("stroke-dasharray", ARC);
  arc.setAttribute("stroke-dashoffset", ARC * (1 - Math.min(result.risk_score, 100) / 100));
  renderReasons($("page-reasons"), result.reasons);
}

function renderStats(stats) {
  if (!stats) return;
  $("s-scans").textContent = stats.scans || 0;
  $("s-phish").textContent = stats.phishing || 0;
  $("s-susp").textContent = stats.suspicious || 0;
}

function renderScan(result, opts = {}) {
  const box = $("scan-result");
  box.hidden = false;
  box.className = `card v-${result.verdict}`;
  $("result-icon").textContent = ICONS[result.verdict];
  $("result-icon").style.color = COLORS[result.verdict];
  $("result-label").textContent = opts.label ||
    (result.scam_label ? `${LABELS[result.verdict]} — ${result.scam_label}` : LABELS[result.verdict]);
  $("result-score").textContent = opts.scoreLine ||
    `risk ${Math.round(result.risk_score)}/100` +
    (result.ml_probability !== undefined ? ` · ML ${(result.ml_probability * 100).toFixed(1)}%` : "") +
    (result.latency_ms !== undefined ? ` · ${result.latency_ms} ms` : "");
  const detail = $("result-detail");
  if (opts.detail) { detail.textContent = opts.detail; detail.hidden = false; }
  else detail.hidden = true;
  renderReasons($("result-reasons"), result.reasons);
  renderAdvice(result.advice ||
    (result.type === "url" && result.verdict !== "safe" ? LINK_ADVICE : null));
}

async function refreshStats() {
  const info = await send({ type: "getTabVerdict", tabId: -1 });
  renderStats(info && info.stats);
}

// ---------------------------------------------------------------- init
(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const info = await send({ type: "getTabVerdict", tabId: tab ? tab.id : -1 });
  $("toggle").checked = info ? info.enabled !== false : true;
  renderStats(info && info.stats);

  if (info && info.result) renderPage(info.result);
  else if (tab && /^https?:\/\//.test(tab.url || "")) renderPage(await send({ type: "scanUrl", url: tab.url }));
  else renderPage(null);
})();

$("toggle").addEventListener("change", (e) => send({ type: "setEnabled", enabled: e.target.checked }));

// ---------------------------------------------------------------- tabs
const panes = { link: [$("tab-link"), $("pane-link")], msg: [$("tab-msg"), $("pane-msg")],
                qr: [$("tab-qr"), $("pane-qr")] };
for (const [name, [btn]] of Object.entries(panes)) {
  btn.addEventListener("click", () => {
    for (const [n, [b, p]] of Object.entries(panes)) {
      b.classList.toggle("active", n === name);
      p.hidden = n !== name;
    }
    $("scan-result").hidden = true;
  });
}

// ---------------------------------------------------------------- link
$("scan-link").addEventListener("click", async () => {
  const url = $("link-input").value.trim();
  if (url.length < 4) return;
  $("scan-link").disabled = true;
  renderScan(await send({ type: "scanUrl", url }));
  refreshStats();
  $("scan-link").disabled = false;
});

// ---------------------------------------------------------------- message
$("scan-msg").addEventListener("click", async () => {
  const body = $("msg-body").value.trim();
  if (!body) return;
  $("scan-msg").disabled = true;
  renderScan(await send({ type: "scanEmail", subject: "", body,
                          sender: $("msg-sender").value.trim() }));
  refreshStats();
  $("scan-msg").disabled = false;
});

// ---------------------------------------------------------------- page scan
$("scan-page").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:\/\//.test(tab.url || "")) return;
  $("scan-page").disabled = true;
  try {
    const page = await chrome.tabs.sendMessage(tab.id, { type: "extractText" });
    const r = await send({ type: "scanEmail", subject: page.title, body: page.text, sender: "" });
    renderScan(r, {
      label: r.scam_label ? `Page content: ${r.scam_label}` : `Page content: ${LABELS[r.verdict]}`,
      detail: `Checked the visible text of ${new URL(tab.url).hostname} for scam language.`,
    });
    refreshStats();
  } catch {
    renderScan({ verdict: "safe", risk_score: 0, reasons: [] },
      { label: "Can't read this page", scoreLine: "Open a normal website tab and try again." });
  }
  $("scan-page").disabled = false;
});

// ---------------------------------------------------------------- QR
$("pane-qr").addEventListener("click", () => $("qr-file").click());
$("qr-file").addEventListener("change", async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  const img = new Image();
  img.onload = async () => {
    const canvas = $("qr-canvas");
    const scale = Math.min(1, 1200 / Math.max(img.width, img.height));
    canvas.width = img.width * scale;
    canvas.height = img.height * scale;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(data.data, data.width, data.height);
    URL.revokeObjectURL(img.src);
    if (!code || !code.data) {
      renderScan({ verdict: "suspicious", risk_score: 0, reasons: [] },
        { label: "No QR code found", scoreLine: "Try a sharper, closer photo of just the QR." });
      return;
    }
    const parsed = parseQrContent(code.data);
    if (parsed.kind === "upi") {
      const r = analyzeUpi(parsed.raw);
      renderScan(r, {
        label: r.verdict === "safe" ? "UPI payment QR" : `UPI payment QR — ${LABELS[r.verdict]}`,
        scoreLine: `pays ${r.payee_name} · ${r.payee}` + (r.amount ? ` · ₹${r.amount}` : ""),
        detail: "Decoded on your device. Always confirm the payee name your UPI app shows before paying.",
      });
    } else if (parsed.kind === "url") {
      const r = await send({ type: "scanUrl", url: parsed.raw });
      renderScan(r, { detail: `QR opens: ${parsed.raw.slice(0, 120)}` });
      refreshStats();
    } else {
      const r = await send({ type: "scanEmail", subject: "", body: parsed.raw, sender: "" });
      renderScan(r, { detail: `QR contains text: "${parsed.raw.slice(0, 100)}"` });
      refreshStats();
    }
  };
  img.src = URL.createObjectURL(file);
  ev.target.value = "";
});
