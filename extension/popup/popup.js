const $ = (id) => document.getElementById(id);
const ARC = Math.PI * 52;
const ICONS = { safe: "✔", suspicious: "⚠", phishing: "✖" };
const COLORS = { safe: "#0ca30c", suspicious: "#fab219", phishing: "#d03b3b" };
const LABELS = { safe: "Looks safe", suspicious: "Suspicious", phishing: "Phishing" };

function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}

function renderReasons(ul, reasons) {
  ul.innerHTML = "";
  for (const r of (reasons || []).slice(0, 4)) {
    const li = document.createElement("li");
    li.className = `sev-${r.severity}`;
    li.textContent = r.rule;
    ul.appendChild(li);
  }
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
  catch { $("page-host").textContent = result.input.slice(0, 60); }
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

function renderScan(result) {
  const box = $("scan-result");
  box.hidden = false;
  box.className = `card v-${result.verdict}`;
  $("result-icon").textContent = ICONS[result.verdict];
  $("result-icon").style.color = COLORS[result.verdict];
  $("result-label").textContent = LABELS[result.verdict];
  $("result-score").textContent =
    `risk ${Math.round(result.risk_score)}/100 · ML ${(result.ml_probability * 100).toFixed(1)}% · ${result.latency_ms} ms`;
  renderReasons($("result-reasons"), result.reasons);
}

// ---------------------------------------------------------------- init
(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const info = await send({ type: "getTabVerdict", tabId: tab ? tab.id : -1 });
  $("toggle").checked = info ? info.enabled !== false : true;
  renderStats(info && info.stats);

  if (info && info.result) {
    renderPage(info.result);
  } else if (tab && /^https?:\/\//.test(tab.url || "")) {
    const r = await send({ type: "scanUrl", url: tab.url });
    renderPage(r);
  } else {
    renderPage(null);
  }
})();

$("toggle").addEventListener("change", (e) => {
  send({ type: "setEnabled", enabled: e.target.checked });
});

// tabs
$("tab-link").addEventListener("click", () => switchPane("link"));
$("tab-email").addEventListener("click", () => switchPane("email"));
function switchPane(which) {
  $("tab-link").classList.toggle("active", which === "link");
  $("tab-email").classList.toggle("active", which === "email");
  $("pane-link").hidden = which !== "link";
  $("pane-email").hidden = which !== "email";
  $("scan-result").hidden = true;
}

$("scan-link").addEventListener("click", async () => {
  const url = $("link-input").value.trim();
  if (url.length < 4) return;
  $("scan-link").disabled = true;
  renderScan(await send({ type: "scanUrl", url }));
  const info = await send({ type: "getTabVerdict", tabId: -1 });
  renderStats(info && info.stats);
  $("scan-link").disabled = false;
});

$("scan-email").addEventListener("click", async () => {
  const body = $("email-body").value.trim();
  if (!body) return;
  $("scan-email").disabled = true;
  renderScan(await send({
    type: "scanEmail",
    subject: $("email-subject").value.trim(),
    body,
    sender: $("email-sender").value.trim(),
  }));
  const info = await send({ type: "getTabVerdict", tabId: -1 });
  renderStats(info && info.stats);
  $("scan-email").disabled = false;
});
