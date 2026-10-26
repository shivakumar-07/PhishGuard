/* PhishGuard console — scan UI, live feed (WebSocket) and monitoring charts. */
"use strict";

const $ = (id) => document.getElementById(id);

const STATUS = { safe: "#0ca30c", suspicious: "#fab219", phishing: "#d03b3b" };
const ICONS = { safe: "✔", suspicious: "⚠", phishing: "✖" };
const INK_2 = "#c3c2b7", MUTED = "#898781", GRID = "#2c2c2a";

const SAMPLES = {
  "url-phish": { url: "http://paypal-secure.account-verify.tk/webscr/login?confirm=4852" },
  "url-safe": { url: "https://www.wikipedia.org/wiki/Machine_learning" },
  "email-phish": {
    sender: "security-alert@paypa1-support.gmail.com",
    subject: "URGENT: Your account will be suspended within 24 hours",
    body: "Dear customer, we detected unusual activity on your account. " +
          "You must verify your password and billing information immediately " +
          "or your account will be suspended. Click http://192.168.4.21/verify " +
          "to confirm your credentials now!!!",
  },
  "email-safe": {
    sender: "mentor@university.edu",
    subject: "Project review meeting moved to Thursday",
    body: "Hi team, the weekly project review is moved from Wednesday to " +
          "Thursday 3 pm in the same room. Please bring the updated test " +
          "results and the draft report. Thanks!",
  },
};

/* ---------------------------------------------------------- mode switch */
const modes = { url: [$("mode-url"), $("url-form")], email: [$("mode-email"), $("email-form")] };
for (const [name, [btn, form]] of Object.entries(modes)) {
  btn.addEventListener("click", () => {
    for (const [n, [b, f]] of Object.entries(modes)) {
      const active = n === name;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", String(active));
      f.hidden = !active;
    }
  });
}

document.querySelectorAll(".sample").forEach((btn) => {
  btn.addEventListener("click", () => {
    const s = SAMPLES[btn.dataset.sample];
    if (s.url !== undefined) $("url-input").value = s.url;
    else {
      $("email-sender").value = s.sender;
      $("email-subject").value = s.subject;
      $("email-body").value = s.body;
    }
  });
});

/* ---------------------------------------------------------- scanning */
async function postJSON(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const detail = (await res.json().catch(() => ({}))).detail;
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json();
}

function bindForm(form, buildPayload, path) {
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = form.querySelector(".scan-btn");
    btn.disabled = true;
    try {
      const result = await postJSON(path, buildPayload());
      renderVerdict(result);
      refreshStats();
    } catch (err) {
      alertVerdictError(err.message);
    } finally {
      btn.disabled = false;
    }
  });
}

bindForm($("url-form"), () => ({ url: $("url-input").value.trim() }), "/api/scan/url");
bindForm($("email-form"), () => ({
  sender: $("email-sender").value.trim(),
  subject: $("email-subject").value.trim(),
  body: $("email-body").value.trim(),
}), "/api/scan/email");

/* ---------------------------------------------------------- verdict card */
const ARC_LEN = Math.PI * 52; // dial semicircle length

function renderVerdict(r) {
  const v = $("verdict");
  v.hidden = false;
  v.className = `verdict v-${r.verdict}`;

  $("verdict-label").textContent =
    r.verdict === "phishing" ? "Phishing" : r.verdict === "suspicious" ? "Suspicious" : "Looks safe";
  $("verdict-icon").textContent = ICONS[r.verdict];
  $("verdict-icon").style.color = STATUS[r.verdict];
  $("verdict-input").textContent = r.input;

  $("dial-num").textContent = Math.round(r.risk_score);
  const arc = $("dial-arc");
  arc.style.stroke = STATUS[r.verdict];
  arc.setAttribute("stroke-dasharray", ARC_LEN);
  arc.setAttribute("stroke-dashoffset", ARC_LEN * (1 - Math.min(r.risk_score, 100) / 100));

  $("v-ml").textContent = `${(r.ml_probability * 100).toFixed(1)}%`;
  $("v-heur").textContent = `${r.heuristic_score.toFixed(0)} / 100`;
  $("v-lat").textContent = `${r.latency_ms} ms`;

  const pm = $("per-model");
  pm.innerHTML = "";
  for (const [name, p] of Object.entries(r.per_model || {})) {
    const row = document.createElement("div");
    row.className = "pm-row";
    row.innerHTML =
      `<span>${name.replace(/_/g, " ")}</span>` +
      `<span class="pm-bar"><span class="pm-fill" style="width:${(p * 100).toFixed(1)}%"></span></span>` +
      `<span class="pm-val">${(p * 100).toFixed(1)}%</span>`;
    pm.appendChild(row);
  }

  const ul = $("reasons");
  ul.innerHTML = "";
  const reasons = r.reasons && r.reasons.length ? r.reasons
    : [{ rule: "No heuristic rules triggered — verdict driven by the ML ensemble.", severity: "info" }];
  for (const re of reasons) {
    const li = document.createElement("li");
    li.className = `sev-${re.severity}`;
    li.textContent = re.rule;
    ul.appendChild(li);
  }

  const tk = $("tokens");
  tk.innerHTML = "";
  for (const t of r.top_tokens || []) {
    const span = document.createElement("span");
    span.className = `token ${t.direction === "phishing" ? "t-phish" : "t-legit"}`;
    span.textContent = `${t.token} ${t.direction === "phishing" ? "+" : "−"}`;
    span.title = `pushes toward ${t.direction} (weight ${t.weight})`;
    tk.appendChild(span);
  }
}

function alertVerdictError(message) {
  const v = $("verdict");
  v.hidden = false;
  v.className = "verdict";
  $("verdict-label").textContent = "Scan failed";
  $("verdict-icon").textContent = "!";
  $("verdict-icon").style.color = STATUS.suspicious;
  $("verdict-input").textContent = message;
  $("reasons").innerHTML = "";
  $("tokens").innerHTML = "";
  $("per-model").innerHTML = "";
}

/* ---------------------------------------------------------- live feed */
const feedBody = $("feed-body");

function feedRow(s, flash = false) {
  const tr = document.createElement("tr");
  if (flash) tr.className = "flash";
  tr.innerHTML =
    `<td><span class="badge b-${s.verdict}">${ICONS[s.verdict]} ${s.verdict}</span></td>` +
    `<td>${s.scan_type}</td>` +
    `<td class="input-cell"></td>` +
    `<td class="num">${Number(s.risk_score).toFixed(0)}</td>` +
    `<td class="num">${(Number(s.ml_prob) * 100).toFixed(0)}%</td>`;
  tr.querySelector(".input-cell").textContent = s.input_text;
  return tr;
}

function pushFeed(s) {
  const empty = feedBody.querySelector(".empty-row");
  if (empty) empty.remove();
  feedBody.prepend(feedRow(s, true));
  while (feedBody.children.length > 30) feedBody.lastChild.remove();
}

/* ---------------------------------------------------------- websocket */
let ws, wsPing;
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  ws.onopen = () => {
    $("live-dot").className = "dot on";
    $("live-label").textContent = "live";
    wsPing = setInterval(() => ws.readyState === 1 && ws.send("ping"), 25000);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.event === "scan") { pushFeed(msg.data); refreshStats(); }
  };
  ws.onclose = () => {
    $("live-dot").className = "dot off";
    $("live-label").textContent = "reconnecting";
    clearInterval(wsPing);
    setTimeout(connectWS, 2500);
  };
}
connectWS();

/* ---------------------------------------------------------- charts */
Chart.defaults.color = INK_2;
Chart.defaults.borderColor = GRID;
Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';

const timelineChart = new Chart($("timeline-chart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "Phishing", data: [], borderColor: STATUS.phishing, backgroundColor: STATUS.phishing, borderWidth: 2, pointRadius: 0, pointHitRadius: 10, tension: 0.25 },
    { label: "Suspicious", data: [], borderColor: STATUS.suspicious, backgroundColor: STATUS.suspicious, borderWidth: 2, pointRadius: 0, pointHitRadius: 10, tension: 0.25 },
    { label: "Safe", data: [], borderColor: STATUS.safe, backgroundColor: STATUS.safe, borderWidth: 2, pointRadius: 0, pointHitRadius: 10, tension: 0.25 },
  ]},
  options: {
    responsive: true, maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: { legend: { labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true } } },
    scales: {
      x: { grid: { display: false }, ticks: { maxTicksLimit: 6, color: MUTED } },
      y: { beginAtZero: true, ticks: { precision: 0, color: MUTED }, grid: { color: GRID } },
    },
  },
});

const verdictChart = new Chart($("verdict-chart"), {
  type: "doughnut",
  data: {
    labels: ["Safe", "Suspicious", "Phishing"],
    datasets: [{
      data: [0, 0, 0],
      backgroundColor: [STATUS.safe, STATUS.suspicious, STATUS.phishing],
      borderColor: "#212120", borderWidth: 2,
    }],
  },
  options: {
    responsive: true, maintainAspectRatio: false, cutout: "62%",
    plugins: { legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true } } },
  },
});

/* ---------------------------------------------------------- stats */
async function refreshStats() {
  try {
    const s = await (await fetch("/api/stats")).json();
    $("t-total").textContent = s.total;
    $("t-phish").textContent = s.by_verdict.phishing || 0;
    $("t-susp").textContent = s.by_verdict.suspicious || 0;
    $("t-safe").textContent = s.by_verdict.safe || 0;

    timelineChart.data.labels = s.timeline.map((t) => t.minute.slice(11));
    timelineChart.data.datasets[0].data = s.timeline.map((t) => t.phishing);
    timelineChart.data.datasets[1].data = s.timeline.map((t) => t.suspicious);
    timelineChart.data.datasets[2].data = s.timeline.map((t) => t.safe);
    timelineChart.update("none");

    verdictChart.data.datasets[0].data = [
      s.by_verdict.safe || 0, s.by_verdict.suspicious || 0, s.by_verdict.phishing || 0];
    verdictChart.update("none");
  } catch { /* server restarting — retry on next event */ }
}

async function loadInitial() {
  refreshStats();
  try {
    const scans = await (await fetch("/api/scans?limit=20")).json();
    if (scans.length) {
      feedBody.innerHTML = "";
      scans.forEach((s) => feedBody.appendChild(feedRow(s)));
    }
    const info = await (await fetch("/api/model-info")).json();
    const badges = [];
    for (const kind of ["url", "email"]) {
      const m = info[kind] && info[kind].models.find((x) => x.model === "hybrid_ensemble");
      if (m) badges.push(`<span class="model-badge">${kind} ensemble <b>${(m.accuracy * 100).toFixed(2)}%</b></span>`);
    }
    $("model-badges").innerHTML = badges.join("");
    if (info.url && info.email) {
      const u = info.url.models.find((x) => x.model === "hybrid_ensemble");
      const e = info.email.models.find((x) => x.model === "hybrid_ensemble");
      $("foot-metrics").textContent =
        `test-set F1 — URL ${u.f1.toFixed(4)}, email ${e.f1.toFixed(4)} · ` +
        `trained on ${info.url.dataset_size.toLocaleString()} URLs & ${info.email.dataset_size.toLocaleString()} emails`;
    }
  } catch { /* models not trained yet */ }
}
loadInitial();
