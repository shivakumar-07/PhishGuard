const params = new URLSearchParams(location.search);
const url = params.get("u") || "";
const risk = Math.round(parseFloat(params.get("r") || "0"));
const mode = params.get("mode") || "block";
const verdict = params.get("v") || "phishing";

document.getElementById("blocked-url").textContent = url;
const badge = document.getElementById("risk-badge");
badge.textContent = `risk ${risk}/100`;

let reasons = [];
try { reasons = JSON.parse(params.get("d") || "[]"); } catch { /* none */ }
const ul = document.getElementById("reasons");
for (const r of reasons.slice(0, 6)) {
  const li = document.createElement("li");
  li.className = `sev-${r.severity}`;
  li.textContent = r.rule;
  ul.appendChild(li);
}

const back = document.getElementById("back");
const proceed = document.getElementById("proceed");

if (mode === "report") {
  document.body.classList.add("report");
  const titles = { safe: "This link looks safe", suspicious: "This link looks suspicious", phishing: "This link looks like phishing" };
  document.getElementById("title").textContent = titles[verdict] || titles.phishing;
  document.getElementById("subtitle").textContent =
    "Scan requested from the right-click menu. Verdict computed locally by PhishGuard's on-device AI.";
  badge.classList.add(`v-${verdict}`);
  document.querySelector(".shield").classList.add(`v-${verdict}`);
  if (verdict === "safe") {
    document.getElementById("shield-mark").setAttribute("d", "M8.5 12.2l2.4 2.4 4.6-4.8");
  }
  back.textContent = "Close";
  proceed.hidden = true;
  back.addEventListener("click", () => window.close());
} else {
  back.addEventListener("click", async () => {
    const tab = await chrome.tabs.getCurrent();
    try { await chrome.tabs.goBack(tab.id); }
    catch { chrome.tabs.update(tab.id, { url: "about:blank" }); }
  });
  proceed.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "allowOnce", url }, async () => {
      const tab = await chrome.tabs.getCurrent();
      chrome.tabs.update(tab.id, { url });
    });
  });
}
