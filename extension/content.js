/* PhishGuard content script — asks the service worker to score the links on
 * the page (locally, on-device) and outlines the ones that score as phishing.
 * Deliberately conservative: only confirmed-phishing links are marked, so the
 * page is never cluttered with false alarms.
 */
(() => {
  const MAX_LINKS = 150;
  const seen = new WeakSet();

  function collect() {
    const anchors = [...document.querySelectorAll("a[href^='http']")]
      .filter((a) => !seen.has(a))
      .slice(0, MAX_LINKS);
    if (!anchors.length) return;

    const urls = [...new Set(anchors.map((a) => a.href))];
    let resp;
    try {
      resp = chrome.runtime.sendMessage({ type: "scanBatch", urls }, (res) => {
        if (chrome.runtime.lastError || !res || !res.results) return;
        const risky = new Map(
          res.results.filter((r) => r.verdict === "phishing").map((r) => [r.url, r]));
        for (const a of anchors) {
          seen.add(a);
          const r = risky.get(a.href);
          if (r) {
            a.style.outline = "2px solid #d03b3b";
            a.style.outlineOffset = "1px";
            a.title = `PhishGuard: likely phishing (risk ${Math.round(r.risk)}/100) — think before you click`;
            a.dataset.phishguard = "phishing";
          }
        }
      });
      void resp;
    } catch { /* extension reloaded — stop quietly */ }
  }

  collect();
  let timer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(collect, 1500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ---- page-text extraction for "Scan this page" -------------------------
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === "extractText") {
      const meta = document.querySelector('meta[name="description"]');
      sendResponse({
        title: document.title || "",
        text: ((meta && meta.content ? meta.content + " " : "") +
               (document.body ? document.body.innerText : "")).slice(0, 6000),
      });
    }
    return false;
  });

  // ---- password-entry guard ----------------------------------------------
  // When a password field gains focus on a little-known site, show one
  // gentle, dismissable banner. Never blocks typing; once per page.
  let pwWarned = false;
  document.addEventListener("focusin", (ev) => {
    if (pwWarned) return;
    const el = ev.target;
    if (!el || el.tagName !== "INPUT" || el.type !== "password") return;
    pwWarned = true;
    try {
      chrome.runtime.sendMessage({ type: "myTabVerdict" }, (resp) => {
        if (chrome.runtime.lastError || !resp || !resp.result) return;
        const r = resp.result;
        if (r.trust_tier !== "unknown") return; // known sites: stay silent
        const banner = document.createElement("div");
        banner.setAttribute("style",
          "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
          "background:#1a1a19;color:#f0efec;border-bottom:2px solid " +
          (r.verdict === "safe" ? "#fab219" : "#d03b3b") + ";" +
          "font:13.5px/1.45 system-ui,sans-serif;padding:10px 14px;" +
          "display:flex;align-items:center;gap:10px;");
        const msgSpan = document.createElement("span");
        msgSpan.textContent =
          `PhishGuard: you're entering a password on a little-known site` +
          (r.verdict === "safe" ? "" : ` (risk ${Math.round(r.risk_score)}/100)`) +
          ` — make sure you trust ${location.hostname}.`;
        const close = document.createElement("button");
        close.textContent = "Dismiss";
        close.setAttribute("style",
          "margin-left:auto;background:transparent;color:#c3c2b7;" +
          "border:1px solid rgba(255,255,255,0.25);border-radius:6px;" +
          "padding:4px 12px;font:inherit;cursor:pointer;");
        close.addEventListener("click", () => banner.remove());
        banner.append(msgSpan, close);
        document.documentElement.appendChild(banner);
        setTimeout(() => banner.remove(), 15000);
      });
    } catch { /* extension reloaded */ }
  }, true);
})();
