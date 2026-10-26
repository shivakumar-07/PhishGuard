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
})();
