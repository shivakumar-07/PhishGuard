/* PhishGuard service worker — scores every navigation on-device,
 * sets the badge, blocks phishing pages behind a warning interstitial,
 * and answers scan requests from the popup and content scripts.
 * No network request is ever made: the ML model ships inside the extension.
 */
import { scanUrl, scanEmail, loadTrust } from "./lib/engine.js";

let models = null;
async function getModels() {
  if (!models) {
    const [u, e, psl, bloom] = await Promise.all([
      fetch(chrome.runtime.getURL("model/url_model.json")).then((r) => r.json()),
      fetch(chrome.runtime.getURL("model/email_model.json")).then((r) => r.json()),
      fetch(chrome.runtime.getURL("model/psl.json")).then((r) => r.json()),
      fetch(chrome.runtime.getURL("model/topdomains.bloom")).then((r) => r.arrayBuffer()),
    ]);
    loadTrust(psl, new Uint8Array(bloom));
    models = { url: u, email: e };
  }
  return models;
}

const tabVerdicts = new Map();   // tabId -> last scan result
const lastScanned = new Map();   // tabId -> last URL scored (dedupe onUpdated)

async function isEnabled() {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  return enabled;
}

async function bumpStats(verdict) {
  const { stats = { scans: 0, phishing: 0, suspicious: 0, safe: 0 } } =
    await chrome.storage.local.get("stats");
  stats.scans += 1;
  stats[verdict] = (stats[verdict] || 0) + 1;
  await chrome.storage.local.set({ stats });
}

const BADGE_COLORS = { safe: "#0ca30c", suspicious: "#fab219", phishing: "#d03b3b" };

function setBadge(tabId, result) {
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.verdict] });
  chrome.action.setBadgeText({
    tabId,
    text: result.verdict === "safe" ? "OK" : String(Math.round(result.risk_score)),
  });
}

async function hostAllowedThisSession(url) {
  try {
    const host = new URL(url).hostname;
    const { allow = [] } = await chrome.storage.session.get("allow");
    return allow.includes(host);
  } catch {
    return false;
  }
}

async function checkTab(tabId, url) {
  if (!/^https?:\/\//.test(url || "")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    lastScanned.delete(tabId);
    return;
  }
  if (lastScanned.get(tabId) === url) return; // already scored this navigation
  if (!(await isEnabled())) return;
  lastScanned.set(tabId, url);

  const m = await getModels();
  const result = scanUrl(m.url, url);
  tabVerdicts.set(tabId, result);
  setBadge(tabId, result);
  bumpStats(result.verdict);

  if (result.verdict === "phishing" && !(await hostAllowedThisSession(url))) {
    const page =
      chrome.runtime.getURL("warning/warning.html") +
      `?u=${encodeURIComponent(url)}&r=${result.risk_score}` +
      `&d=${encodeURIComponent(JSON.stringify(result.reasons.slice(0, 6)))}`;
    chrome.tabs.update(tabId, { url: page });
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.url) checkTab(tabId, info.url);
  else if (info.status === "loading" && tab && tab.url) checkTab(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabVerdicts.delete(tabId);
  lastScanned.delete(tabId);
});

// ------------------------------------------------- context menu: scan a link
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "pg-scan-link",
    title: "Scan link with PhishGuard",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "pg-scan-link" || !info.linkUrl) return;
  const m = await getModels();
  const result = scanUrl(m.url, info.linkUrl);
  bumpStats(result.verdict);
  const page =
    chrome.runtime.getURL("warning/warning.html") +
    `?mode=report&v=${result.verdict}&u=${encodeURIComponent(info.linkUrl)}` +
    `&r=${result.risk_score}` +
    `&d=${encodeURIComponent(JSON.stringify(result.reasons.slice(0, 6)))}`;
  chrome.tabs.create({ url: page, index: tab ? tab.index + 1 : undefined });
});

// ------------------------------------------------- messaging
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    const m = await getModels();
    switch (msg.type) {
      case "scanUrl": {
        const r = scanUrl(m.url, msg.url);
        bumpStats(r.verdict);
        sendResponse(r);
        break;
      }
      case "scanEmail": {
        const r = scanEmail(null, m.email, msg.subject, msg.body, msg.sender);
        bumpStats(r.verdict);
        sendResponse(r);
        break;
      }
      case "scanBatch": {
        if (!(await isEnabled())) { sendResponse({ results: [] }); break; }
        const results = (msg.urls || []).slice(0, 200).map((u) => {
          const r = scanUrl(m.url, u);
          return { url: u, verdict: r.verdict, risk: r.risk_score };
        });
        sendResponse({ results });
        break;
      }
      case "getTabVerdict": {
        const { stats = null } = await chrome.storage.local.get("stats");
        sendResponse({
          result: tabVerdicts.get(msg.tabId) || null,
          enabled: await isEnabled(),
          stats,
        });
        break;
      }
      case "setEnabled": {
        await chrome.storage.local.set({ enabled: !!msg.enabled });
        sendResponse({ ok: true });
        break;
      }
      case "allowOnce": {
        try {
          const host = new URL(msg.url).hostname;
          const { allow = [] } = await chrome.storage.session.get("allow");
          if (!allow.includes(host)) allow.push(host);
          await chrome.storage.session.set({ allow });
        } catch { /* malformed URL — nothing to allow */ }
        sendResponse({ ok: true });
        break;
      }
      default:
        sendResponse({ error: "unknown message" });
    }
  })();
  return true; // keep the message channel open for the async response
});
