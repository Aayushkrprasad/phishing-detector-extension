/**
 * Phishing Detector Pro - Service Worker
 * Background monitoring, badge updates, threat caching, and auto-navigation blocking.
 */

try {
  importScripts("heuristics.js");
} catch (e) {
  console.warn("Failed to import heuristics.js in service-worker:", e);
}

// Initialize Extension Settings on install
chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing Detector Pro v3.0 Installed & Ready");

  chrome.storage.local.get(["userSettings", "trustedSites", "customBlacklist", "scanHistory"], (data) => {
    if (!data.userSettings) {
      chrome.storage.local.set({
        userSettings: {
          linkShieldEnabled: true,
          credentialGuardEnabled: true,
          autoBlockEnabled: false,
          threatIntelEnabled: true
        }
      });
    }
    if (!data.trustedSites) {
      chrome.storage.local.set({ trustedSites: ["google.com", "github.com", "wikipedia.org"] });
    }
    if (!data.customBlacklist) {
      chrome.storage.local.set({ customBlacklist: [] });
    }
    if (!data.scanHistory) {
      chrome.storage.local.set({ scanHistory: [] });
    }
  });

  chrome.action.setBadgeText({ text: "PRO" });
  chrome.action.setBadgeBackgroundColor({ color: "#3B82F6" });
});

// Update Action Badge based on Tab Security Status
function evaluateTabSecurity(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  try {
    const parsedUrl = new URL(url);
    const host = parsedUrl.hostname.toLowerCase();

    chrome.storage.local.get(["trustedSites", "customBlacklist", "scanHistory"], (storage) => {
      const trusted = storage.trustedSites || [];
      const blacklist = storage.customBlacklist || [];

      // Check Blacklist first
      if (blacklist.includes(host)) {
        chrome.action.setBadgeText({ tabId, text: "BLOCK" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
        return;
      }

      // Check Whitelist / Trusted
      if (trusted.includes(host)) {
        chrome.action.setBadgeText({ tabId, text: "SAFE" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
        return;
      }

      // Run Heuristic Engine
      const evaluation = self.ThreatEngine
        ? self.ThreatEngine.evaluateUrlThreat(url)
        : { risk: 0, level: "SAFE", threats: [] };

      if (evaluation.risk >= 60) {
        chrome.action.setBadgeText({ tabId, text: "RISK" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
      } else if (evaluation.risk >= 25) {
        chrome.action.setBadgeText({ tabId, text: "WARN" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
      } else {
        chrome.action.setBadgeText({ tabId, text: "OK" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
      }

      // Record automatically into scan history
      recordScanHistory({
        url,
        hostname: host,
        risk: evaluation.risk,
        level: evaluation.level,
        threats: evaluation.threats,
        timestamp: new Date().toISOString()
      });
    });
  } catch (e) {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// Automatically save scan entry to local history (capped at last 100 scans)
function recordScanHistory(scanEntry) {
  chrome.storage.local.get(["scanHistory"], (res) => {
    let history = res.scanHistory || [];
    // Avoid rapid duplicate history spam for the same hostname within 30 seconds
    const existingIndex = history.findIndex(h => h.hostname === scanEntry.hostname);
    if (existingIndex !== -1) {
      const timeDiff = Math.abs(new Date() - new Date(history[existingIndex].timestamp));
      if (timeDiff < 30000) {
        history[existingIndex] = scanEntry; // Update existing entry
        chrome.storage.local.set({ scanHistory: history });
        return;
      }
    }

    history.unshift(scanEntry);
    if (history.length > 150) history = history.slice(0, 150);
    chrome.storage.local.set({ scanHistory: history });
  });
}

// Tab navigation listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    evaluateTabSecurity(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url) {
      evaluateTabSecurity(activeInfo.tabId, tab.url);
    }
  });
});

// Optional Auto-Block Interceptor for Critical Threats
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only intercept main frame navigations
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url || url.startsWith("chrome") || url.startsWith("about:") || url.includes("warning.html")) return;

  try {
    const host = new URL(url).hostname.toLowerCase();

    chrome.storage.local.get(["userSettings", "trustedSites", "customBlacklist"], (storage) => {
      const settings = storage.userSettings || {};
      const trusted = storage.trustedSites || [];
      const blacklist = storage.customBlacklist || [];

      if (trusted.includes(host)) return;

      const isBlacklisted = blacklist.includes(host);
      let isSevereThreat = false;

      if (self.ThreatEngine) {
        const threat = self.ThreatEngine.evaluateUrlThreat(url);
        if (threat.risk >= 80) isSevereThreat = true;
      }

      if ((settings.autoBlockEnabled && isSevereThreat) || isBlacklisted) {
        const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&risk=95`);
        chrome.tabs.update(details.tabId, { url: warningUrl });
      }
    });
  } catch (e) {}
});

// Handle inter-extension messaging
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "GET_EXTENSION_STATUS") {
    sendResponse({ status: "ACTIVE", version: "3.0" });
  }
  return true;
});