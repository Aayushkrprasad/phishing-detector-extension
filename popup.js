/**
 * Phishing Detector Pro - Popup Controller v3.5
 * Live Tab Inspector & Instant URL Scanner
 */

document.addEventListener("DOMContentLoaded", async () => {
  let currentTabUrl = "";
  let currentHostname = "";
  let currentTabId = null;

  // Initialize UI, Tabs, and Settings
  initPopupModeTabs();
  initQuickScanner();
  await initSettingsToggles();

  // Query Current Active Tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      showSpecialPageState("Browser Tab", "Unable to inspect current tab.", 0);
      return;
    }

    const currentTab = tabs[0];
    currentTabId = currentTab.id;
    currentTabUrl = currentTab.url;

    // Handle internal browser pages
    if (
      currentTabUrl.startsWith("chrome://") ||
      currentTabUrl.startsWith("edge://") ||
      currentTabUrl.startsWith("chrome-extension://") ||
      currentTabUrl.startsWith("about:")
    ) {
      showSpecialPageState("Browser Internal Page", "Internal browser pages are safe by default.", 0);
      return;
    }

    try {
      currentHostname = new URL(currentTabUrl).hostname;
      document.getElementById("currentHost").textContent = currentHostname;

      // Check site status in storage (Trusted vs Blacklisted)
      chrome.storage.local.get(["trustedSites", "customBlacklist"], (res) => {
        const trusted = res.trustedSites || [];
        const blacklist = res.customBlacklist || [];

        updateButtonStates(trusted.includes(currentHostname), blacklist.includes(currentHostname));

        if (blacklist.includes(currentHostname)) {
          renderScanView({
            risk: 100,
            level: "HIGH_RISK",
            threats: [{ icon: "🚫", text: "Domain is explicitly blocked in your Custom Blacklist." }],
            metrics: { ssl: "Blacklisted", entropy: "--", targetBrand: "None", passwordFields: 0 }
          });
          return;
        }

        if (trusted.includes(currentHostname)) {
          renderScanView({
            risk: 0,
            level: "SAFE",
            threats: [{ icon: "🛡️", text: "Domain is verified and marked as Trusted by you." }],
            metrics: { ssl: "Trusted Site", entropy: "Verified", targetBrand: "Whitelisted", passwordFields: 0 }
          });
          return;
        }

        // Execute scan on current tab
        runScanOnTab(currentTabId, currentTabUrl);
      });
    } catch (e) {
      showSpecialPageState("Invalid URL", "Could not parse current page URL.", 50);
    }
  });

  // Setup Event Listeners
  setupEventListeners();

  /**
   * Tab Switching between Live Tab & Quick Scanner
   */
  function initPopupModeTabs() {
    const liveBtn = document.getElementById("tabLiveBtn");
    const scanBtn = document.getElementById("tabScannerBtn");
    const liveSec = document.getElementById("liveTabSection");
    const scanSec = document.getElementById("scannerSection");

    if (liveBtn && scanBtn) {
      liveBtn.addEventListener("click", () => {
        liveBtn.classList.add("active");
        scanBtn.classList.remove("active");
        liveSec.classList.add("active");
        scanSec.classList.remove("active");
      });

      scanBtn.addEventListener("click", () => {
        scanBtn.classList.add("active");
        liveBtn.classList.remove("active");
        scanSec.classList.add("active");
        liveSec.classList.remove("active");
      });
    }
  }

  /**
   * Quick Scanner Module
   */
  function initQuickScanner() {
    const quickInput = document.getElementById("quickUrlInput");
    const quickBtn = document.getElementById("quickScanBtn");
    const copyReportBtn = document.getElementById("copyReportBtn");

    if (quickBtn) quickBtn.addEventListener("click", runQuickScan);
    if (quickInput) {
      quickInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") runQuickScan();
      });
    }

    // Sample pills
    document.querySelectorAll(".sample-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        quickInput.value = btn.getAttribute("data-url");
        runQuickScan();
      });
    });

    // Run default scan on load
    runQuickScan();

    function runQuickScan() {
      const raw = quickInput.value.trim();
      if (!raw) return;

      const evalData = window.ThreatEngine
        ? window.ThreatEngine.evaluateUrlThreat(raw)
        : { risk: 80, level: "HIGH_RISK", threats: [{ icon: "⚠️", text: "Suspicious link structure" }] };

      document.getElementById("quickResHost").textContent = evalData.hostname || raw;
      document.getElementById("quickScoreVal").textContent = evalData.risk;

      const scoreLabel = document.getElementById("quickScoreLabel");
      const scoreNum = document.getElementById("quickScoreVal");

      if (evalData.risk >= 60) {
        scoreLabel.className = "quick-score-pill status-danger";
        scoreLabel.textContent = "HIGH RISK";
        scoreNum.style.color = "var(--accent-danger)";
      } else if (evalData.risk >= 25) {
        scoreLabel.className = "quick-score-pill status-warn";
        scoreLabel.textContent = "CAUTION";
        scoreNum.style.color = "var(--accent-warn)";
      } else {
        scoreLabel.className = "quick-score-pill status-safe";
        scoreLabel.textContent = "SAFE";
        scoreNum.style.color = "var(--accent-safe)";
      }

      document.getElementById("quickEntropy").textContent = `${evalData.metrics?.entropy || '2.8'} H(X)`;
      document.getElementById("quickBrand").textContent = evalData.metrics?.targetBrand || "None";
      document.getElementById("quickTld").textContent = evalData.metrics?.tld || ".com";

      const listEl = document.getElementById("quickThreatsList");
      listEl.innerHTML = "";

      if (evalData.threats && evalData.threats.length > 0) {
        evalData.threats.forEach(t => {
          const item = document.createElement("div");
          item.className = "reason-item";
          item.innerHTML = `<span>${t.icon || '⚠️'}</span><span>${t.text}</span>`;
          listEl.appendChild(item);
        });
      } else {
        listEl.innerHTML = `<div class="reason-item" style="color: var(--accent-safe);"><span>🛡️</span><span>No malicious heuristics or typosquatting flags found.</span></div>`;
      }

      // Save report data for copying
      window.__lastQuickScanReport = {
        url: raw,
        hostname: evalData.hostname,
        risk: evalData.risk,
        level: evalData.level,
        threats: evalData.threats?.map(t => t.text).join(", ") || "None",
        scannedAt: new Date().toISOString()
      };
    }

    if (copyReportBtn) {
      copyReportBtn.addEventListener("click", () => {
        if (!window.__lastQuickScanReport) return;
        const text = `Phishing Detector Pro - Forensic Report\n` +
          `-----------------------------------------\n` +
          `Target URL: ${window.__lastQuickScanReport.url}\n` +
          `Host: ${window.__lastQuickScanReport.hostname}\n` +
          `Risk Score: ${window.__lastQuickScanReport.risk}/100 (${window.__lastQuickScanReport.level})\n` +
          `Detected Threats: ${window.__lastQuickScanReport.threats}\n` +
          `Timestamp: ${window.__lastQuickScanReport.scannedAt}\n`;

        navigator.clipboard.writeText(text).then(() => {
          const btnTxt = document.getElementById("copyBtnText");
          btnTxt.textContent = "Copied to Clipboard!";
          setTimeout(() => { btnTxt.textContent = "Copy Forensic Report"; }, 2000);
        });
      });
    }
  }

  /**
   * Run Scan on Active Tab
   */
  function runScanOnTab(tabId, url) {
    chrome.tabs.sendMessage(tabId, { action: "RUN_DEEP_SCAN" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.data) {
        const fallbackScan = window.ThreatEngine
          ? window.ThreatEngine.evaluateUrlThreat(url)
          : { risk: 10, level: "SAFE", threats: [{ icon: "ℹ️", text: "Fast URL heuristic analysis." }] };
        renderScanView(fallbackScan);
        return;
      }
      renderScanView(response.data);
    });
  }

  /**
   * Render Analysis Results into UI
   */
  function renderScanView(data) {
    const risk = data.risk !== undefined ? data.risk : 0;
    const scoreVal = document.getElementById("scoreValue");
    const gaugeFill = document.getElementById("gaugeFill");
    const heading = document.getElementById("statusHeading");
    const subtext = document.getElementById("statusSubtext");
    const tag = document.getElementById("hostStatusTag");
    const reasonsList = document.getElementById("reasonsList");
    const findingCount = document.getElementById("findingCount");

    // Animate Gauge (314 is circumference)
    const offset = 314 - (314 * risk) / 100;
    gaugeFill.style.strokeDashoffset = offset;
    scoreVal.textContent = risk;

    // Reset Pills and Styles
    tag.className = "status-pill";

    if (risk >= 60) {
      gaugeFill.style.stroke = "var(--accent-danger)";
      scoreVal.style.color = "var(--accent-danger)";
      tag.classList.add("status-danger");
      tag.textContent = "DANGER";
      heading.textContent = "High Phishing Threat";
      subtext.textContent = "Critical deception signals or typosquatting patterns detected.";
    } else if (risk >= 25) {
      gaugeFill.style.stroke = "var(--accent-warn)";
      scoreVal.style.color = "var(--accent-warn)";
      tag.classList.add("status-warn");
      tag.textContent = "CAUTION";
      heading.textContent = "Suspicious Domain Signals";
      subtext.textContent = "Page exhibits heuristic anomalies. Exercise caution.";
    } else {
      gaugeFill.style.stroke = "var(--accent-safe)";
      scoreVal.style.color = "var(--accent-safe)";
      tag.classList.add("status-safe");
      tag.textContent = "SAFE";
      heading.textContent = "Legitimate Domain";
      subtext.textContent = "No mathematical typosquatting or brand spoofing detected.";
    }

    // Populate Metrics
    const metrics = data.metrics || {};
    document.getElementById("metricSsl").textContent = metrics.ssl || (currentTabUrl.startsWith("https") ? "Valid SSL" : "HTTP (Insecure)");
    document.getElementById("metricEntropy").textContent = metrics.entropy !== undefined ? `${metrics.entropy} H(X)` : "Normal";
    document.getElementById("metricBrand").textContent = metrics.targetBrand || "None";
    document.getElementById("metricInputs").textContent = `${metrics.passwordFields || 0} Passwords`;

    // Populate Reasons List
    reasonsList.innerHTML = "";
    const threats = data.threats || [];
    findingCount.textContent = `${threats.length} Flag${threats.length === 1 ? '' : 's'}`;

    if (threats.length === 0) {
      const item = document.createElement("div");
      item.className = "reason-item";
      item.innerHTML = `<span>🛡️</span><span>All mathematical and brand heuristic checks passed.</span>`;
      reasonsList.appendChild(item);
    } else {
      threats.forEach((threat) => {
        const item = document.createElement("div");
        item.className = "reason-item";
        item.innerHTML = `<span>${threat.icon || "⚠️"}</span><span>${threat.text}</span>`;
        reasonsList.appendChild(item);
      });
    }
  }

  function showSpecialPageState(title, description, risk) {
    document.getElementById("currentHost").textContent = title;
    document.getElementById("scoreValue").textContent = risk;
    const tag = document.getElementById("hostStatusTag");
    tag.className = "status-pill status-safe";
    tag.textContent = "INTERNAL";

    document.getElementById("statusHeading").textContent = title;
    document.getElementById("statusSubtext").textContent = description;
    document.getElementById("reasonsList").innerHTML = `<div class="reason-item"><span>ℹ️</span><span>${description}</span></div>`;
    document.getElementById("gaugeFill").style.strokeDashoffset = 314;
    document.getElementById("findingCount").textContent = "0 Flags";
  }

  function updateButtonStates(isTrusted, isBlacklisted) {
    const trustBtn = document.getElementById("trustSiteBtn");
    const blacklistBtn = document.getElementById("blacklistSiteBtn");
    const trustTxt = document.getElementById("trustBtnText");

    if (isTrusted) {
      trustBtn.classList.add("trusted-active");
      trustTxt.textContent = "Trusted ✓";
    } else {
      trustBtn.classList.remove("trusted-active");
      trustTxt.textContent = "Trust Site";
    }

    if (isBlacklisted) {
      blacklistBtn.classList.add("blacklisted-active");
    } else {
      blacklistBtn.classList.remove("blacklisted-active");
    }
  }

  /**
   * Setup UI Event Listeners
   */
  function setupEventListeners() {
    // Trust Site Button
    document.getElementById("trustSiteBtn").addEventListener("click", () => {
      if (!currentHostname) return;
      chrome.storage.local.get(["trustedSites", "customBlacklist"], (res) => {
        let trusted = res.trustedSites || [];
        let blacklist = (res.customBlacklist || []).filter(h => h !== currentHostname);

        if (trusted.includes(currentHostname)) {
          trusted = trusted.filter(h => h !== currentHostname);
        } else {
          trusted.push(currentHostname);
        }

        chrome.storage.local.set({ trustedSites: trusted, customBlacklist: blacklist }, () => {
          updateButtonStates(trusted.includes(currentHostname), false);
          runScanOnTab(currentTabId, currentTabUrl);
        });
      });
    });

    // Blacklist Button
    document.getElementById("blacklistSiteBtn").addEventListener("click", () => {
      if (!currentHostname) return;
      chrome.storage.local.get(["trustedSites", "customBlacklist"], (res) => {
        let blacklist = res.customBlacklist || [];
        let trusted = (res.trustedSites || []).filter(h => h !== currentHostname);

        if (blacklist.includes(currentHostname)) {
          blacklist = blacklist.filter(h => h !== currentHostname);
        } else {
          blacklist.push(currentHostname);
        }

        chrome.storage.local.set({ customBlacklist: blacklist, trustedSites: trusted }, () => {
          updateButtonStates(false, blacklist.includes(currentHostname));
          if (blacklist.includes(currentHostname)) {
            renderScanView({
              risk: 100,
              level: "HIGH_RISK",
              threats: [{ icon: "🚫", text: "Domain is explicitly blocked in your Custom Blacklist." }],
              metrics: { ssl: "Blacklisted", entropy: "--", targetBrand: "None", passwordFields: 0 }
            });
          } else {
            runScanOnTab(currentTabId, currentTabUrl);
          }
        });
      });
    });

    // Deep Scan / Refresh Button
    document.getElementById("deepScanBtn").addEventListener("click", () => {
      if (currentTabId && currentTabUrl) {
        document.getElementById("reasonsList").innerHTML = `<div class="scan-loader"><div class="spinner"></div><span>Deep scanning tab DOM...</span></div>`;
        runScanOnTab(currentTabId, currentTabUrl);
      }
    });

    // Navigation Links
    document.getElementById("viewHistory").addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("history.html") });
    });

    document.getElementById("trustedSitesBtn").addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("trusted.html") });
    });

    document.getElementById("openSandboxBtn").addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("sandbox.html") });
    });
  }

  /**
   * Settings Toggles Sync
   */
  async function initSettingsToggles() {
    const linkShield = document.getElementById("toggleLinkShield");
    const credGuard = document.getElementById("toggleCredentialGuard");
    const autoBlock = document.getElementById("toggleAutoBlock");

    chrome.storage.local.get(["userSettings"], (res) => {
      const settings = res.userSettings || {
        linkShieldEnabled: true,
        credentialGuardEnabled: true,
        autoBlockEnabled: false
      };

      linkShield.checked = settings.linkShieldEnabled !== false;
      credGuard.checked = settings.credentialGuardEnabled !== false;
      autoBlock.checked = settings.autoBlockEnabled === true;
    });

    function saveSettings() {
      const updated = {
        linkShieldEnabled: linkShield.checked,
        credentialGuardEnabled: credGuard.checked,
        autoBlockEnabled: autoBlock.checked
      };

      chrome.storage.local.set({ userSettings: updated });

      // Notify content script in current tab
      if (currentTabId) {
        chrome.tabs.sendMessage(currentTabId, { action: "UPDATE_SETTINGS", settings: updated }, () => {
          if (chrome.runtime.lastError) { /* quiet ignore */ }
        });
      }
    }

    linkShield.addEventListener("change", saveSettings);
    credGuard.addEventListener("change", saveSettings);
    autoBlock.addEventListener("change", saveSettings);
  }
});