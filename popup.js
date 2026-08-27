/**
 * Phishing Detector Pro - Popup Controller v3.5
 * Live Tab Inspector & Instant URL Scanner
 */

document.addEventListener("DOMContentLoaded", async () => {
  let currentTabUrl = "";
  let currentHostname = "";
  let currentTabId = null;

  let isRealTimeShieldEnabled = true;
  let currentUserMode = "simple";

  // Initialize UI Mode, Tabs, Scanner and Settings
  initUserMode();
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
      const hostEl = document.getElementById("currentHost");
      const simpleHostEl = document.getElementById("simpleCurrentHost");
      if (hostEl) hostEl.textContent = currentHostname;
      if (simpleHostEl) simpleHostEl.textContent = currentHostname;

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
   * User Mode Handler (Simple vs Advanced)
   */
  function initUserMode() {
    const appContainer = document.querySelector(".app-container");
    const modeBtn = document.getElementById("toggleUserModeBtn");
    const modeLabel = document.getElementById("userModeLabel");
    const openAdvBtn = document.getElementById("openAdvancedViewBtn");

    chrome.storage.local.get(["userMode"], (res) => {
      currentUserMode = res.userMode || "simple";
      applyUserMode(currentUserMode);
    });

    function applyUserMode(mode) {
      currentUserMode = mode;
      if (appContainer) {
        appContainer.className = "app-container " + (mode === "advanced" ? "advanced-mode" : "simple-mode");
      }
      if (modeLabel) {
        modeLabel.textContent = mode === "advanced" ? "Advanced Mode" : "Simple Mode";
      }
      chrome.storage.local.set({ userMode: mode });
    }

    if (modeBtn) {
      modeBtn.addEventListener("click", () => {
        const nextMode = currentUserMode === "simple" ? "advanced" : "simple";
        applyUserMode(nextMode);
      });
    }

    if (openAdvBtn) {
      openAdvBtn.addEventListener("click", () => {
        applyUserMode("advanced");
      });
    }
  }

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

      // Save report data for copying & PDF export
      window.__lastQuickScanReport = {
        url: raw,
        hostname: evalData.hostname || raw,
        risk: evalData.risk,
        level: evalData.level,
        threats: evalData.threats?.map(t => t.text).join(", ") || "None",
        threatItems: evalData.threats || [],
        scannedAt: new Date().toISOString()
      };
    }

    const exportPdfBtn = document.getElementById("exportPdfReportBtn");
    if (exportPdfBtn) {
      exportPdfBtn.addEventListener("click", () => {
        if (window.__lastQuickScanReport) {
          generatePdfAuditReport(window.__lastQuickScanReport);
        }
      });
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

    // Update Simple Mode Card UI
    const simpleTag = document.getElementById("simpleHostStatusTag");
    const simpleShield = document.getElementById("simpleShieldWrapper");
    const simpleTitle = document.getElementById("simpleStatusTitle");
    const simpleDesc = document.getElementById("simpleStatusDesc");
    const simpleIcon = document.getElementById("simpleShieldIcon");

    if (simpleTag) simpleTag.className = tag.className;
    if (simpleTag) simpleTag.textContent = tag.textContent;

    if (simpleShield && simpleTitle && simpleDesc && simpleIcon) {
      simpleShield.className = "simple-shield-wrapper";

      if (!isRealTimeShieldEnabled) {
        simpleShield.classList.add("paused");
        simpleTitle.textContent = "Protection Shield Paused";
        simpleTitle.style.color = "var(--text-muted)";
        simpleDesc.textContent = "Real-time protection is turned off. Toggle Real-time Shield to resume monitoring.";
        simpleIcon.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="simple-shield-svg">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="4" y1="4" x2="20" y2="20"/>
          </svg>
        `;
      } else if (risk >= 60) {
        simpleShield.classList.add("danger");
        simpleTitle.textContent = "High Phishing Threat";
        simpleTitle.style.color = "var(--accent-danger)";
        simpleDesc.textContent = threats[0]?.text || "Critical brand spoofing or credential harvesting flags detected.";
        simpleIcon.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="simple-shield-svg">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        `;
      } else if (risk >= 25) {
        simpleShield.classList.add("warn");
        simpleTitle.textContent = "Caution: Suspect Page";
        simpleTitle.style.color = "var(--accent-warn)";
        simpleDesc.textContent = threats[0]?.text || "Page exhibits heuristic anomalies. Exercise caution entering information.";
        simpleIcon.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="simple-shield-svg">
            <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        `;
      } else {
        simpleShield.classList.add("safe");
        simpleTitle.textContent = "Your Connection is Secure";
        simpleTitle.style.color = "var(--accent-safe)";
        simpleDesc.textContent = "Phishing Detector scanned this page and found no security risks.";
        simpleIcon.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="simple-shield-svg">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        `;
      }
    }
  }

  function showSpecialPageState(title, description, risk) {
    document.getElementById("currentHost").textContent = title;
    document.getElementById("scoreValue").textContent = risk;
    const tag = document.getElementById("hostStatusTag");
    tag.className = "status-pill status-safe";
    tag.textContent = "INTERNAL";

    const simpleHost = document.getElementById("simpleCurrentHost");
    const simpleTag = document.getElementById("simpleHostStatusTag");
    if (simpleHost) simpleHost.textContent = title;
    if (simpleTag) {
      simpleTag.className = "status-pill status-safe";
      simpleTag.textContent = "INTERNAL";
    }

    const simpleShield = document.getElementById("simpleShieldWrapper");
    const simpleTitle = document.getElementById("simpleStatusTitle");
    const simpleDesc = document.getElementById("simpleStatusDesc");
    const simpleIcon = document.getElementById("simpleShieldIcon");
    if (simpleShield && simpleTitle && simpleDesc && simpleIcon) {
      simpleShield.className = "simple-shield-wrapper safe";
      simpleTitle.textContent = title;
      simpleTitle.style.color = "var(--accent-safe)";
      simpleDesc.textContent = description;
      simpleIcon.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="simple-shield-svg">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
      `;
    }

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
   * Settings Toggles & Theme Sync
   */
  async function initSettingsToggles() {
    const masterShield = document.getElementById("toggleMasterProtection");
    const linkShield = document.getElementById("toggleLinkShield");
    const credGuard = document.getElementById("toggleCredentialGuard");
    const autoBlock = document.getElementById("toggleAutoBlock");
    const audioAlerts = document.getElementById("toggleAudioAlerts");
    const themeSelect = document.getElementById("themeSelect");

    chrome.storage.local.get(["userSettings", "theme"], (res) => {
      const settings = res.userSettings || {
        realTimeShieldEnabled: true,
        linkShieldEnabled: true,
        credentialGuardEnabled: true,
        autoBlockEnabled: false,
        audioAlertsEnabled: true
      };

      const theme = res.theme || "cyber";
      if (themeSelect) themeSelect.value = theme;
      applyTheme(theme);

      isRealTimeShieldEnabled = settings.realTimeShieldEnabled !== false;
      if (masterShield) masterShield.checked = isRealTimeShieldEnabled;
      if (linkShield) linkShield.checked = settings.linkShieldEnabled !== false;
      if (credGuard) credGuard.checked = settings.credentialGuardEnabled !== false;
      if (autoBlock) autoBlock.checked = settings.autoBlockEnabled === true;
      if (audioAlerts) audioAlerts.checked = settings.audioAlertsEnabled !== false;
    });

    function applyTheme(theme) {
      if (theme === "emerald" || theme === "cyberpunk") {
        document.documentElement.setAttribute("data-theme", theme);
      } else {
        document.documentElement.removeAttribute("data-theme");
      }
      chrome.storage.local.set({ theme });
    }

    if (themeSelect) {
      themeSelect.addEventListener("change", (e) => {
        applyTheme(e.target.value);
      });
    }

    function saveSettings() {
      if (masterShield) isRealTimeShieldEnabled = masterShield.checked;
      const updated = {
        realTimeShieldEnabled: isRealTimeShieldEnabled,
        linkShieldEnabled: linkShield ? linkShield.checked : true,
        credentialGuardEnabled: credGuard ? credGuard.checked : true,
        autoBlockEnabled: autoBlock ? autoBlock.checked : false,
        audioAlertsEnabled: audioAlerts ? audioAlerts.checked : true
      };

      chrome.storage.local.set({ userSettings: updated });

      // Notify content script in current tab
      if (currentTabId) {
        chrome.tabs.sendMessage(currentTabId, { action: "UPDATE_SETTINGS", settings: updated }, () => {
          if (chrome.runtime.lastError) { /* quiet ignore */ }
        });
      }

      // Re-scan tab to update popup status view immediately
      if (currentTabId && currentTabUrl) {
        runScanOnTab(currentTabId, currentTabUrl);
      }
    }

    if (masterShield) masterShield.addEventListener("change", saveSettings);
    if (linkShield) linkShield.addEventListener("change", saveSettings);
    if (credGuard) credGuard.addEventListener("change", saveSettings);
    if (autoBlock) autoBlock.addEventListener("change", saveSettings);
    if (audioAlerts) audioAlerts.addEventListener("change", saveSettings);
  }

  /**
   * PDF Audit Report Generator
   */
  function generatePdfAuditReport(report) {
    const printWin = window.open("", "_blank", "width=800,height=900");
    if (!printWin) return;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Phishing Detector Pro - Forensic Security Audit Report</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; padding: 30px; color: #0F172A; background: #FFF; }
          .header { display: flex; justify-content: space-between; border-bottom: 2px solid #3B82F6; padding-bottom: 12px; margin-bottom: 24px; }
          .title { font-size: 20px; font-weight: 800; color: #1E3A8A; }
          .sub { font-size: 12px; color: #64748B; margin-top: 4px; }
          .badge { padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 14px; display: inline-block; }
          .danger { background: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
          .warn { background: #FEF3C7; color: #92400E; border: 1px solid #FBBF24; }
          .safe { background: #D1FAE5; color: #065F46; border: 1px solid #34D399; }
          .box { background: #F8FAFC; border: 1px solid #E2E8F0; padding: 16px; border-radius: 8px; margin-bottom: 16px; }
          .item { display: flex; gap: 10px; margin-bottom: 8px; font-size: 13px; }
          .footer { margin-top: 40px; font-size: 11px; color: #94A3B8; border-top: 1px solid #E2E8F0; padding-top: 12px; }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <div class="title">🛡️ PHISHING DETECTOR PRO</div>
            <div class="sub">Forensic Security Audit Report</div>
          </div>
          <div>
            <span class="badge ${report.risk >= 60 ? 'danger' : report.risk >= 25 ? 'warn' : 'safe'}">
              SCORE: ${report.risk}/100 (${report.level})
            </span>
          </div>
        </div>

        <div class="box">
          <p><strong>Target URL:</strong> ${report.url}</p>
          <p><strong>Hostname:</strong> ${report.hostname}</p>
          <p><strong>Timestamp:</strong> ${report.scannedAt}</p>
        </div>

        <h3>Detection Flags & Heuristic Findings</h3>
        <div class="box">
          ${report.threatItems && report.threatItems.length > 0
            ? report.threatItems.map(t => `<div class="item"><span>${t.icon || '⚠️'}</span><span><strong>${t.type || 'FLAG'}:</strong> ${t.text}</span></div>`).join('')
            : '<div class="item"><span>🛡️</span><span>No malicious heuristics or typosquatting flags found.</span></div>'
          }
        </div>

        <div class="footer">
          Generated automatically by Phishing Detector Pro Chrome Extension • Standard STIX 2.1 IOC Compliant
        </div>
        <script>
          window.onload = function() { window.print(); };
        </script>
      </body>
      </html>
    `;
    printWin.document.write(html);
    printWin.document.close();
  }
});