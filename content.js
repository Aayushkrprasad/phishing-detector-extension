/**
 * Phishing Detector Pro - Active Real-Time In-Page Content Script
 * Features:
 * 1. Live Hover Link Shield (Instant link inspection badge)
 * 2. In-Page Credential Guard (Alerts user when typing password on unverified/risky sites)
 * 3. Fake OAuth / In-DOM Login Window Detector
 * 4. Crypto Clipboard Hijack (Clipjacking) Sentinel
 * 5. Cross-Origin Form Exfiltration Guard
 * 6. Deep DOM Analysis (Brand spoofing, fake login dialogs, deceptive urgency)
 */

(() => {
  // Guard against duplicate injection
  if (window.__pdpInitialized) return;
  window.__pdpInitialized = true;

  let userSettings = {
    realTimeShieldEnabled: true,
    linkShieldEnabled: true,
    credentialGuardEnabled: true,
    autoBlockEnabled: false,
    clipGuardEnabled: true,
    audioAlertsEnabled: true
  };

  // Load preferences from storage
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["userSettings", "trustedSites"], (res) => {
      if (res.userSettings) {
        userSettings = { ...userSettings, ...res.userSettings };
      }
      window.__pdpTrustedSites = res.trustedSites || [];
    });
  }

  // -------------------------------------------------------------
  // 1. Hover Link Shield Tooltip
  // -------------------------------------------------------------
  let shieldEl = null;
  let currentHoveredLink = null;
  let hoverTimeout = null;

  function initLinkShield() {
    if (document.getElementById("pdp-link-shield")) return;

    shieldEl = document.createElement("div");
    shieldEl.id = "pdp-link-shield";
    shieldEl.innerHTML = `
      <span class="pdp-shield-indicator pdp-shield-safe"></span>
      <span class="pdp-shield-text">Checking...</span>
      <span class="pdp-shield-host"></span>
      <span class="pdp-shield-tag pdp-tag-safe">SAFE</span>
    `;
    document.body.appendChild(shieldEl);

    // Event delegation on mouseover
    document.addEventListener("mouseover", handleLinkMouseOver, true);
    document.addEventListener("mouseout", handleLinkMouseOut, true);
    document.addEventListener("mousemove", handleLinkMouseMove, true);
  }

  function handleLinkMouseOver(e) {
    if (userSettings.realTimeShieldEnabled === false || !userSettings.linkShieldEnabled) return;

    const link = e.target.closest("a[href]");
    if (!link || !link.href) return;

    // Ignore internal anchor hashes or javascript: pseudo-protocols
    const href = link.href.trim();
    if (href.startsWith("javascript:") || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
      return;
    }

    currentHoveredLink = link;
    clearTimeout(hoverTimeout);

    // Debounce hover evaluation slightly for performance
    hoverTimeout = setTimeout(() => {
      if (currentHoveredLink === link) {
        evaluateAndDisplayLinkBadge(href, e.pageX, e.pageY);
      }
    }, 120);
  }

  function handleLinkMouseOut(e) {
    const link = e.target.closest("a[href]");
    if (link && link === currentHoveredLink) {
      clearTimeout(hoverTimeout);
      currentHoveredLink = null;
      if (shieldEl) {
        shieldEl.classList.remove("pdp-visible");
      }
    }
  }

  function handleLinkMouseMove(e) {
    if (shieldEl && shieldEl.classList.contains("pdp-visible")) {
      positionShield(e.pageX, e.pageY);
    }
  }

  function positionShield(x, y) {
    if (!shieldEl) return;
    const offset = 14;
    shieldEl.style.left = `${x + offset}px`;
    shieldEl.style.top = `${y + offset}px`;
  }

  function evaluateAndDisplayLinkBadge(url, x, y) {
    if (!shieldEl) return;

    try {
      const evaluation = window.ThreatEngine
        ? window.ThreatEngine.evaluateUrlThreat(url)
        : fallbackUrlEval(url);

      const indicator = shieldEl.querySelector(".pdp-shield-indicator");
      const textEl = shieldEl.querySelector(".pdp-shield-text");
      const hostEl = shieldEl.querySelector(".pdp-shield-host");
      const tagEl = shieldEl.querySelector(".pdp-shield-tag");

      let host = "";
      try { host = new URL(url).hostname; } catch(e) { host = url; }
      hostEl.textContent = `(${host})`;

      indicator.className = "pdp-shield-indicator";
      tagEl.className = "pdp-shield-tag";

      if (evaluation.risk >= 50) {
        indicator.classList.add("pdp-shield-danger");
        tagEl.classList.add("pdp-tag-danger");
        tagEl.textContent = "PHISHING RISK";
        textEl.textContent = evaluation.threats[0]?.text || "High Threat Detected";
      } else if (evaluation.risk >= 20) {
        indicator.classList.add("pdp-shield-warn");
        tagEl.classList.add("pdp-tag-warn");
        tagEl.textContent = "CAUTION";
        textEl.textContent = evaluation.threats[0]?.text || "Suspicious Link";
      } else {
        indicator.classList.add("pdp-shield-safe");
        tagEl.classList.add("pdp-tag-safe");
        tagEl.textContent = "VERIFIED";
        textEl.textContent = "Link Looks Safe";
      }

      positionShield(x, y);
      shieldEl.classList.add("pdp-visible");
    } catch (e) {
      // Quiet fail
    }
  }

  function fallbackUrlEval(url) {
    let risk = 0;
    const threats = [];
    if (!url.startsWith("https://")) {
      risk += 20;
      threats.push({ text: "Insecure HTTP connection" });
    }
    if (url.includes("@")) {
      risk += 35;
      threats.push({ text: "Embedded credentials / @" });
    }
    return { risk, threats };
  }

  // -------------------------------------------------------------
  // 2. Credential Guard (Anti-Password Harvesting)
  // -------------------------------------------------------------
  function initCredentialGuard() {
    document.addEventListener("focusin", (e) => {
      if (userSettings.realTimeShieldEnabled === false || !userSettings.credentialGuardEnabled) return;
      const target = e.target;
      if (!target || target.nodeName !== "INPUT") return;

      const isSensitiveInput =
        target.type === "password" ||
        target.name?.toLowerCase().includes("card") ||
        target.name?.toLowerCase().includes("cvv") ||
        target.name?.toLowerCase().includes("ssn");

      if (isSensitiveInput) {
        checkAndWarnCredentialField(target);
      }
    }, true);
  }

  function checkAndWarnCredentialField(inputEl) {
    const currentHost = window.location.hostname.toLowerCase();
    const isHttps = window.location.protocol === "https:";
    const isTrusted = (window.__pdpTrustedSites || []).includes(currentHost);

    if (isTrusted) return;

    // Check if form or page is suspicious
    const evaluation = window.ThreatEngine
      ? window.ThreatEngine.evaluateUrlThreat(window.location.href)
      : fallbackUrlEval(window.location.href);

    const form = inputEl.closest("form");
    let isExternalAction = false;
    if (form && form.action) {
      try {
        const actionHost = new URL(form.action, window.location.href).hostname.toLowerCase();
        if (actionHost && actionHost !== currentHost) {
          isExternalAction = true;
        }
      } catch (e) {}
    }

    const needsWarning = !isHttps || evaluation.risk >= 30 || isExternalAction;

    if (needsWarning) {
      const container = form || inputEl.parentElement || document.body;
      if (container.querySelector(".pdp-credential-guard-banner")) return; // already shown

      const banner = document.createElement("div");
      banner.className = "pdp-credential-guard-banner";
      banner.innerHTML = `
        <div class="pdp-guard-icon">🛡️</div>
        <div class="pdp-guard-content">
          <div class="pdp-guard-title">
            <span>Phishing Detector: Sensitive Input Alert</span>
          </div>
          <div class="pdp-guard-desc">
            ${
              !isHttps
                ? "This page is using an insecure connection (HTTP). Never enter passwords or payment information here."
                : isExternalAction
                ? "This form submits your credentials to an external destination! It may be an exfiltration attempt."
                : "This domain triggered security heuristic flags. Confirm the URL address carefully before logging in."
            }
          </div>
        </div>
        <button type="button" class="pdp-guard-close" title="Dismiss warning">✕</button>
      `;

      banner.querySelector(".pdp-guard-close").addEventListener("click", () => {
        banner.remove();
      });

      if (form) {
        form.insertBefore(banner, form.firstChild);
      } else {
        inputEl.parentElement.insertBefore(banner, inputEl);
      }
      playSecurityAudioAlert("warn");
    }
  }

  // -------------------------------------------------------------
  // 3. Fake OAuth / Fake Browser Window Detector
  // -------------------------------------------------------------
  function initFakeOAuthDetector() {
    const observer = new MutationObserver(() => {
      checkForFakeOAuthModals();
    });
    observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
    checkForFakeOAuthModals();
  }

  function checkForFakeOAuthModals() {
    if (userSettings.realTimeShieldEnabled === false) return;
    const currentHost = window.location.hostname.toLowerCase();
    if ((window.__pdpTrustedSites || []).includes(currentHost)) return;

    // Check for elements that mimic a browser window / OAuth titlebar
    const candidateContainers = document.querySelectorAll("div, section, modal");
    candidateContainers.forEach(el => {
      if (el.dataset.pdpChecked) return;
      const text = (el.innerText || "").toLowerCase();
      
      const hasOAuthBrand = text.includes("sign in with google") || text.includes("sign in with microsoft") || text.includes("sign in with apple");
      const hasSimulatedAddressBar = el.querySelector("input[value*='accounts.google.com'], input[value*='login.microsoftonline.com'], input[value*='appleid.apple.com']") ||
                                    (text.includes("accounts.google.com") && text.includes("https://"));

      if (hasOAuthBrand && hasSimulatedAddressBar) {
        el.dataset.pdpChecked = "true";
        showToastAlert(
          "🚨 Fake OAuth Window Detected",
          "This page is simulating a browser login window inside the DOM to steal OAuth credentials. Do not type your password!"
        );
      }
    });
  }

  // -------------------------------------------------------------
  // 4. Crypto Clipboard Hijacking (Clipjacking) Guard
  // -------------------------------------------------------------
  function initClipboardGuard() {
    let lastCopiedText = "";

    document.addEventListener("copy", () => {
      const selected = window.getSelection().toString();
      if (selected) lastCopiedText = selected.trim();
    }, true);

    // Watch for malicious script modification to clipboard
    document.addEventListener("copy", (e) => {
      if (userSettings.realTimeShieldEnabled === false) return;
      setTimeout(async () => {
        try {
          if (!navigator.clipboard || !navigator.clipboard.readText) return;
          const currentClip = await navigator.clipboard.readText();
          
          // Regex for Bitcoin, Ethereum, Solana addresses
          const cryptoRegex = /(^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$)|(^0x[a-fA-F0-9]{40}$)|(^[1-9A-HJ-NP-Za-km-z]{32,44}$)/;
          
          if (cryptoRegex.test(currentClip) && lastCopiedText && lastCopiedText !== currentClip) {
            showToastAlert(
              "⚠️ Clipboard Hijacking Detected",
              "A background script altered the cryptocurrency address in your clipboard! Always double-check recipient addresses."
            );
          }
        } catch (e) {}
      }, 300);
    }, true);
  }

  function showToastAlert(title, message) {
    playSecurityAudioAlert("danger");
    const existing = document.getElementById("pdp-toast-alert");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "pdp-toast-alert";
    toast.className = "pdp-toast-alert";
    toast.innerHTML = `
      <div class="pdp-toast-icon">🛡️</div>
      <div class="pdp-toast-body">
        <strong>${title}</strong>
        <p>${message}</p>
      </div>
      <button class="pdp-toast-close">✕</button>
    `;

    toast.querySelector(".pdp-toast-close").addEventListener("click", () => toast.remove());
    document.body.appendChild(toast);

    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 8000);
  }

  // -------------------------------------------------------------
  // Web Audio API Synthesizer Alert Sounds
  // -------------------------------------------------------------
  function playSecurityAudioAlert(type) {
    if (userSettings.audioAlertsEnabled === false) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (type === "danger") {
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.3);
      } else if (type === "warn") {
        osc.type = "sine";
        osc.frequency.setValueAtTime(587, ctx.currentTime);
        gain.gain.setValueAtTime(0.1, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.2);
      } else {
        osc.type = "sine";
        osc.frequency.setValueAtTime(1046, ctx.currentTime);
        gain.gain.setValueAtTime(0.08, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.15);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.15);
      }
    } catch (e) {}
  }

  // -------------------------------------------------------------
  // 5. Deep Page Inspection (Called by popup / background)
  // -------------------------------------------------------------
  window.performDeepPageScan = function() {
    const rawUrl = window.location.href;
    const host = window.location.hostname.toLowerCase();

    // 1. Run URL evaluation from Heuristics Engine
    const urlEval = window.ThreatEngine
      ? window.ThreatEngine.evaluateUrlThreat(rawUrl)
      : fallbackUrlEval(rawUrl);

    let risk = urlEval.risk || 0;
    const threats = [...(urlEval.threats || [])];
    const metrics = { ...(urlEval.metrics || {}) };

    // 2. DOM Password Field Checks
    const passwordInputs = document.querySelectorAll("input[type='password']");
    metrics.passwordFields = passwordInputs.length;
    if (passwordInputs.length > 0) {
      if (window.location.protocol !== "https:") {
        risk += 35;
        threats.push({
          icon: "🚨",
          type: "INSECURE_PASSWORD",
          text: "Password input on unencrypted HTTP page. Credentials will be sent in plain text!"
        });
      }
    }

    // 3. Deceptive Urgent & Social Engineering Keywords in DOM Text
    const pageText = (document.body ? document.body.innerText : "").toLowerCase();
    const phishingPhrases = [
      { phrase: "account suspended", risk: 20, icon: "⚠️" },
      { phrase: "unauthorized activity detected", risk: 25, icon: "🚨" },
      { phrase: "verify your identity immediately", risk: 25, icon: "⚠️" },
      { phrase: "confirm your banking details", risk: 30, icon: "💳" },
      { phrase: "update payment information to avoid termination", risk: 25, icon: "⚠️" },
      { phrase: "crypto wallet recovery phrase", risk: 35, icon: "🪙" },
      { phrase: "enter your 12-word seed phrase", risk: 40, icon: "🔑" }
    ];

    let foundUrgentPhrase = false;
    for (const item of phishingPhrases) {
      if (pageText.includes(item.phrase)) {
        risk += item.risk;
        threats.push({
          icon: item.icon,
          type: "SOCIAL_ENGINEERING",
          text: `Social engineering phrase found: "${item.phrase}"`
        });
        foundUrgentPhrase = true;
        break;
      }
    }
    metrics.urgentPhrases = foundUrgentPhrase;

    // 4. Form Action Hijack & Exfiltration Check
    let externalFormCount = 0;
    const forms = document.querySelectorAll("form");
    forms.forEach(form => {
      const action = form.getAttribute("action");
      if (action && !action.startsWith("#") && !action.startsWith("javascript:")) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname && actionUrl.hostname.toLowerCase() !== host) {
            externalFormCount++;
            if (actionUrl.href.includes("discord.com/api/webhooks") || actionUrl.href.includes("api.telegram.org")) {
              risk += 50;
              threats.push({
                icon: "🚨",
                type: "WEBHOOK_EXFILTRATION",
                text: "Form exfiltrates data directly to third-party webhook service (Discord/Telegram)!"
              });
            }
          }
        } catch (e) {}
      }
    });
    metrics.externalForms = externalFormCount;
    if (externalFormCount > 0 && !threats.some(t => t.type === "WEBHOOK_EXFILTRATION")) {
      risk += 35;
      threats.push({
        icon: "📤",
        type: "EXTERNAL_FORM",
        text: `Form submits data to an external third-party domain (${externalFormCount} found).`
      });
    }

    // 5. Hidden & Obfuscated iFrames Check
    let hiddenIframeFound = false;
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      const isZeroSize = iframe.width === "0" || iframe.height === "0" || iframe.style.width === "0px" || iframe.style.height === "0px";
      const isHidden = style.display === "none" || style.visibility === "hidden" || style.opacity === "0" || isZeroSize;
      if (isHidden) {
        hiddenIframeFound = true;
      }
    });
    metrics.hiddenIframes = hiddenIframeFound;
    if (hiddenIframeFound) {
      risk += 25;
      threats.push({
        icon: "🕵️",
        type: "HIDDEN_IFRAME",
        text: "Hidden iframe detected. Could be running stealth clickjacking or credential harvesting."
      });
    }

    // 6. Brand Impersonation via Page Title Spoofing
    const pageTitle = (document.title || "").toLowerCase();
    if (window.ThreatEngine) {
      for (const brand of window.ThreatEngine.PROTECTED_BRANDS) {
        const isOfficialDomain = host === brand.domain || host.endsWith("." + brand.domain);
        if (!isOfficialDomain) {
          if (pageTitle.includes(brand.name.toLowerCase()) && (passwordInputs.length > 0 || pageText.includes("login") || pageText.includes("sign in"))) {
            risk += 40;
            threats.push({
              icon: "🎭",
              type: "TITLE_SPOOFING",
              text: `Page claims to be '${brand.name}' in title, but is hosted on unofficial '${host}'.`
            });
            break;
          }
        }
      }
    }

    risk = Math.min(Math.max(risk, 0), 100);
    let level = "SAFE";
    if (risk >= 60) level = "HIGH_RISK";
    else if (risk >= 25) level = "SUSPICIOUS";

    return {
      risk,
      level,
      threats,
      metrics,
      hostname: host,
      url: rawUrl,
      title: document.title || host,
      timestamp: new Date().toISOString()
    };
  };

  // Message listener for popup requests
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === "RUN_DEEP_SCAN") {
        const scanResult = window.performDeepPageScan();
        sendResponse({ success: true, data: scanResult });
      } else if (request.action === "UPDATE_SETTINGS") {
        userSettings = { ...userSettings, ...request.settings };
        sendResponse({ success: true });
      }
      return true;
    });
  }

  // Initialize in-page tools when DOM is ready
  function initAll() {
    initLinkShield();
    initCredentialGuard();
    initFakeOAuthDetector();
    initClipboardGuard();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll);
  } else {
    initAll();
  }
})();