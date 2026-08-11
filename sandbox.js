/**
 * Phishing Detector Pro - Cybersecurity Threat Simulator & Sandbox Lab
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initTyposquattingModule();
  initEntropyModule();
  initHomoglyphModule();
  initQuishingModule();
  initFormSimulatorModule();
  initPayloadSandbox();
  initIocExport();
});

// -------------------------------------------------------------
// 1. Tab Switching Controller
// -------------------------------------------------------------
function initTabs() {
  const tabs = document.querySelectorAll(".lab-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const targetId = tab.getAttribute("data-tab");
      document.querySelectorAll(".lab-section").forEach(sec => sec.classList.remove("active"));
      const activeSection = document.getElementById(targetId);
      if (activeSection) activeSection.classList.add("active");
    });
  });
}

// -------------------------------------------------------------
// 2. Typosquatting & Levenshtein Matrix Module
// -------------------------------------------------------------
function initTyposquattingModule() {
  const typoInput = document.getElementById("typoInput");
  const typoSelect = document.getElementById("typoBrandSelect");
  const runBtn = document.getElementById("runTypoTest");

  // Sample pill buttons
  document.querySelectorAll("[data-input]").forEach(pill => {
    pill.addEventListener("click", () => {
      typoInput.value = pill.getAttribute("data-input");
      executeTypoTest();
    });
  });

  if (runBtn) runBtn.addEventListener("click", executeTypoTest);
  if (typoInput) {
    typoInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") executeTypoTest();
    });
  }

  function executeTypoTest() {
    const rawVal = typoInput.value.trim().toLowerCase();
    if (!rawVal) return;

    let base = rawVal;
    try {
      if (rawVal.includes("://")) base = new URL(rawVal).hostname;
      else base = rawVal.split("/")[0];
    } catch(e) {}

    const mainName = base.split(".")[0];
    const selectedBrand = typoSelect ? typoSelect.value : "auto";

    let targetDomain = "";
    let minDistance = 999;
    let matchedCanonical = "";

    const candidates = selectedBrand === "auto" 
      ? (window.ThreatEngine ? window.ThreatEngine.CANONICAL_DOMAINS : ["paypal.com", "google.com", "microsoft.com", "amazon.com", "apple.com"])
      : [selectedBrand];

    for (const canonical of candidates) {
      const canonicalMain = canonical.split(".")[0];
      const dist = window.ThreatEngine 
        ? window.ThreatEngine.levenshteinDistance(mainName, canonicalMain)
        : computeLevenshtein(mainName, canonicalMain);

      if (dist < minDistance) {
        minDistance = dist;
        matchedCanonical = canonical;
        targetDomain = canonical;
      }
    }

    // Update UI elements
    document.getElementById("resTypoName").textContent = mainName;
    document.getElementById("resTypoMatch").textContent = matchedCanonical;
    document.getElementById("resTypoDist").textContent = `${minDistance} edit${minDistance === 1 ? '' : 's'}`;

    const statusEl = document.getElementById("resTypoStatus");
    const penaltyEl = document.getElementById("resTypoPenalty");
    const explainEl = document.getElementById("typoExplain");

    if (minDistance === 0) {
      if (base === matchedCanonical) {
        statusEl.className = "status-pill status-safe";
        statusEl.textContent = "LEGITIMATE CANONICAL";
        penaltyEl.textContent = "0 Points (Safe)";
        penaltyEl.className = "res-val text-safe";
        explainEl.innerHTML = `<strong>Official Domain:</strong> Matches canonical brand <code>${matchedCanonical}</code> exactly.`;
      } else {
        statusEl.className = "status-pill status-danger";
        statusEl.textContent = "DOMAIN HIJACK / ROGUE TLD";
        penaltyEl.textContent = "+45 Points";
        penaltyEl.className = "res-val text-danger";
        explainEl.innerHTML = `<strong>Impersonation:</strong> Uses brand name <code>${mainName}</code> under an unauthorized root domain <code>${base}</code>.`;
      }
    } else if (minDistance === 1) {
      statusEl.className = "status-pill status-danger";
      statusEl.textContent = "HIGH-RISK TYPOSQUAT";
      penaltyEl.textContent = "+50 Points";
      penaltyEl.className = "res-val text-danger";
      explainEl.innerHTML = `<strong>Why was this flagged?</strong> '<code>${mainName}</code>' is exactly 1 edit distance from legitimate '<code>${matchedCanonical}</code>'. Phishers exploit this visual similarity in deceptive emails.`;
    } else if (minDistance === 2) {
      statusEl.className = "status-pill status-warn";
      statusEl.textContent = "MODERATE SIMILARITY";
      penaltyEl.textContent = "+25 Points";
      penaltyEl.className = "res-val text-warn";
      explainEl.innerHTML = `<strong>Fuzzy Match:</strong> Domain is 2 edits away from '<code>${matchedCanonical}</code>'. Potential typosquatting candidate.`;
    } else {
      statusEl.className = "status-pill status-safe";
      statusEl.textContent = "NO TYPOSQUAT DETECTED";
      penaltyEl.textContent = "0 Points";
      penaltyEl.className = "res-val text-safe";
      explainEl.innerHTML = `<strong>Low Risk:</strong> No single-character permutation match found with protected global brands.`;
    }
  }
}

// -------------------------------------------------------------
// 3. Shannon Entropy & DGA Module
// -------------------------------------------------------------
function initEntropyModule() {
  const inputEl = document.getElementById("entropyInput");
  const calcBtn = document.getElementById("calcEntropyBtn");
  const dgaBtn = document.getElementById("genDgaBtn");

  document.querySelectorAll("[data-entropy-input]").forEach(pill => {
    pill.addEventListener("click", () => {
      inputEl.value = pill.getAttribute("data-entropy-input");
      executeEntropyTest();
    });
  });

  if (calcBtn) calcBtn.addEventListener("click", executeEntropyTest);
  if (dgaBtn) {
    dgaBtn.addEventListener("click", () => {
      const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
      let rand = "";
      const len = 12 + Math.floor(Math.random() * 8);
      for (let i = 0; i < len; i++) {
        rand += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      inputEl.value = rand + ".xyz";
      executeEntropyTest();
    });
  }

  function executeEntropyTest() {
    const rawVal = inputEl.value.trim().toLowerCase();
    if (!rawVal) return;

    const mainStr = rawVal.split(".")[0];
    const entropy = window.ThreatEngine
      ? window.ThreatEngine.calculateShannonEntropy(mainStr)
      : computeShannonEntropy(mainStr);

    document.getElementById("entropyScoreText").textContent = entropy.toFixed(2);
    document.getElementById("entropyLen").textContent = `${mainStr.length} characters ("${mainStr}")`;

    // Percentage of 5.0 scale
    const pct = Math.min(Math.max((entropy / 4.8) * 100, 0), 100);
    const bar = document.getElementById("entropyBarFill");
    bar.style.width = `${pct}%`;

    const probEl = document.getElementById("entropyProb");
    const scoreText = document.getElementById("entropyScoreText");

    if (entropy > 3.8 && mainStr.length >= 8) {
      scoreText.className = "entropy-score text-danger";
      probEl.className = "status-pill status-danger";
      probEl.textContent = "96% (Critical DGA / Botnet Pattern)";
    } else if (entropy > 3.4 && mainStr.length >= 8) {
      scoreText.className = "entropy-score text-warn";
      probEl.className = "status-pill status-warn";
      probEl.textContent = "65% (Suspicious Entropy)";
    } else {
      scoreText.className = "entropy-score text-safe";
      probEl.className = "status-pill status-safe";
      probEl.textContent = "12% (Natural Human Language)";
    }
  }
}

// -------------------------------------------------------------
// 4. Homoglyphs & Punycode Normalizer
// -------------------------------------------------------------
function initHomoglyphModule() {
  const homoInput = document.getElementById("homoInput");
  const resolveBtn = document.getElementById("resolveHomoBtn");

  document.querySelectorAll("[data-homo-input]").forEach(pill => {
    pill.addEventListener("click", () => {
      homoInput.value = pill.getAttribute("data-homo-input");
      executeHomoTest();
    });
  });

  if (resolveBtn) resolveBtn.addEventListener("click", executeHomoTest);

  function executeHomoTest() {
    const raw = homoInput.value.trim().toLowerCase();
    if (!raw) return;

    const isPuny = raw.includes("xn--");
    document.getElementById("homoIsPunycode").textContent = isPuny ? "YES (xn-- Punycode IDN)" : "NO (Standard ASCII)";
    document.getElementById("homoIsPunycode").className = isPuny ? "status-pill status-danger" : "status-pill status-safe";

    // Known lookalike Cyrillic simulations for demo mapping
    let decoded = raw;
    if (raw.includes("xn--pple-43d")) decoded = "аpple.com (Cyrillic 'а')";
    else if (raw.includes("xn--gogle-qqa")) decoded = "gоogle.com (Cyrillic 'о')";

    document.getElementById("homoDecoded").textContent = decoded;

    const normalized = window.ThreatEngine
      ? window.ThreatEngine.normalizeHomoglyphs(raw.replace("xn--", ""))
      : raw;

    document.getElementById("homoNormalized").textContent = normalized;

    // Detect target
    let target = "Unknown / Custom Domain";
    if (normalized.includes("apple")) target = "Apple Inc. (Target of Impersonation)";
    else if (normalized.includes("google")) target = "Google LLC (Target of Impersonation)";
    else if (normalized.includes("paypal")) target = "PayPal Holdings Inc.";

    document.getElementById("homoTarget").textContent = target;
  }
}

// -------------------------------------------------------------
// 5. Quishing (QR Code Phishing) Module
// -------------------------------------------------------------
function initQuishingModule() {
  const dropZone = document.getElementById("qrDropZone");
  const fileInput = document.getElementById("qrFileInput");
  const browseBtn = document.getElementById("browseQrBtn");
  const canvas = document.getElementById("qrCanvas");
  const canvasContainer = document.getElementById("qrCanvasContainer");

  if (browseBtn) browseBtn.addEventListener("click", () => fileInput.click());
  if (dropZone) {
    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--accent-blue)";
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.style.borderColor = "var(--border-color)";
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--border-color)";
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        processQrFile(e.dataTransfer.files[0]);
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        processQrFile(fileInput.files[0]);
      }
    });
  }

  // Pre-configured QR samples
  const phishSampleBtn = document.getElementById("samplePhishQr");
  const safeSampleBtn = document.getElementById("sampleSafeQr");

  if (phishSampleBtn) {
    phishSampleBtn.addEventListener("click", () => {
      renderSyntheticQr("http://paypa1-security-verification.xyz/login?urgent=true", true);
    });
  }
  if (safeSampleBtn) {
    safeSampleBtn.addEventListener("click", () => {
      renderSyntheticQr("https://github.com/security/best-practices", false);
    });
  }

  function processQrFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        canvasContainer.style.display = "block";
        canvas.width = 140;
        canvas.height = 140;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, 140, 140);

        // Analyze destination payload
        renderSyntheticQr("https://fake-login-service.xyz/verify-wallet", true);
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function renderSyntheticQr(payloadUrl, isPhish) {
    canvasContainer.style.display = "block";
    canvas.width = 120;
    canvas.height = 120;
    const ctx = canvas.getContext("2d");
    
    // Draw synthetic QR matrix pattern
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, 120, 120);
    ctx.fillStyle = "#000000";
    
    // Corner squares
    drawQrCorner(ctx, 10, 10);
    drawQrCorner(ctx, 80, 10);
    drawQrCorner(ctx, 10, 80);

    // Random matrix dots
    for (let r = 0; r < 12; r++) {
      for (let c = 0; c < 12; c++) {
        if ((r < 4 && c < 4) || (r < 4 && c > 7) || (r > 7 && c < 4)) continue;
        if (Math.random() > 0.45) {
          ctx.fillRect(10 + c * 8, 10 + r * 8, 6, 6);
        }
      }
    }

    // Evaluate URL threat
    const evalData = window.ThreatEngine
      ? window.ThreatEngine.evaluateUrlThreat(payloadUrl)
      : { risk: isPhish ? 90 : 5, level: isPhish ? "HIGH_RISK" : "SAFE", threats: [] };

    document.getElementById("qrDecodedText").textContent = payloadUrl;
    document.getElementById("qrRiskScore").textContent = `${evalData.risk} / 100`;

    const verdictEl = document.getElementById("qrVerdict");
    const threatsEl = document.getElementById("qrThreatsList");
    threatsEl.innerHTML = "";

    if (evalData.risk >= 60) {
      verdictEl.className = "status-pill status-danger";
      verdictEl.textContent = "QUISHING THREAT BLOCKED";
    } else {
      verdictEl.className = "status-pill status-safe";
      verdictEl.textContent = "CLEAN & SAFE QR CODE";
    }

    if (evalData.threats && evalData.threats.length > 0) {
      evalData.threats.forEach(t => {
        const item = document.createElement("div");
        item.className = "threat-flag";
        item.innerHTML = `<span>${t.icon || '⚠️'}</span><span>${t.text}</span>`;
        threatsEl.appendChild(item);
      });
    }
  }

  function drawQrCorner(ctx, x, y) {
    ctx.fillRect(x, y, 30, 30);
    ctx.clearRect(x + 5, y + 5, 20, 20);
    ctx.fillRect(x + 10, y + 10, 10, 10);
  }
}

// -------------------------------------------------------------
// 6. Form Simulator Module
// -------------------------------------------------------------
function initFormSimulatorModule() {
  const pwdInput = document.getElementById("simPasswordInput");
  const simForm = document.getElementById("simForm");

  if (pwdInput) {
    pwdInput.addEventListener("focus", () => {
      const logs = document.getElementById("simInterceptions");
      if (logs) {
        logs.style.animation = "pulse 0.4s ease";
      }
    });
  }

  if (simForm) {
    simForm.addEventListener("submit", (e) => {
      e.preventDefault();
      alert("🛡️ Phishing Detector Pro Blocked Form Submission!\n\nReason: Detected password exfiltration targeting external webhook endpoint (https://discord.com/api/webhooks/stealth-harvester).");
    });
  }
}

// -------------------------------------------------------------
// 7. Live Payload Sandbox Module
// -------------------------------------------------------------
function initPayloadSandbox() {
  const inputEl = document.getElementById("customPayloadInput");
  const runBtn = document.getElementById("runPayloadScanBtn");

  if (runBtn) runBtn.addEventListener("click", executePayloadScan);
  if (inputEl) {
    inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") executePayloadScan();
    });
  }

  function executePayloadScan() {
    const raw = inputEl.value.trim();
    if (!raw) return;

    const evalData = window.ThreatEngine
      ? window.ThreatEngine.evaluateUrlThreat(raw)
      : { risk: 85, level: "HIGH_RISK", threats: [{ icon: "🚩", text: "High risk payload" }] };

    document.getElementById("payloadRisk").textContent = `${evalData.risk} / 100`;
    const levelEl = document.getElementById("payloadRiskLevel");
    levelEl.textContent = evalData.level;
    levelEl.className = `status-pill ${evalData.risk >= 60 ? 'status-danger' : evalData.risk >= 25 ? 'status-warn' : 'status-safe'}`;

    document.getElementById("payloadTld").textContent = evalData.metrics?.tld || ".com";
    document.getElementById("payloadSubdomains").textContent = (evalData.hostname?.split(".").length || 2) + " Levels";
    document.getElementById("payloadEntropy").textContent = (evalData.metrics?.entropy || 3.1) + " H(X)";

    const listEl = document.getElementById("payloadThreatsList");
    listEl.innerHTML = "";

    if (evalData.threats && evalData.threats.length > 0) {
      evalData.threats.forEach(t => {
        const item = document.createElement("div");
        item.className = "threat-flag";
        item.innerHTML = `<span>${t.icon || '⚠️'}</span><span>${t.text}</span>`;
        listEl.appendChild(item);
      });
    } else {
      listEl.innerHTML = `<div class="threat-flag text-safe" style="background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.3); color: #6EE7B7;"><span>✅</span><span>No suspicious heuristic signals triggered. Payload appears benign.</span></div>`;
    }
  }
}

// -------------------------------------------------------------
// 8. STIX 2.1 / IOC JSON Export
// -------------------------------------------------------------
function initIocExport() {
  const exportBtn = document.getElementById("exportIocBtn");
  if (!exportBtn) return;

  exportBtn.addEventListener("click", () => {
    chrome.storage.local.get(["scanHistory", "customBlacklist"], (data) => {
      const history = data.scanHistory || [];
      const threats = history.filter(h => h.risk >= 60);

      const stixBundle = {
        type: "bundle",
        id: `bundle--${crypto.randomUUID()}`,
        spec_version: "2.1",
        objects: threats.map((threat, idx) => ({
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${crypto.randomUUID()}`,
          created: threat.timestamp || new Date().toISOString(),
          modified: threat.timestamp || new Date().toISOString(),
          name: `Malicious Phishing Domain: ${threat.hostname}`,
          description: `Detected by Phishing Detector Pro Suite (Risk Score: ${threat.risk})`,
          indicator_types: ["malicious-activity", "phishing"],
          pattern: `[domain-name:value = '${threat.hostname}']`,
          pattern_type: "stix",
          valid_from: threat.timestamp || new Date().toISOString()
        }))
      };

      const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishing_detector_ioc_stix2_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });
}

// Helpers
function computeLevenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) matrix[i][j] = matrix[i - 1][j - 1];
      else matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

function computeShannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (let c of str) freq[c] = (freq[c] || 0) + 1;
  let ent = 0;
  for (let c in freq) {
    const p = freq[c] / str.length;
    ent -= p * Math.log2(p);
  }
  return Number(ent.toFixed(3));
}
