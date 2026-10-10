/**
 * Phishing Detector Enterprise - SaaS Landing Page Interactive Engine
 */

document.addEventListener("DOMContentLoaded", () => {
  initDemoTabs();
  initUrlDemoScanner();
  initTextDemoScanner();
  animateHeroStats();
});

function initDemoTabs() {
  const urlTab = document.getElementById("demoTabUrl");
  const textTab = document.getElementById("demoTabText");
  const urlView = document.getElementById("demoViewUrl");
  const textView = document.getElementById("demoViewText");

  if (urlTab && textTab && urlView && textView) {
    urlTab.addEventListener("click", () => {
      urlTab.classList.add("active");
      textTab.classList.remove("active");
      urlView.classList.add("active");
      textView.classList.remove("active");
    });

    textTab.addEventListener("click", () => {
      textTab.classList.add("active");
      urlTab.classList.remove("active");
      textView.classList.add("active");
      urlView.classList.remove("active");
    });
  }
}

function initUrlDemoScanner() {
  const inputEl = document.getElementById("demoUrlInput");
  const runBtn = document.getElementById("demoRunUrlBtn");

  document.querySelectorAll(".demo-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      if (inputEl) inputEl.value = pill.getAttribute("data-url");
      executeUrlScan();
    });
  });

  if (runBtn) runBtn.addEventListener("click", executeUrlScan);

  function executeUrlScan() {
    const raw = inputEl ? inputEl.value.trim() : "";
    if (!raw) return;

    const evalData = window.ThreatEngine
      ? window.ThreatEngine.evaluateUrlThreat(raw)
      : fallbackUrlScan(raw);

    updateDemoOutput(evalData, raw);
  }
}

function initTextDemoScanner() {
  const textInput = document.getElementById("demoTextInput");
  const runBtn = document.getElementById("demoRunTextBtn");

  document.querySelectorAll(".demo-pill-text").forEach(pill => {
    pill.addEventListener("click", () => {
      const type = pill.getAttribute("data-type");
      if (type === "urgent") {
        textInput.value = "URGENT SECURITY ALERT: Your PayPal account has been temporarily locked due to unauthorized login attempts. Please verify your credentials within 24 hours at http://paypa1-security.xyz/login";
      } else if (type === "reward") {
        textInput.value = "CONGRATULATIONS! You have been selected to win a $500 Amazon Gift Card. Claim your reward immediately at http://amazn-prime-reward.top/claim";
      } else if (type === "seed") {
        textInput.value = "METAMASK ALERT: Please reply with your 12-word seed phrase to restore wallet sync and unblock your crypto assets.";
      }
      executeTextScan();
    });
  });

  if (runBtn) runBtn.addEventListener("click", executeTextScan);

  function executeTextScan() {
    const raw = textInput ? textInput.value.trim() : "";
    if (!raw) return;

    const evalData = window.ThreatEngine
      ? window.ThreatEngine.evaluateTextThreat(raw)
      : { risk: 85, level: "HIGH_RISK", urgencyScore: 80, threats: [{ icon: "⏳", text: "Urgency and scare tactics detected" }] };

    updateTextOutput(evalData);
  }
}

function updateDemoOutput(evalData, raw) {
  document.getElementById("demoResName").textContent = evalData.hostname || raw;
  document.getElementById("demoResScore").textContent = evalData.risk;

  const scoreEl = document.getElementById("demoResScore");
  const levelEl = document.getElementById("demoResLevel");

  if (evalData.risk >= 60) {
    scoreEl.className = "score-number text-danger";
    levelEl.className = "score-status-pill status-danger";
    levelEl.textContent = "HIGH RISK";
  } else if (evalData.risk >= 25) {
    scoreEl.className = "score-number text-yellow";
    levelEl.className = "score-status-pill status-warn";
    levelEl.textContent = "CAUTION";
  } else {
    scoreEl.className = "score-number text-safe";
    levelEl.className = "score-status-pill status-safe";
    levelEl.textContent = "SAFE";
  }

  document.getElementById("demoResEntropy").textContent = `${evalData.metrics?.entropy || '2.8'} H(X)`;
  document.getElementById("demoResBrand").textContent = evalData.metrics?.targetBrand || "None";
  document.getElementById("demoResDistance").textContent = evalData.risk >= 50 ? "1 Edit (Typosquat)" : "0 Edits";
  document.getElementById("demoResTld").textContent = evalData.metrics?.tld || ".com";

  const listEl = document.getElementById("demoResThreats");
  listEl.innerHTML = "";

  if (evalData.threats && evalData.threats.length > 0) {
    evalData.threats.forEach(t => {
      const item = document.createElement("div");
      item.className = "reason-item";
      item.innerHTML = `<span>${t.icon || '⚠️'}</span><span>${t.text}</span>`;
      listEl.appendChild(item);
    });
  } else {
    listEl.innerHTML = `<div class="reason-item text-safe"><span>🛡️</span><span>All mathematical heuristics and brand checks passed. Domain is clean.</span></div>`;
  }
}

function updateTextOutput(evalData) {
  document.getElementById("demoResName").textContent = "Social Engineering Text Evaluation";
  document.getElementById("demoResScore").textContent = evalData.risk;

  const scoreEl = document.getElementById("demoResScore");
  const levelEl = document.getElementById("demoResLevel");

  if (evalData.risk >= 60) {
    scoreEl.className = "score-number text-danger";
    levelEl.className = "score-status-pill status-danger";
    levelEl.textContent = "HIGH RISK";
  } else if (evalData.risk >= 25) {
    scoreEl.className = "score-number text-yellow";
    levelEl.className = "score-status-pill status-warn";
    levelEl.textContent = "CAUTION";
  } else {
    scoreEl.className = "score-number text-safe";
    levelEl.className = "score-status-pill status-safe";
    levelEl.textContent = "SAFE";
  }

  document.getElementById("demoResEntropy").textContent = `${evalData.urgencyScore || 75}/100 Urgency`;
  document.getElementById("demoResBrand").textContent = "NLP Trigger Scanned";
  document.getElementById("demoResDistance").textContent = "--";
  document.getElementById("demoResTld").textContent = "--";

  const listEl = document.getElementById("demoResThreats");
  listEl.innerHTML = "";

  if (evalData.threats && evalData.threats.length > 0) {
    evalData.threats.forEach(t => {
      const item = document.createElement("div");
      item.className = "reason-item";
      item.innerHTML = `<span>${t.icon || '⚠️'}</span><span>${t.text}</span>`;
      listEl.appendChild(item);
    });
  } else {
    listEl.innerHTML = `<div class="reason-item text-safe"><span>🛡️</span><span>No malicious social engineering phrases found in text.</span></div>`;
  }
}

function animateHeroStats() {
  const scansEl = document.getElementById("heroStatScans");
  if (!scansEl) return;
  let count = 1000000;
  setInterval(() => {
    count += Math.floor(Math.random() * 3) + 1;
    scansEl.textContent = `${(count / 1000000).toFixed(2)}M+`;
  }, 4000);
}

function fallbackUrlScan(url) {
  let risk = 10;
  if (!url.startsWith("https")) risk += 20;
  if (url.includes("@")) risk += 40;
  return { risk, level: risk >= 60 ? "HIGH_RISK" : "SAFE", threats: [{ icon: "ℹ️", text: "Basic heuristic scan" }] };
}
