/**
 * Phishing Detector Pro - Trusted & Blacklist Manager v3.0
 */

document.addEventListener("DOMContentLoaded", () => {
  let currentMode = "WHITELIST"; // or "BLACKLIST"

  loadLists();
  setupEventListeners();

  function loadLists() {
    chrome.storage.local.get(["trustedSites", "customBlacklist", "vtApiKey"], (res) => {
      const trusted = res.trustedSites || [];
      const blacklist = res.customBlacklist || [];
      if (res.vtApiKey && document.getElementById("vtApiKeyInput")) {
        document.getElementById("vtApiKeyInput").value = res.vtApiKey;
      }

      document.getElementById("whitelistCount").textContent = `(${trusted.length})`;
      document.getElementById("blacklistCount").textContent = `(${blacklist.length})`;

      renderCurrentList(currentMode === "WHITELIST" ? trusted : blacklist);
    });
  }

  function renderCurrentList(items) {
    const listEl = document.getElementById("siteList");
    listEl.innerHTML = "";

    if (items.length === 0) {
      listEl.innerHTML = `
        <div class="empty-box">
          No domains in this list yet. Add entries above to configure custom rules.
        </div>
      `;
      return;
    }

    items.forEach((domain, idx) => {
      const itemEl = document.createElement("div");
      itemEl.className = "site-item";
      itemEl.innerHTML = `
        <span class="site-domain">${currentMode === "WHITELIST" ? "🛡️" : "🚫"} ${escapeHtml(domain)}</span>
        <button class="btn-remove" data-idx="${idx}">Remove</button>
      `;

      itemEl.querySelector(".btn-remove").addEventListener("click", () => {
        removeDomain(idx);
      });

      listEl.appendChild(itemEl);
    });
  }

  function removeDomain(index) {
    const storageKey = currentMode === "WHITELIST" ? "trustedSites" : "customBlacklist";
    chrome.storage.local.get([storageKey], (res) => {
      let list = res[storageKey] || [];
      list.splice(index, 1);
      chrome.storage.local.set({ [storageKey]: list }, () => {
        loadLists();
      });
    });
  }

  function setupEventListeners() {
    const tabWhitelist = document.getElementById("tabWhitelist");
    const tabBlacklist = document.getElementById("tabBlacklist");
    const formTitle = document.getElementById("formTitle");
    const currentListTitle = document.getElementById("currentListTitle");
    const addBtn = document.getElementById("addBtn");

    tabWhitelist.addEventListener("click", () => {
      currentMode = "WHITELIST";
      tabWhitelist.className = "tab-btn active-whitelist";
      tabBlacklist.className = "tab-btn";
      formTitle.textContent = "Add Trusted Domain (Bypasses Threat Warnings)";
      currentListTitle.textContent = "CONFIGURED TRUSTED DOMAINS";
      addBtn.className = "btn btn-add-safe";
      loadLists();
    });

    tabBlacklist.addEventListener("click", () => {
      currentMode = "BLACKLIST";
      tabBlacklist.className = "tab-btn active-blacklist";
      tabWhitelist.className = "tab-btn";
      formTitle.textContent = "Add Blacklisted Domain (Always Blocks & Warns)";
      currentListTitle.textContent = "CONFIGURED BLACKLISTED DOMAINS";
      addBtn.className = "btn btn-add-danger";
      loadLists();
    });

    // Add Domain Form
    document.getElementById("addDomainForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("domainInput");
      let val = input.value.trim().toLowerCase();

      try {
        if (val.startsWith("http://") || val.startsWith("https://")) {
          val = new URL(val).hostname;
        }
      } catch (err) {}

      val = val.replace(/^www\./, "");
      if (!val) return;

      const storageKey = currentMode === "WHITELIST" ? "trustedSites" : "customBlacklist";
      const oppositeKey = currentMode === "WHITELIST" ? "customBlacklist" : "trustedSites";

      chrome.storage.local.get([storageKey, oppositeKey], (res) => {
        let currentList = res[storageKey] || [];
        let oppositeList = res[oppositeKey] || [];

        // Remove from opposite list if exists
        oppositeList = oppositeList.filter(d => d !== val);

        if (!currentList.includes(val)) {
          currentList.push(val);
          chrome.storage.local.set({ [storageKey]: currentList, [oppositeKey]: oppositeList }, () => {
            input.value = "";
            loadLists();
          });
        } else {
          alert(`Domain '${val}' is already in this list.`);
        }
      });
    });

    // Clear List
    document.getElementById("clearCurrentList").addEventListener("click", () => {
      const storageKey = currentMode === "WHITELIST" ? "trustedSites" : "customBlacklist";
      if (confirm(`Are you sure you want to clear the entire ${currentMode} list?`)) {
        chrome.storage.local.set({ [storageKey]: [] }, () => {
          loadLists();
        });
      }
    });

    // Save VirusTotal API Key
    const apiKeyForm = document.getElementById("apiKeyForm");
    if (apiKeyForm) {
      apiKeyForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const key = document.getElementById("vtApiKeyInput").value.trim();
        chrome.storage.local.set({ vtApiKey: key }, () => {
          alert(key ? "VirusTotal API Key saved successfully." : "VirusTotal API Key cleared.");
        });
      });
    }
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
});