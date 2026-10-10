/**
 * Phishing Detector Pro - Trusted & Blacklist Manager v3.0
 */

document.addEventListener("DOMContentLoaded", () => {
  let currentMode = "WHITELIST"; // "WHITELIST", "BLACKLIST", or "PROTECTED"

  loadLists();
  setupEventListeners();

  function loadLists() {
    chrome.storage.local.get(["trustedSites", "customBlacklist", "customProtectedSites", "vtApiKey"], (res) => {
      const trusted = res.trustedSites || [];
      const blacklist = res.customBlacklist || [];
      const protectedList = res.customProtectedSites || [];

      if (res.vtApiKey && document.getElementById("vtApiKeyInput")) {
        document.getElementById("vtApiKeyInput").value = res.vtApiKey;
      }

      document.getElementById("whitelistCount").textContent = `(${trusted.length})`;
      document.getElementById("blacklistCount").textContent = `(${blacklist.length})`;
      const protCountEl = document.getElementById("protectedCount");
      if (protCountEl) protCountEl.textContent = `(${protectedList.length})`;

      let activeItems = trusted;
      if (currentMode === "BLACKLIST") activeItems = blacklist;
      else if (currentMode === "PROTECTED") activeItems = protectedList;

      renderCurrentList(activeItems);
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
      const icon = currentMode === "WHITELIST" ? "🛡️" : currentMode === "BLACKLIST" ? "🚫" : "👑";
      itemEl.innerHTML = `
        <span class="site-domain">${icon} ${escapeHtml(domain)}</span>
        <button class="btn-remove" data-idx="${idx}">Remove</button>
      `;

      itemEl.querySelector(".btn-remove").addEventListener("click", () => {
        removeDomain(idx);
      });

      listEl.appendChild(itemEl);
    });
  }

  function getStorageKey() {
    if (currentMode === "BLACKLIST") return "customBlacklist";
    if (currentMode === "PROTECTED") return "customProtectedSites";
    return "trustedSites";
  }

  function removeDomain(index) {
    const storageKey = getStorageKey();
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
    const tabProtected = document.getElementById("tabCustomProtected");
    const formTitle = document.getElementById("formTitle");
    const currentListTitle = document.getElementById("currentListTitle");
    const addBtn = document.getElementById("addBtn");

    if (tabWhitelist) {
      tabWhitelist.addEventListener("click", () => {
        currentMode = "WHITELIST";
        tabWhitelist.className = "tab-btn active-whitelist";
        if (tabBlacklist) tabBlacklist.className = "tab-btn";
        if (tabProtected) tabProtected.className = "tab-btn";
        formTitle.textContent = "Add Trusted Domain (Bypasses Threat Warnings)";
        currentListTitle.textContent = "CONFIGURED TRUSTED DOMAINS";
        addBtn.className = "btn btn-add-safe";
        loadLists();
      });
    }

    if (tabBlacklist) {
      tabBlacklist.addEventListener("click", () => {
        currentMode = "BLACKLIST";
        tabBlacklist.className = "tab-btn active-blacklist";
        if (tabWhitelist) tabWhitelist.className = "tab-btn";
        if (tabProtected) tabProtected.className = "tab-btn";
        formTitle.textContent = "Add Blacklisted Domain (Always Blocks & Warns)";
        currentListTitle.textContent = "CONFIGURED BLACKLISTED DOMAINS";
        addBtn.className = "btn btn-add-danger";
        loadLists();
      });
    }

    if (tabProtected) {
      tabProtected.addEventListener("click", () => {
        currentMode = "PROTECTED";
        tabProtected.className = "tab-btn active-whitelist";
        if (tabWhitelist) tabWhitelist.className = "tab-btn";
        if (tabBlacklist) tabBlacklist.className = "tab-btn";
        formTitle.textContent = "Add Protected Monitored Brand/URL (Actively Flags Typosquatting Against This Domain)";
        currentListTitle.textContent = "CONFIGURED MONITORED BRAND URLS";
        addBtn.className = "btn btn-add-safe";
        loadLists();
      });
    }

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

      const storageKey = getStorageKey();

      chrome.storage.local.get([storageKey], (res) => {
        let currentList = res[storageKey] || [];

        if (!currentList.includes(val)) {
          currentList.push(val);
          chrome.storage.local.set({ [storageKey]: currentList }, () => {
            input.value = "";
            loadLists();
          });
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

    // Export Security Rules
    const exportBtn = document.getElementById("exportRulesBtn");
    if (exportBtn) {
      exportBtn.addEventListener("click", () => {
        chrome.storage.local.get(["trustedSites", "customBlacklist"], (res) => {
          const rulesData = {
            version: "3.5",
            exportedAt: new Date().toISOString(),
            trustedSites: res.trustedSites || [],
            customBlacklist: res.customBlacklist || []
          };
          const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(rulesData, null, 2));
          const dl = document.createElement("a");
          dl.setAttribute("href", dataStr);
          dl.setAttribute("download", `phishing_detector_rules_${Date.now()}.json`);
          document.body.appendChild(dl);
          dl.click();
          dl.remove();
        });
      });
    }

    // Import Security Rules
    const importBtn = document.getElementById("importRulesBtn");
    const fileInput = document.getElementById("importFileInput");

    if (importBtn && fileInput) {
      importBtn.addEventListener("click", () => fileInput.click());
      fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
          try {
            const data = JSON.parse(event.target.result);
            chrome.storage.local.get(["trustedSites", "customBlacklist"], (res) => {
              let trusted = new Set([...(res.trustedSites || []), ...(data.trustedSites || [])]);
              let blacklist = new Set([...(res.customBlacklist || []), ...(data.customBlacklist || [])]);

              chrome.storage.local.set({
                trustedSites: Array.from(trusted),
                customBlacklist: Array.from(blacklist)
              }, () => {
                alert(`Successfully imported ${data.trustedSites?.length || 0} trusted domains and ${data.customBlacklist?.length || 0} blacklisted domains!`);
                loadLists();
              });
            });
          } catch (err) {
            alert("Failed to parse JSON rules file. Please ensure it is a valid format.");
          }
        };
        reader.readAsText(file);
      });
    }
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
});