document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get("url");

  const siteInfo = document.getElementById("siteInfo");
  if (blockedUrl) {
    siteInfo.textContent = blockedUrl;
  } else {
    siteInfo.textContent = "Unknown URL Target";
  }

  document.getElementById("backBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  document.getElementById("continueBtn").addEventListener("click", () => {
    if (blockedUrl) {
      try {
        const host = new URL(blockedUrl).hostname.toLowerCase();
        chrome.storage.local.get(["trustedSites"], (res) => {
          const trusted = res.trustedSites || [];
          if (!trusted.includes(host)) {
            trusted.push(host);
            chrome.storage.local.set({ trustedSites: trusted }, () => {
              window.location.href = blockedUrl;
            });
          } else {
            window.location.href = blockedUrl;
          }
        });
      } catch (e) {
        window.location.href = blockedUrl;
      }
    }
  });
});