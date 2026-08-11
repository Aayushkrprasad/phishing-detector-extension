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
      window.location.href = blockedUrl;
    }
  });
});