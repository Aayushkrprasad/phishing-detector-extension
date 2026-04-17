let params = new URLSearchParams(window.location.search);
let blockedUrl = params.get("url");

document.getElementById("siteInfo").innerText = blockedUrl
  ? "Blocked Site: " + blockedUrl
  : "Blocked Site not found";

document.getElementById("backBtn").addEventListener("click", () => {
  history.back();
});

document.getElementById("continueBtn").addEventListener("click", () => {
  if (blockedUrl) {
    window.location.href = blockedUrl;
  }
});