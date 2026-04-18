chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
  chrome.scripting.executeScript(
    {
      target: { tabId: tabs[0].id },
      func: () => {
        let risk = 0;
        let reasons = [];
        let url = window.location.href.toLowerCase();
        let host = window.location.hostname.toLowerCase();

        if (url.includes("@")) {
          risk += 30;
          reasons.push("@ symbol found in URL");
        }

        if (!url.startsWith("https")) {
          risk += 20;
          reasons.push("Website is not using HTTPS");
        }

        if (document.querySelectorAll("input[type='password']").length > 0) {
          risk += 30;
          reasons.push("Password field found");
        }

        if (url.length > 75) {
          risk += 10;
          reasons.push("URL is too long");
        }

        if (
          url.includes("login") ||
          url.includes("verify") ||
          url.includes("bank") ||
          url.includes("update")
        ) {
          risk += 15;
          reasons.push("Suspicious keyword found in URL");
        }

        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
          risk += 25;
          reasons.push("IP address used instead of domain name");
        }

        let dotCount = (host.match(/\./g) || []).length;
        if (dotCount > 2) {
          risk += 15;
          reasons.push("Too many dots in domain");
        }

        let forms = document.querySelectorAll("form");
        forms.forEach((form) => {
          let action = form.getAttribute("action");
          if (action) {
            try {
              let actionUrl = new URL(action, window.location.href);
              if (actionUrl.hostname && actionUrl.hostname !== window.location.hostname) {
                risk += 25;
                reasons.push("Form submits to different domain");
              }
            } catch (e) {}
          }
        });

        let iframes = document.querySelectorAll("iframe");
        iframes.forEach((iframe) => {
          let style = window.getComputedStyle(iframe);
          if (
            style.display === "none" ||
            style.visibility === "hidden" ||
            iframe.width == 0 ||
            iframe.height == 0
          ) {
            risk += 20;
            reasons.push("Hidden iframe found");
          }
        });

        let scripts = document.querySelectorAll("script[src]");
        let externalCount = 0;
        scripts.forEach((script) => {
          try {
            let scriptUrl = new URL(script.src, window.location.href);
            if (scriptUrl.hostname !== window.location.hostname) {
              externalCount++;
            }
          } catch (e) {}
        });

        if (externalCount > 5) {
          risk += 15;
          reasons.push("Too many external scripts");
        }

        let text = document.body.innerText.toLowerCase();
        let suspiciousWords = [
          "verify your account",
          "update your password",
          "security alert",
          "urgent action",
          "bank account",
          "confirm identity"
        ];

        suspiciousWords.forEach((word) => {
          if (text.includes(word)) {
            risk += 10;
            reasons.push("Suspicious page text found");
          }
        });

        return { risk, reasons, currentUrl: window.location.href };
      }
    },
    (res) => {
      let box = document.getElementById("result");

      if (chrome.runtime.lastError) {
        box.innerText = "Error";
        return;
      }

      let data = res[0].result;
      let level = "Safe";
      let className = "safe";

      if (data.risk >= 60) {
        level = "High Risk";
        className = "danger";
      } else if (data.risk >= 30) {
        level = "Suspicious";
        className = "suspicious";
      }

      let text = "Risk Score: " + data.risk + "\n";
      text += "Level: " + level + "\n\n";

      if (data.reasons.length > 0) {
        text += "Reasons:\n- " + data.reasons.join("\n- ");
      } else {
        text += "Reasons:\n- No major risk found";
      }

      box.className = className;
      box.innerText = text;

      let historyItem = {
        url: data.currentUrl,
        risk: data.risk,
        level: level,
        time: new Date().toLocaleString()
      };

      chrome.storage.local.get(["history"], function(result) {
        let history = result.history || [];
        history.unshift(historyItem);
        chrome.storage.local.set({ history: history });
      });
    }
  );
});

document.getElementById("viewHistory").addEventListener("click", function() {
  chrome.tabs.create({
    url: chrome.runtime.getURL("history.html")
  });
});