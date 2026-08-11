/**
 * Phishing Detector Pro - Security Analytics & History Controller v3.0
 */

document.addEventListener("DOMContentLoaded", () => {
  let allScans = [];
  let currentFilter = "ALL";
  let searchKeyword = "";

  loadScanHistory();
  setupEventListeners();

  function loadScanHistory() {
    chrome.storage.local.get(["scanHistory"], (res) => {
      allScans = res.scanHistory || [];
      updateKPIsAndDistribution();
      renderTable();
    });
  }

  function updateKPIsAndDistribution() {
    const total = allScans.length;
    const highRiskCount = allScans.filter(s => s.risk >= 60).length;
    const suspiciousCount = allScans.filter(s => s.risk >= 25 && s.risk < 60).length;
    const safeCount = allScans.filter(s => s.risk < 25).length;

    // Update KPI Numbers
    document.getElementById("statTotal").textContent = total;
    document.getElementById("statHighRisk").textContent = highRiskCount;
    document.getElementById("statSuspicious").textContent = suspiciousCount;

    const safeRate = total > 0 ? Math.round((safeCount / total) * 100) : 100;
    document.getElementById("statSafeRate").textContent = `${safeRate}%`;

    // Filter pill count badges
    document.getElementById("countAll").textContent = total;
    document.getElementById("countDanger").textContent = highRiskCount;
    document.getElementById("countWarn").textContent = suspiciousCount;
    document.getElementById("countSafe").textContent = safeCount;

    // Update Distribution Bar
    document.getElementById("distTotalLabel").textContent = `${total} Analyzed Domains`;
    document.getElementById("legendSafe").textContent = safeCount;
    document.getElementById("legendWarn").textContent = suspiciousCount;
    document.getElementById("legendDanger").textContent = highRiskCount;

    if (total > 0) {
      const safePct = (safeCount / total) * 100;
      const warnPct = (suspiciousCount / total) * 100;
      const dangerPct = (highRiskCount / total) * 100;

      document.getElementById("distSegSafe").style.width = `${safePct}%`;
      document.getElementById("distSegWarn").style.width = `${warnPct}%`;
      document.getElementById("distSegDanger").style.width = `${dangerPct}%`;
    } else {
      document.getElementById("distSegSafe").style.width = "100%";
      document.getElementById("distSegWarn").style.width = "0%";
      document.getElementById("distSegDanger").style.width = "0%";
    }
  }

  function renderTable() {
    const tbody = document.getElementById("historyTableBody");
    const emptyState = document.getElementById("emptyState");
    tbody.innerHTML = "";

    let filtered = allScans.filter((item) => {
      // Filter by level
      if (currentFilter === "HIGH_RISK" && item.risk < 60) return false;
      if (currentFilter === "SUSPICIOUS" && (item.risk < 25 || item.risk >= 60)) return false;
      if (currentFilter === "SAFE" && item.risk >= 25) return false;

      // Filter by search
      if (searchKeyword) {
        const query = searchKeyword.toLowerCase();
        const hostMatch = (item.hostname || "").toLowerCase().includes(query);
        const urlMatch = (item.url || "").toLowerCase().includes(query);
        return hostMatch || urlMatch;
      }
      return true;
    });

    if (filtered.length === 0) {
      emptyState.style.display = "block";
      return;
    }
    emptyState.style.display = "none";

    filtered.forEach((scan, index) => {
      const tr = document.createElement("tr");

      let badgeClass = "badge-safe";
      let badgeLabel = "Safe";
      if (scan.risk >= 60) {
        badgeClass = "badge-danger";
        badgeLabel = "High Threat";
      } else if (scan.risk >= 25) {
        badgeClass = "badge-warn";
        badgeLabel = "Suspicious";
      }

      const primaryFlag = scan.threats && scan.threats.length > 0
        ? scan.threats[0].text
        : "Standard Domain Heuristics";

      const formattedTime = scan.timestamp ? new Date(scan.timestamp).toLocaleString() : "Just now";

      tr.innerHTML = `
        <td>
          <div class="host-cell">
            <span class="host-text">${scan.hostname || "Unknown Host"}</span>
            <span class="url-subtext">${scan.url || ""}</span>
          </div>
        </td>
        <td><strong style="font-size: 14px;">${scan.risk}/100</strong></td>
        <td><span class="badge ${badgeClass}">${badgeLabel}</span></td>
        <td><span class="threat-tag">${primaryFlag}</span></td>
        <td class="time-cell">${formattedTime}</td>
      `;

      tr.addEventListener("click", () => openDetailModal(scan));
      tbody.appendChild(tr);
    });
  }

  function openDetailModal(scan) {
    const modal = document.getElementById("detailModal");
    const modalHost = document.getElementById("modalHost");
    const modalBody = document.getElementById("modalBody");

    modalHost.textContent = scan.hostname || "Domain Details";
    modalBody.innerHTML = `
      <div style="font-size: 13px; color: var(--text-muted); word-break: break-all;"><strong>URL:</strong> ${scan.url || ""}</div>
      <div style="display: flex; gap: 12px; margin-top: 6px;">
        <div><strong>Risk Score:</strong> ${scan.risk}/100</div>
        <div><strong>Classification:</strong> ${scan.level || "SAFE"}</div>
      </div>
      <div style="margin-top: 10px;">
        <strong>Detection Telemetry & Reasons:</strong>
        <ul style="margin-top: 6px; padding-left: 18px; font-size: 12px; color: #cbd5e1; display: flex; flex-direction: column; gap: 4px;">
          ${(scan.threats || []).map(t => `<li>${t.icon || "⚠️"} ${t.text}</li>`).join("") || "<li>No abnormal flags detected.</li>"}
        </ul>
      </div>
      <div style="margin-top: 12px; font-size: 11px; color: var(--text-muted);">
        <strong>Scanned At:</strong> ${scan.timestamp ? new Date(scan.timestamp).toUTCString() : "N/A"}
      </div>
    `;

    modal.classList.add("show");
  }

  function setupEventListeners() {
    // Search Filter
    document.getElementById("searchInput").addEventListener("input", (e) => {
      searchKeyword = e.target.value.trim();
      renderTable();
    });

    // Pill Filters
    document.querySelectorAll(".filter-pill").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        document.querySelectorAll(".filter-pill").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        currentFilter = btn.getAttribute("data-filter");
        renderTable();
      });
    });

    // Export to CSV
    document.getElementById("exportCsvBtn").addEventListener("click", () => {
      if (allScans.length === 0) {
        alert("No scan data to export.");
        return;
      }

      const headers = ["Timestamp", "Hostname", "URL", "Risk Score", "Level", "Primary Reason"];
      const rows = allScans.map(s => [
        `"${s.timestamp || ""}"`,
        `"${s.hostname || ""}"`,
        `"${(s.url || "").replace(/"/g, '""')}"`,
        s.risk,
        `"${s.level || ""}"`,
        `"${((s.threats && s.threats[0]) ? s.threats[0].text : "Clean").replace(/"/g, '""')}"`
      ]);

      const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", `phishing_detector_report_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    });

    // Export to JSON
    document.getElementById("exportJsonBtn").addEventListener("click", () => {
      if (allScans.length === 0) {
        alert("No scan data to export.");
        return;
      }

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allScans, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `phishing_detector_audit_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });

    // Clear Logs
    document.getElementById("clearHistoryBtn").addEventListener("click", () => {
      if (confirm("Are you sure you want to clear all forensic scan history logs?")) {
        chrome.storage.local.set({ scanHistory: [] }, () => {
          allScans = [];
          updateKPIsAndDistribution();
          renderTable();
        });
      }
    });

    // Modal Close
    document.getElementById("modalCloseBtn").addEventListener("click", () => {
      document.getElementById("detailModal").classList.remove("show");
    });

    document.getElementById("detailModal").addEventListener("click", (e) => {
      if (e.target === document.getElementById("detailModal")) {
        document.getElementById("detailModal").classList.remove("show");
      }
    });
  }
});