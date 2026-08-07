// Unified export menu — one button offering every export the case supports (#415 tier 3).
//
// WIRING ONLY: no declarations, no state, nothing outside calling in — one statement seventy-four
// lines long. So the module publishes only its initializer, and the initializer is the module.
(function () {
  // The statements the inline block ran at module scope, in their original order.
  function initUnifiedExport() {
    // ── Unified export menu ───────────────────────────────────────────────────
    document.getElementById("exportSelect").onchange = (e) => {
      const sel = e.target;
      const action = sel.value;
      sel.value = ""; // reset to the "Export…" placeholder
      const caseId = document.getElementById("caseId").value.trim();
      if (!action || !caseId) return;
      const c = encodeURIComponent(caseId);
      if (action === "report") {
        document.getElementById("status").textContent = "generating report…";
        document.getElementById("reportLinks").innerHTML = "";
        fetch(`/cases/${c}/report`, { method: "POST" })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            document.getElementById("status").textContent = "report written";
            document.getElementById("reportLinks").innerHTML =
              `<a href="/cases/${c}/report/report.html" target="_blank" rel="noopener">Open HTML</a>` +
              ` · <a href="/cases/${c}/report/report.html?download=1">Download HTML</a>` +
              ` · <a href="/cases/${c}/report/report.html?print=1" target="_blank" rel="noopener">Print / Save as PDF</a>` +
              ` · <a href="/cases/${c}/report/report.md?download=1">Download Markdown</a>`;
          })
          .catch(
            (err) =>
              (document.getElementById("status").textContent =
                "report failed: " + err.message),
          );
      } else if (action === "report-pdf") {
        // PDF = generate the report, then open the print-styled HTML which auto-triggers the
        // browser print dialog ("Save as PDF"). Open the tab synchronously (within this click
        // gesture) so it isn't pop-up-blocked, then point it at the print view once generated.
        const printUrl = `/cases/${c}/report/report.html?print=1`;
        const win = window.open("about:blank", "_blank");
        document.getElementById("status").textContent = "generating report…";
        document.getElementById("reportLinks").innerHTML = "";
        fetch(`/cases/${c}/report`, { method: "POST" })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            document.getElementById("status").textContent =
              "report written — opening print dialog";
            if (win && !win.closed) win.location.href = printUrl;
            else window.open(printUrl, "_blank", "noopener");
            document.getElementById("reportLinks").innerHTML =
              `<a href="${printUrl}" target="_blank" rel="noopener">Print / Save as PDF</a>` +
              ` · <a href="/cases/${c}/report/report.html" target="_blank" rel="noopener">Open HTML</a>` +
              ` · <a href="/cases/${c}/report/report.md?download=1">Download Markdown</a>`;
          })
          .catch((err) => {
            if (win && !win.closed) win.close();
            document.getElementById("status").textContent =
              "report failed: " + err.message;
          });
      } else if (action === "report-docx") {
        // On-demand .docx — the server generates the binary fresh per request. No POST
        // /cases/:id/report dance, no on-disk file. Trigger the download directly.
        window.location.href = `/cases/${c}/report.docx`;
      } else if (action === "present-html") {
        // Standalone, self-contained presentation deck (#177) — opens/downloads an offline HTML slide deck.
        window.location.href = `/cases/${c}/present/export`;
      } else if (action === "timeline-csv") {
        window.location.href = `/cases/${c}/incident-timeline.csv`;
      } else if (action === "attack-layer") {
        // On-demand ATT&CK Navigator layer (JSON) — import at mitre-attack.github.io/attack-navigator.
        window.location.href = `/cases/${c}/attack-layer.json`;
      } else if (action === "timesketch-jsonl") {
        window.location.href = `/cases/${c}/timeline.jsonl`;
      } else if (action === "timesketch-jsonl-super") {
        window.location.href = `/cases/${c}/super-timeline.jsonl`;
      } else if (action === "stix") {
        // On-demand STIX 2.1 bundle (JSON) — import into any TIP (OpenCTI, MISP, Anomali…).
        window.location.href = `/cases/${c}/export/stix`;
      } else if (action === "ioc-blocklist") {
        openIocBlocklist();
      } else if (action === "redacted") {
        openRedactedExport();
      } else if (action === "save-template") {
        openSaveTemplate();
      } else if (action === "report-versions") {
        openReportVersions();
      } else if (action === "analysis-runs") {
        openAnalysisRuns();
      }
    };
  }

  window.initUnifiedExport = initUnifiedExport;
})();
