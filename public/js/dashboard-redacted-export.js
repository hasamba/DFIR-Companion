// Redacted case export (#54) — the same case with names, hosts and accounts masked (#415 tier 3).
//
// Same shape as the encrypted archive export beside it: IIFE-wrapped, nothing runs at load, and its
// three controls were bound in the page's shared modal-wiring block with two of them passing a
// function as a value.
(function () {
  // ── Redacted case export (#54) ────────────────────────────────────────────
  function openRedactedExport() {
    document.getElementById("reMsg").textContent = "";
    document.getElementById("redactedExportOverlay").classList.add("open");
  }
  function closeRedactedExport() {
    document.getElementById("redactedExportOverlay").classList.remove("open");
  }
  async function doRedactedExport() {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("reMsg");
    if (!caseId) {
      msg.textContent = "no case loaded";
      return;
    }
    const ck = (id) => (document.getElementById(id).checked ? "1" : "0");
    const q = new URLSearchParams({
      report: ck("reIncludeReport"),
      csvs: ck("reIncludeCsvs"),
      state: ck("reIncludeState"),
      screenshots: ck("reIncludeScreens"),
      blur: ck("reBlur"),
    }).toString();
    const btn = document.getElementById("reDownload");
    btn.disabled = true;
    msg.textContent = "building… (OCR may take a while for many screenshots)";
    try {
      // Fetch the whole archive (so errors surface as JSON), then save it via an object URL.
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/export/redacted?${q}`,
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || "HTTP " + res.status);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case-${caseId}-redacted.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      closeRedactedExport();
      document.getElementById("status").textContent =
        "redacted package downloaded";
    } catch (err) {
      msg.textContent = "export failed: " + err.message;
    } finally {
      btn.disabled = false;
    }
  }

  // Report versions: diff & rollback (#77) moved to js/dashboard-report-versions.js (#415 tier
  // 3). Its controls are bound by initReportVersions(), called from the shared modal-wiring
  // block below, which is also where a missing file is reported.
  // Reproducible analysis runs (#377) moved to js/dashboard-analysis-runs.js (#415 tier 3).
  // Its controls are bound by initAnalysisRuns(), called from the shared modal-wiring block
  // below, which is also where a missing file is reported.

  // The three controls the shared modal-wiring block used to bind.
  function initRedactedExport() {
    document.getElementById("reDownload").onclick = doRedactedExport;
    document.getElementById("reCancel").onclick = closeRedactedExport;
    document
      .getElementById("redactedExportOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "redactedExportOverlay") closeRedactedExport();
      });
  }

  window.openRedactedExport = openRedactedExport;
  window.closeRedactedExport = closeRedactedExport;
  window.doRedactedExport = doRedactedExport;
  window.initRedactedExport = initRedactedExport;
})();
