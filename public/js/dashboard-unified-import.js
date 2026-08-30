// Unified import — one button that takes any evidence file and lets the server work out what it is
// (#415 tier 3).
//
// LIKE THE ASSET OVERRIDES MODULE, THIS IS ONLY AN INITIALIZER: no declarations, no state, two
// statements of listener wiring that happen to be 149 lines long. Nothing outside calls into it.
//
// In a <head> script both would run before the import controls exist and bind nothing, which for
// this feature means the primary import button does nothing and says nothing.
(function () {
  function initUnifiedImport() {
    // ── Unified import: one button, the server auto-detects the file type ─────
    // Images go through the same /captures path the extension uses; every other file is
    // POSTed to /import, where the server sniffs it (JSON/CSV/log + per-format signatures)
    // and routes it to the right importer. Multiple files can be selected at once.
    document.getElementById("importBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) {
        document.getElementById("status").textContent =
          "enter/connect a Case ID first";
        return;
      }
      const permissionError = importPermissionMessage(caseId);
      if (permissionError) {
        document.getElementById("status").textContent = permissionError;
        return;
      }
      document.getElementById("importFile").click();
    };
    document.getElementById("importFile").onchange = async (e) => {
      const caseId = document.getElementById("caseId").value.trim();
      const files = Array.from(e.target.files || []);
      if (!caseId || !files.length) return;
      const statusEl = document.getElementById("status");
      const permissionError = importPermissionMessage(caseId);
      if (permissionError) {
        cancelImportProgress();
        statusEl.textContent = permissionError;
        e.target.value = "";
        return;
      }
      const isImage = (f) =>
        /^image\//.test(f.type) || /\.(png|jpe?g|webp)$/i.test(f.name);
      // Raw evidence an external tool handles (built-in EVTX/PCAP + any extension a CUSTOM tool claims)
      // can't be read as text. The set of "raw" extensions comes from /tools/status so custom tools work
      // too. Ask the analyst (one banner for the batch) whether to run a tool; never send raw through the
      // text import path. #211
      const rawExtSet = await fetchRawToolExts();
      const isRawTool = (f) =>
        rawExtSet.has(uploadExtOf(f.name));
      const images = files.filter(isImage);
      const rawTool = files.filter((f) => !isImage(f) && isRawTool(f));
      const data = files.filter((f) => !isImage(f) && !isRawTool(f));
      if (rawTool.length) askRunToolsOnImport(caseId, rawTool);
      if (!data.length && !images.length) {
        e.target.value = "";
        return;
      }

      // Minimum severity to import — restored across all import types. Asked once for the
      // whole batch (data files only; screenshots have no severity). Imports that don't grade
      // severity (e.g. KAPE, Plaso, plain telemetry) are kept in full regardless of this floor;
      // "info" (or Cancel-then-keep) imports everything. The server normalizes the value.
      // A remembered choice (askMinSeverity → IMPORT_SEV_KEY) skips the dialog entirely.
      let minSeverity = "";
      if (data.length) {
        const ans = await askMinSeverity();
        if (ans === null) {
          e.target.value = "";
          return;
        } // cancelled the whole import
        minSeverity = ans;
      }

      // Data files → the unified /import endpoint (server auto-detects + routes).
      // Files over 200 MB would OOM the browser tab if read via FileReader, so for those
      // we prompt for the full local path and let the server read the file directly instead.
      const LARGE_FILE_MB = 200;
      const kinds = {};
      let dataFail = 0,
        aiOffSkipped = 0;
      if (data.length) showImportProgressIndeterminate();
      for (let i = 0; i < data.length; i++) {
        const f = data[i];
        statusEl.textContent = `importing ${i + 1}/${data.length}: ${f.name}…`;
        try {
          let r;
          if (f.size > LARGE_FILE_MB * 1024 * 1024) {
            const filePath = prompt(
              `"${f.name}" is ${Math.round(f.size / 1024 / 1024)} MB — too large to load in the browser.\n\n` +
                `Enter the full path to this file on your machine so the server reads it directly\n` +
                `(e.g. C:\\Users\\you\\Downloads\\${f.name}):`,
              f.name,
            );
            if (!filePath) {
              dataFail++;
              continue;
            }
            // Large file: server reads from disk — bar stays indeterminate until WebSocket N/M updates arrive.
            r = await fetch(`/cases/${caseId}/import-file`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ path: filePath, minSeverity }),
            });
          } else {
            // Small file: read in browser with progress (0→40%), then upload (bar holds at 40% until server N/M).
            const text = await readFileTextWithProgress(f);
            showImportProgress(40);
            r = await fetch(`/cases/${caseId}/import`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ filename: f.name, text, minSeverity }),
            });
          }
          const jr = await r.json().catch(() => ({}));
          if (r.status === 403) {
            cancelImportProgress();
            statusEl.textContent =
              importPermissionMessage(caseId) ||
              jr.error ||
              "Your current role does not permit importing evidence. Ask a case administrator for the investigator or administrator role.";
            e.target.value = "";
            return;
          }
          if (r.status === 423) {
            hideImportProgress();
            statusEl.textContent =
              jr.error || "Case is closed — reopen it to import evidence";
            e.target.value = "";
            return;
          }
          // The case doesn't exist (Connect attaches without creating). All files in the batch would
          // hit the same wall, so abort with the actionable reason instead of a generic "failed".
          if (r.status === 404) {
            hideImportProgress();
            statusEl.textContent =
              jr.error ||
              `Case "${caseId}" does not exist — create it first with “＋ New case”`;
            e.target.value = "";
            return;
          }
          if (!r.ok) throw new Error(jr.error || "HTTP " + r.status);
          // CSV/log need the LLM to interpret them; with AI off the server saves the evidence but
          // skips analysis (jr.analyzed === false). Surface that honestly instead of "analyzing".
          if (jr.analyzed === false && jr.reason === "ai-off") aiOffSkipped++;
          else kinds[jr.kind] = (kinds[jr.kind] || 0) + 1;
        } catch (err) {
          dataFail++;
          console.warn("import failed:", f.name, err && err.message);
        }
      }
      if (!data.length) hideImportProgress(); // images-only batch: nothing to track

      // Image files → screenshot ingest (stored as evidence, analyzed when AI is on).
      let imgOk = 0,
        imgDup = 0,
        imgFail = 0,
        imgAiOff = 0;
      for (let i = 0; i < images.length; i++) {
        const f = images[i];
        statusEl.textContent = `importing screenshot ${i + 1}/${images.length}: ${f.name}…`;
        try {
          const imageBase64 = await fileToBase64(f);
          if (!imageBase64) {
            imgFail++;
            continue;
          }
          const triggerType = i === images.length - 1 ? "tab_switch" : "timer"; // flush the last window
          const r = await fetch("/captures", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              caseId,
              timestamp: new Date().toISOString(),
              url: "imported://" + f.name,
              tabTitle: f.name.replace(/\.[^.]+$/, ""),
              triggerType,
              imageBase64,
            }),
          });
          if (r.status === 403) {
            const jr = await r.json().catch(() => ({}));
            cancelImportProgress();
            statusEl.textContent =
              importPermissionMessage(caseId) ||
              jr.error ||
              "Your current role does not permit importing evidence. Ask a case administrator for the investigator or administrator role.";
            e.target.value = "";
            return;
          }
          if (r.status === 423) {
            const jr = await r.json().catch(() => ({}));
            statusEl.textContent =
              jr.error || "Case is closed — reopen it to add screenshots";
            e.target.value = "";
            return;
          }
          if (!r.ok) {
            imgFail++;
            continue;
          }
          const meta = await r.json();
          if (meta.isDuplicate) imgDup++;
          else if (meta.analyzed === false && meta.reason === "ai-off")
            imgAiOff++;
          else imgOk++;
        } catch {
          imgFail++;
        }
      }

      const parts = [];
      const kindList = Object.entries(kinds).map(([k, n]) =>
        n > 1 ? `${n}× ${k}` : k,
      );
      const floorNote =
        minSeverity && minSeverity !== "info"
          ? ` (min severity ${minSeverity})`
          : "";
      if (kindList.length)
        parts.push(
          `imported ${kindList.join(", ")}${floorNote} — analyzing (see AI status)`,
        );
      if (aiOffSkipped)
        parts.push(
          `${aiOffSkipped} CSV/log saved as evidence but NOT analyzed — AI is off (turn AI on, then re-import)`,
        );
      if (imgOk || imgDup || imgFail)
        parts.push(
          `${imgOk} screenshot(s)` +
            (imgDup ? `, ${imgDup} dup` : "") +
            (imgFail ? `, ${imgFail} failed` : ""),
        );
      if (imgAiOff)
        parts.push(
          `${imgAiOff} screenshot(s) saved but NOT analyzed — AI is off (turn AI on, then run: npm run reanalyze -- ${caseId})`,
        );
      if (dataFail) parts.push(`${dataFail} file(s) failed / unrecognized`);
      statusEl.textContent = parts.join(" · ") || "nothing imported";
      e.target.value = ""; // allow re-selecting the same files
      // Near-duplicate hosts (e.g. "HOST" vs "HOST.domain") are refreshed off the "idle" AI-status
      // event (js/dashboard-ai-status.js), not here: /import and /import-file both answer 202 before
      // the background import job actually lands the new events in the timeline, so a refresh at
      // this point would read pre-import state. "idle" is emitted once that background run finishes,
      // for every import kind — including with AI off, which is what this deterministic check needs.
    };
  }

  window.initUnifiedImport = initUnifiedImport;
})();
