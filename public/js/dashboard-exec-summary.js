// Executive summary generator — the short non-technical write-up of a case (#415 tier 3).
//
// NO INITIALIZER: nothing in this block runs at load. All three statements the splitter reported
// are guard stanzas that earlier extractions left in this range — the narrative timeline, import
// undo/redo and the correlation profile — and they stay in the page.
(function () {
  // --- Executive summary generator ----------------------------------------------
  // One AI call over the synthesized case → a management-facing prose summary. Shown for review;
  // "Save" copies it into the report-meta Executive Summary field (which overrides the auto
  // summary in the generated report).
  function genExecSummary() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    // A hidden dashboard panel must not spend tokens generating AI content (issue #168).
    if (!isSectionVisible("sec-exec", loadSectionsVis())) return;
    const btn = document.getElementById("genExecBtn");
    const msg = document.getElementById("genExecMsg");
    const out = document.getElementById("execGenResult");
    btn.disabled = true;
    msg.textContent = "generating… (one AI call)";
    out.innerHTML = "";
    fetch(`/cases/${caseId}/executive-summary`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(async (r) => {
        const d = await r.json().catch(() => ({}));
        // 409 + sectionDisabled: the report's Executive summary section is off, so the server
        // skipped the AI call to save tokens. Surface why instead of a generic failure.
        if (r.status === 409 && d.sectionDisabled) {
          const e = new Error(d.error || "section disabled");
          e.sectionDisabled = true;
          throw e;
        }
        // Surface the server's real error (e.g. "Budget limit exceeded", "402 billing") instead of a
        // bare "HTTP 500" — the route returns it in d.error; fall back to the status only when absent.
        if (!r.ok) throw new Error(d.error || "HTTP " + r.status);
        return d;
      })
      .then((d) => {
        msg.textContent = "";
        const text = d.summary || "(no summary returned)";
        out.innerHTML =
          `<div class="info-card" data-safe-style="border-left:3px solid var(--accent);margin-top:8px">` +
          // Paragraphed prose in a capped measure, like the saved summary above it — the review
          // copy is the one an analyst actually reads before deciding to keep it.
          `<div class="prose">${proseHtml(text)}</div>` +
          `<div data-safe-style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">` +
          `<button id="execSaveBtn">Save to report's Executive Summary</button>` +
          `<span id="execSaveMsg" data-safe-style="color:var(--text-muted);font-size:12px"></span></div></div>`;
        document.getElementById("execSaveBtn").onclick = () => {
          const ta = document.getElementById("rm-executiveSummary");
          if (ta) ta.value = text;
          saveReportMeta(); // persists rm-executiveSummary alongside the rest of the report meta
          document.getElementById("execSaveMsg").textContent =
            "saved ✓ — overrides the auto summary in the report";
          document.getElementById("execSaveBtn").disabled = true;
        };
      })
      .catch((e) => {
        msg.textContent = "";
        out.innerHTML = e.sectionDisabled
          ? `<div data-safe-style="color:var(--text-muted);margin-top:8px">${esc(e.message)}</div>`
          : `<div data-safe-style="color:var(--sev-high);margin-top:8px">generate failed: ${esc(e.message)} — restart the companion server if this 404s</div>`;
      })
      .finally(() => {
        btn.disabled = false;
      });
  }

  window.genExecSummary = genExecSummary;
})();
