// Narrative Timeline — the AI-written case narrative, its editor, and the synthesis metadata strip
// that says which model wrote it and when (#415 tier 3).
//
// IIFE-WRAPPED AS A MATTER OF COURSE. It happens to own no top-level state today, but this is a
// CLASSIC script: any binding added later at this level would join the shared global lexical
// environment and be reachable by name from every other script on the page.
//
// ITS WIRING IS AN INITIALIZER. Four controls — Generate, Edit, Save and Cancel — were bound at
// module scope in the inline block. In a <head> script that queries them before the markup exists
// and binds nothing, silently.
//
// TWO OF THE SIX BINDINGS UNDER THAT BANNER DID NOT COME. importUndoBtn and importRedoBtn call
// doImportUndoRedo, which is declared six hundred lines away and belongs to the import feature.
// They sat between the narrative bindings for no reason other than proximity, and they stay in the
// page with the function they call.
(function () {
  // --- Narrative Timeline -------------------------------------------------------
  function genNarrative() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    // A hidden dashboard panel must not spend tokens generating AI content (issue #168).
    if (!isSectionVisible("sec-narrative", loadSectionsVis())) return;
    const btn = document.getElementById("genNarrativeBtn");
    const msg = document.getElementById("genNarrativeMsg");
    btn.disabled = true;
    msg.textContent = "generating… (one AI call)";
    fetch(`/cases/${caseId}/narrative`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then(async (r) => {
        const d = await r.json().catch(() => ({}));
        // 409 + sectionDisabled: the report's Timeline section (which holds the narrative) is off,
        // so the server skipped the AI call to save tokens (issue #168). Surface why, not a failure.
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
        if (d.error) {
          msg.textContent = "error: " + esc(d.error);
          return;
        }
        msg.textContent = "generated and saved ✓";
        document.getElementById("narrativeView").textContent =
          d.narrativeTimeline || "—";
        setTimeout(() => {
          msg.textContent = "";
        }, 3000);
      })
      .catch((e) => {
        msg.textContent = e.sectionDisabled
          ? esc(e.message)
          : "generate failed: " +
            esc(e.message) +
            " — restart the companion server if this 404s";
      })
      .finally(() => {
        btn.disabled = false;
      });
  }

  function loadSynthMeta(caseId) {
    fetch(`/cases/${caseId}/synth-meta`)
      .then((r) => r.json())
      .then(renderSynthMeta)
      .catch(() => {});
  }
  function renderSynthMeta(m) {
    const el = document.getElementById("synthMeta");
    if (!el) return;
    if (!m || !m.lastSynthesizedAt) {
      el.innerHTML = "";
      el.style.display = "none";
      return;
    }
    el.style.display = "block";
    const d = m.lastDiff || { added: [], removed: [], severityChanged: [] };
    const a = d.added.length,
      r = d.removed.length,
      c = d.severityChanged.length;
    const counts = [];
    if (a) counts.push(`<span class="sm-added">+${a} new</span>`);
    if (r) counts.push(`<span class="sm-removed">−${r} dropped</span>`);
    if (c) counts.push(`<span class="sm-changed">↕ ${c} severity</span>`);
    const summary = counts.length
      ? counts.join(" · ")
      : "no change in findings";
    let detail = "";
    if (a || r || c) {
      const items = [
        ...d.added.map(
          (t) => `<span class="sm-item sm-added">+ ${esc(t)}</span>`,
        ),
        ...d.removed.map(
          (t) => `<span class="sm-item sm-removed">− ${esc(t)}</span>`,
        ),
        ...d.severityChanged.map(
          (x) =>
            `<span class="sm-item sm-changed">↕ ${esc(x.title)} (${esc(x.from)} → ${esc(x.to)})</span>`,
        ),
      ].join("");
      detail = `<details><summary>what changed since the prior run</summary>${items}</details>`;
    }
    const perfParts = [];
    if (m.durationMs !== undefined)
      perfParts.push(
        `<span title="Synthesis AI call duration">⏱ ${m.durationMs < 60000 ? (m.durationMs / 1000).toFixed(1) + "s" : Math.round(m.durationMs / 60000) + "m"}</span>`,
      );
    if (m.eventCount !== undefined)
      perfParts.push(
        `<span title="Events in case at synthesis time">${m.eventCount.toLocaleString()} events</span>`,
      );
    if (m.iocCount !== undefined)
      perfParts.push(
        `<span title="IOCs in case at synthesis time">${m.iocCount.toLocaleString()} IOCs</span>`,
      );
    const perfSpan = perfParts.length
      ? `<span class="sm-perf">${perfParts.join(" · ")}</span>`
      : "";
    const largeAdvisory =
      m.eventCount !== undefined && m.eventCount >= 5000
        ? `<div data-safe-style="margin-top:5px;color:var(--sev-medium);font-size:11px">⚠ Large case (${m.eventCount.toLocaleString()} events) — consider restricting the investigation scope to a date range for faster synthesis.</div>`
        : "";
    // Second-look loop (#11): the post-synthesis raw re-query result. A green line when it pulled
    // rows up and re-synthesized; a muted line listing collection leads when requests came back empty.
    let secondLook = "";
    const sl = m.secondLook;
    if (sl && (sl.promoted > 0 || (sl.leads && sl.leads.length))) {
      if (sl.promoted > 0) {
        secondLook = `<div data-safe-style="margin-top:5px;color:var(--sev-low);font-size:11px" title="The tool re-queried the complete raw record for the open questions and folded new matches into the conclusions">🔁 ${esc(sl.summary || sl.promoted + " raw event(s) promoted")}</div>`;
      } else {
        const leads = sl.leads.slice(0, 4).map(esc).join("; ");
        secondLook = `<div data-safe-style="margin-top:5px;color:var(--text-muted);font-size:11px" title="Second-look requests that matched nothing in the raw record — collect these to close the gap">🔎 Second look found no new evidence; collection leads: ${leads}${sl.leads.length > 4 ? ` +${sl.leads.length - 4} more` : ""}</div>`;
      }
    }
    // Evidence mix (#4): the per-class counts of events the model actually saw this run, so the analyst
    // understands the basis — e.g. "24 anchors · 60 context · 12 corroborated · 8 rare".
    let evidenceMix = "";
    const sc = m.selectionCounts;
    if (sc && typeof sc === "object") {
      const LABELS = {
        anchor: "anchors",
        earliest: "earliest",
        anchor_context: "context",
        corroborated: "corroborated",
        technique: "technique",
        rare: "rare",
        spread: "spread",
      };
      const parts = Object.keys(LABELS)
        .filter((k) => (sc[k] || 0) > 0)
        .map((k) => `${sc[k]} ${LABELS[k]}`);
      if (parts.length)
        evidenceMix = `<div class="sm-perf" data-safe-style="margin-top:4px" title="How many events of each selection class the model saw — the evidence mix behind these conclusions (#4)">🧩 saw ${esc(parts.join(" · "))}</div>`;
    }
    // Coverage audit (#62): how many in-window events the model actually read vs left out, and why.
    // A muted line normally; amber when a chunk was dropped for the size limit, so the analyst can see
    // the conclusions rest on a subset (and consider narrowing the scope).
    let coverage = "";
    const cv = m.coverage;
    if (cv && typeof cv === "object" && cv.inWindow > 0) {
      const omitted = (cv.omittedBudget || 0) + (cv.omittedLegitimate || 0);
      let txt = `📊 Considered <strong>${cv.considered.toLocaleString()}</strong> of ${cv.inWindow.toLocaleString()} in-window events`;
      if (omitted > 0) {
        const bits = [];
        if (cv.omittedBudget > 0)
          bits.push(`${cv.omittedBudget.toLocaleString()} size limit`);
        if (cv.omittedLegitimate > 0)
          bits.push(`${cv.omittedLegitimate.toLocaleString()} filtered`);
        txt += ` (${omitted.toLocaleString()} omitted: ${bits.join(", ")})`;
      }
      if (cv.omittedHighSeverity > 0)
        txt += ` · ${cv.omittedHighSeverity} high-severity recovered by the safety net`;
      if (cv.promptTokensEstimate > 0)
        txt += ` · ~${Math.round(cv.promptTokensEstimate / 1000)}k tokens`;
      const warn = cv.omittedBudget > 0;
      coverage = `<div class="sm-perf" data-safe-style="margin-top:4px${warn ? ";color:var(--sev-medium)" : ""}" title="How much of the in-scope timeline the AI actually read this run (#62). Events omitted for the size limit are still in the case; any Critical/High among them is still covered by the deterministic safety-net backfill.">${txt}</div>`;
    }
    // Per-model quality telemetry (#74): the synthesis model used this run, how many findings it
    // produced vs how many the deterministic safety net had to backfill (a proxy for missed
    // detections), and any parse retries — plus the second-opinion agreement rate when one has run.
    let modelPerf = "";
    if (m.synthModel) {
      const bits = [`🤖 <strong>${esc(m.synthModel)}</strong>`];
      if (m.findingsCount !== undefined)
        bits.push(`${m.findingsCount.toLocaleString()} finding(s)`);
      if (m.highSeverityBackfillCount)
        bits.push(
          `<span data-safe-style="color:var(--sev-medium)">${m.highSeverityBackfillCount} backfilled by safety net</span>`,
        );
      if (m.parseRetries)
        bits.push(
          `<span data-safe-style="color:var(--badge-danger-text)">${m.parseRetries} parse retr${m.parseRetries === 1 ? "y" : "ies"}</span>`,
        );
      modelPerf = `<div class="sm-perf" data-safe-style="margin-top:4px" title="The synthesis model this run, and quality signals to compare DFIR_AI_MODEL / DFIR_AI_SYNTH_MODEL choices empirically (#74)">${bits.join(" · ")}</div>`;
    }
    const so = m.secondOpinionPerf;
    if (so && (so.modelA || so.modelB)) {
      const pct = Math.round((so.agreementRate || 0) * 100);
      modelPerf += `<div class="sm-perf" data-safe-style="margin-top:4px" title="How often the second-opinion model agreed with the primary synthesis model on this case (#74)">🆚 <strong>${esc(so.modelB)}</strong> vs <strong>${esc(so.modelA)}</strong>: ${so.agreementCount} agreed, ${so.deltaCount} disagreed (${pct}%)</div>`;
    }
    el.innerHTML = `<div class="sm-line"><span>🧠 Last synthesized <strong>${esc(relTime(m.lastSynthesizedAt))}</strong></span>${perfSpan}<span>${summary}</span></div>${coverage}${modelPerf}${evidenceMix}${detail}${secondLook}${largeAdvisory}`;
  }

  // The four narrative controls the inline block bound at module scope. Order unchanged.
  function initNarrativeTimeline() {
    document
      .getElementById("genNarrativeBtn")
      .addEventListener("click", (e) => {
        e.stopPropagation();
        genNarrative();
      });
    document
      .getElementById("editNarrativeBtn")
      .addEventListener("click", (e) => {
        e.stopPropagation();
        const view = document.getElementById("narrativeView");
        const wrap = document.getElementById("narrativeEditWrap");
        const ta = document.getElementById("narrativeText");
        ta.value = view.textContent === "—" ? "" : view.textContent;
        view.style.display = "none";
        wrap.style.display = "";
        ta.focus();
      });
    document
      .getElementById("saveNarrativeBtn")
      .addEventListener("click", () => {
        const caseId = document.getElementById("caseId").value.trim();
        if (!caseId) return;
        const text = document.getElementById("narrativeText").value;
        const msg = document.getElementById("saveNarrativeMsg");
        msg.textContent = "saving…";
        fetch(`/cases/${caseId}/narrative`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ narrativeTimeline: text }),
        })
          .then((r) => {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(() => {
            document.getElementById("narrativeView").textContent = text || "—";
            document.getElementById("narrativeView").style.display = "";
            document.getElementById("narrativeEditWrap").style.display = "none";
            msg.textContent = "";
          })
          .catch((e) => {
            msg.textContent = "save failed: " + esc(e.message);
          });
      });
    document
      .getElementById("cancelNarrativeBtn")
      .addEventListener("click", () => {
        document.getElementById("narrativeView").style.display = "";
        document.getElementById("narrativeEditWrap").style.display = "none";
      });
  }

  window.genNarrative = genNarrative;
  window.loadSynthMeta = loadSynthMeta;
  window.initNarrativeTimeline = initNarrativeTimeline;
})();
