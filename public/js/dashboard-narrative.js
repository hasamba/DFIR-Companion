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

  // The view is display-formatted prose — escaped paragraphs in a .prose container (proseHtml, in
  // js/dashboard-fragments.js) instead of one full-width block of text.
  //
  // THE RAW TEXT RIDES ALONG IN data-raw, and that is not bookkeeping. The Edit button used to seed
  // its textarea from view.textContent, which is the same string only while the view holds exactly
  // what the server sent. Once the display splits it into paragraphs, textContent concatenates them
  // with nothing between — so an analyst who opened the editor and saved would have written the
  // narrative back with its paragraph boundaries fused. Every writer sets both halves together.
  function setNarrativeView(text) {
    const view = document.getElementById("narrativeView");
    view.dataset.raw = text;
    view.innerHTML = proseHtml(text);
  }

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
          msg.textContent = "error: " + d.error;
          return;
        }
        msg.textContent = "generated and saved ✓";
        setNarrativeView(d.narrativeTimeline || "—");
        setTimeout(() => {
          msg.textContent = "";
        }, 3000);
      })
      .catch((e) => {
        msg.textContent = e.sectionDisabled
          ? e.message || ""
          : "generate failed: " +
            (e.message || "") +
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
      modelPerf += `<div class="sm-perf" data-safe-style="margin-top:4px" title="How often the second-opinion model agreed with the primary synthesis model on this case (#74)">🆚 A: <strong>${esc(so.modelA)}</strong> vs B: <strong>${esc(so.modelB)}</strong>: ${so.agreementCount} agreed, ${so.deltaCount} disagreed (${pct}%)${typeof so.referee === "string" && so.referee ? ` · referee: ${esc(so.referee)}` : ""}</div>`;
    }
    el.innerHTML = `<div class="sm-line"><span>🧠 Last synthesized <strong>${esc(relTime(m.lastSynthesizedAt))}</strong></span>${perfSpan}<span>${summary}</span></div>${coverage}${modelPerf}${evidenceMix}${detail}${secondLook}${largeAdvisory}`;
  }

  // ── Second look (#1554) — the analyst presses it, and sees the price first ──────────────
  //
  // IT USED TO RUN ITSELF. Every synthesis ended with a sweep that re-queried the raw archive and
  // wrote rows into the forensic record unasked. The record is the product, so what goes into it is
  // the analyst's decision, not a side effect of pressing something else.
  //
  // THE PREVIEW IS NOT AN EXTRA CLICK. It costs nothing — no model call, no write — so making the
  // analyst press the button to learn what the button would do is a worse trade than simply
  // telling them. It loads with the case and says how much would be searched and roughly how many
  // rows would land in the record.
  //
  // NO BROWSER MODAL anywhere in here. confirm() and alert() block the automation harness, and a
  // native dialog cannot show the numbers this panel has to. Every question is inline markup.
  //
  // EVERY SERVER STRING IS ESCAPED. The summary and the leads are built from event text, and event
  // text comes from the machine under investigation.
  let slCaseId = "";
  let slPreview = null; // the last /second-look/preview answer for this case
  let slPreviewError = "";
  let slPreviewState = "idle"; // "idle" | "loading" | "ready" | "error"
  let slResult = null; // the last completed run
  let slRunError = "";
  let slBusy = false;
  let slRunGen = 0; // whose resolution owns the busy flag
  let slLoadGen = 0;

  const slNum = (v) => (typeof v === "number" && isFinite(v) ? v.toLocaleString() : "0");
  const slPlural = (n, one, many) => (n === 1 ? one : many);

  /** The counts the preview quotes, as "7 open questions, 3 hypotheses, 12 IOCs". Never a total we invented. */
  function slScopeParts(p) {
    const parts = [];
    if (p.questions > 0) parts.push(`${slNum(p.questions)} open ${slPlural(p.questions, "question", "questions")}`);
    if (p.hypotheses > 0) parts.push(`${slNum(p.hypotheses)} ${slPlural(p.hypotheses, "hypothesis", "hypotheses")}`);
    if (p.iocs > 0) parts.push(`${slNum(p.iocs)} ${slPlural(p.iocs, "IOC", "IOCs")}`);
    if (p.modelRequests > 0)
      parts.push(`${slNum(p.modelRequests)} evidence ${slPlural(p.modelRequests, "request", "requests")} from the model`);
    return parts;
  }

  // WHAT THE PRESS WOULD DO, BEFORE IT IS PRESSED.
  //
  // `wouldPromote` is the server's own count of matching rows, not a guess, so it is stated as a
  // number. When the sweep has nothing to search the panel says so plainly rather than offering a
  // button that would do nothing: an offer that is always there stops meaning anything.
  function slPreviewHtml() {
    const p = slPreview;
    const scope = slScopeParts(p);
    if (!scope.length) {
      return (
        `<p class="sl-line">Nothing to look for yet. A second look searches the raw archive for this case's open` +
        ` questions, hypotheses and IOCs, and this case has none recorded — run synthesis first.</p>`
      );
    }
    const searches = p.requests > 0 ? p.requests : 0;
    const lines = [];
    lines.push(
      `<p class="sl-line">Would search the raw archive for ${esc(scope.join(", "))}` +
        (searches > 0 ? ` — ${slNum(searches)} ${slPlural(searches, "search", "searches")} in all.` : ".") +
        `</p>`,
    );
    if (typeof p.wouldPromote === "number") {
      lines.push(
        p.wouldPromote > 0
          ? `<p class="sl-line"><strong>About ${slNum(p.wouldPromote)} ${slPlural(p.wouldPromote, "row", "rows")}</strong>` +
              ` would be pulled out of the archive and written into this case's forensic timeline.</p>`
          : `<p class="sl-line">No archive row matches any of them right now, so nothing would be written into the` +
              ` forensic timeline.</p>`,
      );
    }
    const leadCount = Array.isArray(p.leads) ? p.leads.length : 0;
    if (leadCount > 0) {
      lines.push(
        `<p class="sl-line sl-muted">${slNum(leadCount)} of those ${slPlural(leadCount, "search matches", "searches match")}` +
          ` nothing in the archive. Each one is recorded as a collection lead — evidence this case does not hold yet.</p>`,
      );
    }
    if (p.shapeHeld > 0) {
      lines.push(
        `<p class="sl-line sl-muted">${slNum(p.shapeHeld)} further ${slPlural(p.shapeHeld, "row is", "rows are")} repeats of a` +
          ` row already being promoted and would be held back. They stay searchable in the archive.</p>`,
      );
    }
    if (p.truncated === true) {
      lines.push(
        `<p class="sl-line sl-warn">More rows match than one sweep reads. This is not full coverage of the archive.</p>`,
      );
    }
    return lines.join("");
  }

  function slNotConfiguredHtml(reason) {
    return (
      `<p class="sl-line">${esc(reason)}</p>` +
      `<p class="sl-line sl-muted">A second look reads the raw super-timeline archive. Without one there is nothing` +
      ` for it to re-read, and this control stays off.</p>`
    );
  }

  // WHAT HAPPENED, IN THE ANALYST'S TERMS — rows, repeats, leads, and whether the conclusions moved.
  function slResultHtml() {
    const r = slResult;
    const lines = [];
    const promoted = typeof r.promoted === "number" ? r.promoted : 0;
    lines.push(
      promoted > 0
        ? `<p class="sl-line"><strong>${slNum(promoted)} ${slPlural(promoted, "row", "rows")}</strong> moved from the raw` +
            ` archive into this case's forensic timeline. Each one carries a "✓ Promoted" badge in the timeline.</p>`
        : `<p class="sl-line">Nothing matched, so no row was written into the forensic timeline.</p>`,
    );
    const held = typeof r.shapeCapped === "number" ? r.shapeCapped : 0;
    if (held > 0) {
      lines.push(
        `<p class="sl-line sl-muted">${slNum(held)} repeat ${slPlural(held, "row was", "rows were")} held back — same shape as` +
          ` a row already promoted. They were not deleted: they are still in the archive and still searchable there.</p>`,
      );
    }
    const leads = Array.isArray(r.leads) ? r.leads : [];
    if (leads.length > 0) {
      const shown = leads.slice(0, 6).map(esc).join("; ");
      lines.push(
        `<p class="sl-line sl-muted">${slNum(leads.length)} ${slPlural(leads.length, "question", "questions")} found nothing` +
          ` in the archive. Each is recorded as a collection lead: ${shown}` +
          (leads.length > 6 ? ` +${slNum(leads.length - 6)} more` : "") +
          `.</p>`,
      );
    }
    if (r.truncated === true) {
      lines.push(
        `<p class="sl-line sl-warn">Not every matching row was read — the sweep hit its own limit, so this is not full` +
          ` coverage of the archive.</p>`,
      );
    }
    lines.push(
      r.resynthesized === true
        ? `<p class="sl-line sl-muted">The conclusions were written again afterwards, so they take these rows into account.</p>`
        : `<p class="sl-line sl-warn">The conclusions were NOT written again. They are still the ones from before these rows` +
            ` arrived — re-synthesise when you want them to catch up.</p>`,
    );
    if (r.summary) lines.push(`<p class="sl-line sl-muted">${esc(String(r.summary))}</p>`);
    return lines.join("");
  }

  function renderSecondLook() {
    const card = document.getElementById("secondLookCard");
    if (!card) return;
    const prev = document.getElementById("secondLookPreview");
    const statusEl = document.getElementById("secondLookStatus");
    const resultEl = document.getElementById("secondLookResult");
    const btn = document.getElementById("secondLookRunBtn");
    const resynth = document.getElementById("secondLookResynth");

    const configured = slPreviewState === "ready" && slPreview && slPreview.configured === true;
    const nothingToDo = configured && slScopeParts(slPreview).length === 0;
    card.style.display = slCaseId ? "block" : "none";

    if (prev) {
      if (slPreviewState === "loading") prev.innerHTML = `<p class="sl-line sl-muted">Measuring what a second look would find…</p>`;
      else if (slPreviewState === "error")
        prev.innerHTML =
          `<p class="sl-line sl-warn">Could not measure what a second look would find (${esc(slPreviewError)}).` +
          ` Nothing here says the archive holds no answers.</p>`;
      else if (slPreviewState === "ready" && !configured) prev.innerHTML = slNotConfiguredHtml(slPreviewError || "The super-timeline archive is not configured for this case.");
      else if (configured) prev.innerHTML = slPreviewHtml();
      else prev.innerHTML = "";
    }

    // The button is locked by the SAME flag the run reads; `disabled` is only what the analyst
    // sees of it. A second press cannot start a concurrent run even if the attribute is edited.
    if (btn) {
      btn.disabled = slBusy || !slCaseId || !configured || nothingToDo;
      btn.textContent = slBusy ? "Looking…" : "Run second look";
      btn.title = configured
        ? "Search the raw archive for this case's open questions, hypotheses and IOCs, promote every row that matches into the forensic timeline, then re-synthesise."
        : "The super-timeline archive is not configured — see the note above.";
    }
    if (resynth) resynth.disabled = slBusy;

    if (statusEl) {
      let msg = "";
      if (!slCaseId) msg = "Connect to a case to run a second look.";
      else if (slBusy) msg = "Re-reading the raw archive. Nothing is on screen yet; rows are written when it finishes.";
      else if (slRunError) msg = slRunError;
      statusEl.textContent = msg;
    }
    if (resultEl) resultEl.innerHTML = slBusy || !slResult ? "" : slResultHtml();
  }

  // ONE RUN AT A TIME, AND THE FLAG COMES OFF ON EVERY PATH.
  //
  // A cancelled or errored load that leaves an in-flight flag on wedges the control for the rest of
  // the session — a bug class this codebase has shipped before. The flag is cleared in a `finally`,
  // and generation-stamped so a resolution that no longer owns it lets go rather than unlocking a
  // newer run. loadSecondLookPreview() clears it too, which covers a case switch mid-run.
  function runSecondLook() {
    if (slBusy || !slCaseId) return;
    const caseId = slCaseId;
    const box = document.getElementById("secondLookResynth");
    const resynthesize = !box || box.checked !== false;
    const gen = ++slRunGen;
    slBusy = true;
    slRunError = "";
    slResult = null;
    renderSecondLook();
    return fetch(`/cases/${encodeURIComponent(caseId)}/second-look`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ resynthesize }),
    })
      .then((r) => r.json().then((body) => ({ ok: r.ok, code: r.status, body })))
      .then((r) => {
        if (slCaseId !== caseId || slRunGen !== gen) return;
        if (!r.ok) {
          slRunError = `The second look did not run: ${r.body && r.body.error ? String(r.body.error) : `HTTP ${r.code}`}`;
          return;
        }
        slResult = r.body && typeof r.body === "object" ? r.body : null;
        if (!slResult) slRunError = "The second look returned nothing this panel can read.";
      })
      .catch((err) => {
        if (slCaseId !== caseId || slRunGen !== gen) return;
        slRunError = `The second look did not run: ${String((err && err.message) || err)}`;
      })
      .finally(() => {
        // The generation check is not an escape from "always clear it": loadSecondLookPreview() has
        // already cleared the flag for the run this resolution belongs to, and a newer run may own
        // it now. Clearing it here would unlock a run still in flight — the same wedge, one case on.
        if (slRunGen !== gen) return;
        slBusy = false;
        renderSecondLook();
        // ONLY AFTER A RUN THAT LANDED. Rows are in the case now, so the synthesis strip and the
        // preview's own figures are both stale. A run that FAILED changed nothing, and re-measuring
        // would replace the reason on screen with a spinner and disable the button the analyst
        // needs in order to try again.
        if (!slResult) return;
        if (typeof loadSynthMeta === "function") loadSynthMeta(caseId);
        loadSecondLookPreview(caseId);
      });
  }

  /** Measure, never spend. Called on case connect, and again after a run so the panel re-costs. */
  function loadSecondLookPreview(caseId) {
    // A CASE SWITCH IS AN EXIT PATH for a run started under the previous case: the flag goes off
    // and the generation moves on, so that run's `finally` cannot touch either again.
    //
    // A RE-MEASURE OF THE SAME CASE IS NOT. The last thing this function does after a successful
    // run is call itself, and clearing the result there would wipe the report of the run the
    // analyst had just pressed — one render after it appeared.
    const switched = slCaseId !== caseId;
    slCaseId = caseId;
    slBusy = false;
    slRunGen++;
    if (switched) {
      slResult = null;
      slRunError = "";
    }
    slPreview = null;
    slPreviewError = "";
    slPreviewState = "loading";
    renderSecondLook();
    const gen = ++slLoadGen;
    return fetch(`/cases/${encodeURIComponent(caseId)}/second-look/preview`)
      .then((r) => r.json().then((body) => ({ ok: r.ok, code: r.status, body })))
      .then((r) => {
        if (slCaseId !== caseId || slLoadGen !== gen) return;
        // A 501 IS an answer — "no super-timeline archive here" — and belongs in the panel as the
        // reason, not as a request failure the analyst can do nothing with.
        if (!r.ok) {
          if (r.code === 501 && r.body && r.body.error) {
            slPreview = { configured: false };
            slPreviewError = String(r.body.error);
            slPreviewState = "ready";
            return;
          }
          throw new Error(`HTTP ${r.code}`);
        }
        slPreview = r.body && typeof r.body === "object" ? r.body : { configured: false };
        slPreviewState = "ready";
      })
      .catch((err) => {
        if (slCaseId !== caseId || slLoadGen !== gen) return;
        slPreviewError = String((err && err.message) || err);
        slPreviewState = "error";
      })
      .finally(() => {
        if (slCaseId === caseId && slLoadGen === gen) renderSecondLook();
      });
  }

  // Wired from initNarrativeTimeline, not from a second initializer: the control sits in the card
  // this module already owns, so it shares the one entry point the page calls.
  /**
   * The toolbar button OPENS the card; it never starts the sweep. A second look writes rows into
   * the forensic record, and a toolbar click that spends nothing is the only kind that can be
   * pressed by accident safely. Same contract as the Missed evidence button beside it.
   */
  function revealSecondLook() {
    const card = document.getElementById("secondLookCard");
    const section = document.getElementById("sec-findings");
    if (typeof markSectionRevealed === "function") markSectionRevealed("sec-findings");
    if (section) section.classList.remove("collapsed");
    (card || section)?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function initSecondLook() {
    document.getElementById("secondLookBtn")?.addEventListener("click", revealSecondLook);
    const btn = document.getElementById("secondLookRunBtn");
    if (!btn) return;
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      runSecondLook();
    });
    const box = document.getElementById("secondLookResynth");
    if (box) box.addEventListener("change", renderSecondLook);
    renderSecondLook();
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
        // data-raw, never textContent — see setNarrativeView. The `??` covers the one case where
        // no writer has run yet: the markup's own "—" placeholder carries no data-raw.
        const raw = view.dataset.raw ?? view.textContent;
        ta.value = raw === "—" ? "" : raw;
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
            setNarrativeView(text || "—");
            document.getElementById("narrativeView").style.display = "";
            document.getElementById("narrativeEditWrap").style.display = "none";
            msg.textContent = "";
          })
          .catch((e) => {
            msg.textContent = "save failed: " + (e.message || "");
          });
      });
    document
      .getElementById("cancelNarrativeBtn")
      .addEventListener("click", () => {
        document.getElementById("narrativeView").style.display = "";
        document.getElementById("narrativeEditWrap").style.display = "none";
      });
    initSecondLook();
  }

  window.genNarrative = genNarrative;
  window.loadSynthMeta = loadSynthMeta;
  window.loadSecondLookPreview = loadSecondLookPreview;
  window.runSecondLook = runSecondLook;
  window.initNarrativeTimeline = initNarrativeTimeline;
})();
