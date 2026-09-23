// Second look (#1554) — its own panel, beside Missed Evidence Review.
//
// IT WAS A CARD INSIDE FINDINGS. It sat under the synthesis strip, on the argument that the strip
// already reports what a sweep found so the control that starts one belongs in the same card. The
// analyst could not find it — twice. A control that writes to the forensic record has to be
// somewhere a person looks for it, and the place they look is the left nav.
//
// ITS PEER IS sec-jev-review, and the two are the same kind of thing: both read the raw
// super-timeline archive, both write rows into the forensic record, both cost nothing to open and
// only spend when a button inside the panel is pressed. They now sit next to each other.
//
// WHAT STAYED BEHIND is the one-line summary on the synthesis strip ("🔁 N raw event(s) promoted",
// or the collection leads). That line is synthesis METADATA — a fact about the last synthesis run —
// so it belongs with the other synthesis facts in js/dashboard-narrative.js, and it is not
// duplicated here.
//
// IIFE-WRAPPED. Every `let` below is this feature's own state; at top level in a classic script it
// would join the shared global lexical environment and be reachable by name from every other
// script on the page.
//
// NO MODULE-SCOPE DOM WORK. The page loads this in <head>, before the markup exists, so every
// getElementById lives inside a function and the wiring waits for initSecondLook().
(function () {
  // ── The analyst presses it, and sees the price first ───────────────────────────────────
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

  /**
   * The toolbar button OPENS the panel; it never starts the sweep. A second look writes rows into
   * the forensic record, and a toolbar click that spends nothing is the only kind that can be
   * pressed by accident safely. Same contract as the Missed evidence button beside it.
   *
   * The reveal is the page's own idiom: a view profile may have hidden the section outright, and
   * scrollIntoView() on a display:none element is a silent no-op.
   */
  function revealSecondLook() {
    const sec = document.getElementById("sec-second-look");
    if (!sec) return;
    if (typeof markSectionRevealed === "function") markSectionRevealed("sec-second-look");
    sec.classList.remove("collapsed");
    sec.scrollIntoView({ behavior: "smooth", block: "start" });
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

  // Only the three that are called from outside this file: initSecondLook from the inline script at
  // load, loadSecondLookPreview from the case-panel loaders in js/dashboard-case-connect.js, and
  // runSecondLook, which the panel's own suite drives the way the button does. The render and every
  // piece of state stay inside the closure.
  window.loadSecondLookPreview = loadSecondLookPreview;
  window.runSecondLook = runSecondLook;
  window.initSecondLook = initSecondLook;
})();
