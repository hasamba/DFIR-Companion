// Watson marks: the "Watson" badge and Undo button on every item Watson wrote, in the section that
// shows it (findings, next steps, forensic-timeline rows, report details). The sections call
// watsonMarkHtml() once; this file knows which proposals are applied (dashboard-watson.js hands them
// over through watsonMarksSet) and how to jump to an item from a "Wrote:" link.
//
// Every analyst, model and evidence string goes through esc()/escAttr() (dashboard-escape.js).
// Actions ride on data-act="watsonAct" + data-w-verb; the CSP bans inline handlers.
(function () {
  const SECTION = {
    finding: "sec-findings",
    next_step: "sec-next-steps",
    event: "sec-timeline",
    report: "sec-case-details",
  };
  const KIND_OF = {
    finding_new: "finding",
    finding_update: "finding",
    next_step_new: "next_step",
    event_promote: "event",
    report_text: "report",
  };
  const WATSON_MARKER = "[watson]";
  const REPORT_FIELDS = ["conclusions", "investigationLimitations"];

  let applied = []; // applied Watson proposals that write into a section
  let signature = "";
  let lastReportMeta = null;

  // The ids one applied proposal marks: a finding/step id, a report field, every row a promotion
  // actually added (its recorded ids — a held row the case already held is not Watson's).
  function idsOf(p) {
    if (p.kind === "event_promote") return Array.isArray(p.createdEventIds) ? p.createdEventIds : [];
    return p.kind === "report_text" ? [p.field || p.targetId] : [p.targetId];
  }
  const proposalFor = (kind, id) =>
    applied.find((p) => KIND_OF[p.kind] === kind && idsOf(p).includes(id));

  function watsonUndoTarget(kind, id) {
    const p = proposalFor(kind, id);
    return p ? p.id : "";
  }

  function notesHtml(f) {
    const d = f.synthesisDisagrees;
    return (
      (d ? `<span class="watson-note">Synthesis disagrees: ${esc(d.severity)} — ${esc(d.title)}</span>` : "") +
      (f.similarSynthesisId
        ? `<span class="watson-note">Synthesis has a similar finding: <a class="finding-jump" data-fid="${escAttr(f.similarSynthesisId)}" title="Jump to that finding">${esc(f.similarSynthesisId)}</a></span>`
        : "") +
      (f.citationsChanged ? `<span class="watson-note">cited evidence changed</span>` : "")
    );
  }

  const isWatsonItem = (kind, item) =>
    !!item && (kind === "event" ? (item.provenance || []).includes(WATSON_MARKER) : item.author === "watson");

  // "" unless an applied Watson proposal targets the item (or the item itself says Watson wrote it).
  // item (optional): the finding / step / event / report meta being drawn, for what the proposal
  // list cannot say (synthesis notes, a proposal that has left the capped chat).
  function watsonMarkHtml(kind, id, item) {
    const p = proposalFor(kind, id);
    if (!p && !isWatsonItem(kind, item)) return "";
    const who = (p && p.appliedBy) || (item && item.approvedBy) || "an analyst";
    const rows = p && p.kind === "event_promote" ? idsOf(p).length : 0;
    const undoTitle = rows ? `Undo — removes all ${rows} row${rows === 1 ? "" : "s"} Watson promoted` : "Undo what Watson wrote";
    return (
      `<span class="watson-mark" data-w-mark="${escAttr(kind + ":" + id)}" title="${escAttr("Added by Watson, approved by " + who)}">Watson</span>` +
      (p
        ? `<button type="button" class="watson-mini watson-undo" data-act="watsonAct" data-w-verb="undo" data-pid="${escAttr(p.id)}" title="${escAttr(undoTitle)}" aria-label="${escAttr(undoTitle)}">Undo</button>`
        : "") +
      (kind === "finding" && item ? notesHtml(item) : "")
    );
  }

  // Report details: the two Watson-writable fields carry a slot beside their label.
  function fillReportSlots() {
    if (typeof document === "undefined" || !document.querySelectorAll) return;
    const marked = (lastReportMeta && lastReportMeta.watsonFields) || {};
    document.querySelectorAll("[data-watson-slot]").forEach((el) => {
      const f = el.dataset.watsonSlot;
      // Marked but the proposal left the chat: the badge stays (no Undo), as for the other kinds.
      el.innerHTML = REPORT_FIELDS.includes(f) && marked[f] ? watsonMarkHtml("report", f, { author: "watson" }) : "";
    });
  }
  function watsonMarkReportSlots(meta) {
    lastReportMeta = meta || null;
    fillReportSlots();
  }

  // The chat arrived or changed. Sections drawn before the proposals were known are drawn again,
  // once, when what is marked has changed (the signature stops a render -> chat -> render loop).
  function watsonMarksSet(proposals) {
    applied = (proposals || []).filter((p) => p.status === "applied" && KIND_OF[p.kind]);
    const next = applied.map((p) => `${p.id}:${p.appliedBy || ""}`).sort().join("|");
    const changed = next !== signature;
    signature = next;
    fillReportSlots();
    if (changed && typeof DfirState !== "undefined" && typeof render === "function" && DfirState.lastState()) {
      render(DfirState.lastState());
    }
  }

  // A refused Undo pressed in a section (not on a card in the panel): the server's message goes in a
  // short line beside that button, so the analyst sees it where they clicked. True when it did.
  function watsonSectionRefused(el, text) {
    if (!el || typeof el.closest !== "function" || el.closest(".watson-root")) return false;
    const host = el.parentElement;
    if (!host || typeof document === "undefined" || !document.createElement) return true;
    let msg = host.querySelector(".watson-undo-msg");
    if (!msg) {
      msg = document.createElement("span");
      msg.className = "watson-undo-msg";
      msg.setAttribute("role", "alert");
      el.insertAdjacentElement("afterend", msg);
    }
    msg.textContent = text; // textContent: the server message is never markup
    return true;
  }

  const FLASH_MS = 1800;
  // "Wrote:" link: reveal the section, scroll to the item, flash it. A row that is not drawn (a
  // filtered or paged timeline) leaves the section itself in view.
  function watsonJump(el) {
    const kind = el.dataset.wKind;
    const id = el.dataset.wId;
    const sec = SECTION[kind];
    if (!sec) return;
    if (typeof revealSection === "function") revealSection(sec);
    const mark = Array.from(document.querySelectorAll("[data-w-mark]")).find((m) => m.dataset.wMark === kind + ":" + id);
    const target = (mark && (mark.closest(".finding, .step-row, .ev-row, label") || mark)) || document.getElementById(sec);
    if (!target) return;
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.classList.add("watson-flash");
    setTimeout(() => target.classList.remove("watson-flash"), FLASH_MS);
  }

  window.watsonMarksSet = watsonMarksSet;
  window.watsonMarkHtml = watsonMarkHtml;
  window.watsonUndoTarget = watsonUndoTarget;
  window.watsonMarkReportSlots = watsonMarkReportSlots;
  window.watsonJump = watsonJump;
  window.watsonSectionRefused = watsonSectionRefused;
})();
