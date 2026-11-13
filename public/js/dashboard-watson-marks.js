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

  // The ids one applied proposal marks: a finding/step id, a report field, every held event row.
  function idsOf(p) {
    if (p.kind === "event_promote") return (p.events || []).map((e) => e.id);
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
    return (
      `<span class="watson-mark" data-w-mark="${escAttr(kind + ":" + id)}" title="${escAttr("Added by Watson, approved by " + who)}">Watson</span>` +
      (p
        ? `<button type="button" class="watson-mini watson-undo" data-act="watsonAct" data-w-verb="undo" data-pid="${escAttr(p.id)}" title="Undo what Watson wrote">Undo</button>`
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
      el.innerHTML = REPORT_FIELDS.includes(f) && marked[f] ? watsonMarkHtml("report", f, {}) : "";
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
})();
