// Watson's proposal cards (finding, next step, report text, held events), the "Wrote:" line that ends
// a turn, and the paused-reactions banner. Pure HTML builders, no state; dashboard-watson-view.js
// calls them by name. Question proposals stay in the view file.
//
// Every model and evidence string, paste lines included, goes through esc()/escAttr()
// (dashboard-escape.js). Actions ride on data-act="watsonAct" + data-w-verb.
(function () {
  const HELD_SHOWN = 5;
  const FIELD_LABEL = { conclusions: "Conclusions", investigationLimitations: "Investigation limitations" };
  const PAUSED = {
    presidio: "Presidio is holding a value for approval",
    limit: "the Watson cost or token limit was reached",
    errors: "several reactions failed in a row",
  };
  const TITLE = {
    finding_new: "New finding",
    finding_update: "Finding update",
    next_step_new: "Next step",
    report_text: "Report text",
    event_promote: "Held events",
  };

  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;

  // Pending: Apply / Reject. Applied: Undo. A promotion that was undone can be applied again.
  function verbsHtml(p) {
    if (p.status === "pending") return btn(p.id, "apply", "Apply") + btn(p.id, "reject", "Reject");
    if (p.status === "applied") return btn(p.id, "undo", "Undo");
    return p.kind === "event_promote" && p.status === "undone" ? btn(p.id, "apply", "Apply again") : "";
  }

  const pre = (text) => `<pre class="watson-pre">${esc(text)}</pre>`;

  function findingBody(p) {
    const f = p.after || {};
    const ids = Array.isArray(f.relatedEventIds) ? f.relatedEventIds : [];
    const cited = typeof citeEvents === "function" ? citeEvents(ids) : "";
    const lines = Array.isArray(p.pasteLineEvents) ? p.pasteLineEvents : [];
    return (
      `<div><span class="sev-${esc(f.severity)}">${esc(f.severity)}</span> <strong>${esc(f.title)}</strong></div>` +
      `<div class="watson-text">${esc(f.description)}</div>` +
      (cited ? `<div class="watson-why">cited events: ${cited}</div>` : "") +
      (lines.length ? `<div class="watson-why">cited paste lines</div>` + pre(lines.map((e) => e.description).join("\n")) : "") +
      keptHtml(p)
    );
  }

  // An undone finding whose created rows other findings cite: those rows stayed in the timeline.
  function keptHtml(p) {
    const kept = p.status === "undone" && Array.isArray(p.keptEventIds) ? p.keptEventIds : [];
    if (!kept.length) return "";
    const cited = typeof citeEvents === "function" ? citeEvents(kept) : "";
    const n = kept.length === 1 ? "1 event" : `${esc(String(kept.length))} events`;
    return `<div class="watson-why">Removed the finding; kept ${n} because other findings cite ${kept.length === 1 ? "it" : "them"}${cited ? `: ${cited}` : ""}</div>`;
  }

  function stepBody(p) {
    const s = p.after || {};
    return (
      `<div><span class="step-priority">${esc(String(s.priority || "").toUpperCase())}</span> <strong>${esc(s.action)}</strong></div>` +
      (s.rationale ? `<div class="watson-why">${esc(s.rationale)}</div>` : "") +
      (s.pointer ? `<div class="watson-why">→ ${esc(s.pointer)}</div>` : "")
    );
  }

  function reportBody(p) {
    return `<div class="watson-lbl">${esc(FIELD_LABEL[p.field] || p.field)}</div><div class="watson-text">${esc(p.after)}</div>`;
  }

  function heldBody(p) {
    const rows = Array.isArray(p.events) ? p.events : [];
    const more = rows.length - HELD_SHOWN;
    return (
      `<div>${esc(String(rows.length))} rows held for you${p.status === "pending" ? " · Waiting for your approval" : ""}</div>` +
      pre(rows.slice(0, HELD_SHOWN).map((e) => `[${e.severity}] ${e.description}`).join("\n")) +
      (more > 0 ? `<div class="watson-why">and ${esc(String(more))} more</div>` : "")
    );
  }

  const BODY = { finding_new: findingBody, finding_update: findingBody, next_step_new: stepBody, report_text: reportBody, event_promote: heldBody };

  // uiError: the server's message when this card's action was refused (a 409 on undo).
  function watsonCardHtml(p) {
    if (p.kind === "velo_launch" && typeof watsonVeloCardHtml === "function") return watsonVeloCardHtml(p);
    const body = Object.prototype.hasOwnProperty.call(BODY, p.kind) ? BODY[p.kind](p) : "";
    return (
      `<div class="watson-prop" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">${esc(TITLE[p.kind] || "Proposal")} · ${esc(p.status)}</div>` +
      body +
      (p.uiError ? `<div class="watson-why watson-err">${esc(p.uiError)}</div>` : "") +
      `<div>${verbsHtml(p)}</div></div>`
    );
  }

  const link = (kind, id, label) =>
    `<button type="button" class="watson-link" data-act="watsonAct" data-w-verb="jump" data-w-kind="${escAttr(kind)}" data-w-id="${escAttr(id)}">${label}</button>`;

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  // The rows an applied promotion actually added (a row the case already held is not Watson's).
  const landedIds = (p) => (Array.isArray(p.createdEventIds) ? p.createdEventIds : []);

  // "Wrote: 2 findings · 1 next step · 3 events · Report § Conclusions": each part jumps to its item.
  function watsonWroteHtml(proposals) {
    const done = (proposals || []).filter((p) => p.status === "applied");
    const of = (...kinds) => done.filter((p) => kinds.includes(p.kind));
    const findings = of("finding_new", "finding_update");
    const steps = of("next_step_new");
    const rowIds = of("event_promote").flatMap(landedIds);
    const parts = [];
    if (findings.length) parts.push(link("finding", findings[0].targetId, plural(findings.length, "finding", "findings")));
    if (steps.length) parts.push(link("next_step", steps[0].targetId, plural(steps.length, "next step", "next steps")));
    if (rowIds.length) parts.push(link("event", rowIds[0], plural(rowIds.length, "event", "events")));
    of("report_text").forEach((p) => parts.push(link("report", p.field, `Report § ${esc(FIELD_LABEL[p.field] || p.field)}`)));
    return parts.length ? `<div class="watson-wrote"><b>Wrote:</b> ${parts.join(" · ")}</div>` : "";
  }

  // One line, only for a reason the server sets.
  function watsonPausedHtml(reason) {
    return Object.prototype.hasOwnProperty.call(PAUSED, reason)
      ? `<div class="watson-turn watson-warn watson-paused">Watson paused its reactions: ${esc(PAUSED[reason])}. Send a message to resume.</div>`
      : "";
  }

  window.watsonCardHtml = watsonCardHtml;
  window.watsonWroteHtml = watsonWroteHtml;
  window.watsonPausedHtml = watsonPausedHtml;
})();
