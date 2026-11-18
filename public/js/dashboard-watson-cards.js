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
    presidio: "Presidio has a value that waits for approval",
    limit: "Watson reached its cost or token limit",
    errors: "many reactions failed, one after the other",
  };
  const TITLE = {
    finding_new: "New finding",
    finding_update: "Finding update",
    next_step_new: "Next step",
    next_step_update: "Next step change",
    finding_review: "Finding change", // #2682
    report_text: "Report text",
    event_promote: "Held events",
  };

  const btn = (pid, verb, label) =>
    `<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="${verb}" data-pid="${escAttr(pid)}">${label}</button> `;

  // What Apply does, per kind: the button names it, so the analyst knows Apply writes to the case only.
  const APPLY = {
    finding_new: ["Add finding", "the finding"],
    finding_update: ["Update finding", "the finding update"],
    next_step_new: ["Add next step", "the next step"],
    next_step_update: ["Change next step", "the next step change"],
    finding_review: ["Change finding", "the finding change"],
    question_new: ["Add question", "the question"],
    question_update: ["Update question", "the question update"],
    report_text: ["Add to report", "the report text"],
    event_promote: ["Add rows", "the rows"],
    cs_search: ["Run search", "the search"], // #2666
  };
  const applyLabel = (kind) => (APPLY[kind] ? APPLY[kind][0] : "Apply");
  const applyNoun = (kind) => (APPLY[kind] ? APPLY[kind][1] : "this card");
  const HOST_SAFE = `<div class="watson-meta">This adds it to the case. Nothing changes on the host.</div>`;

  // Pending: Apply / Reject. Applied: Undo. A promotion that was undone can be applied again.
  // A pending super-timeline promotion is an unfinished one: Apply only (the server refuses Reject).
  function verbsHtml(p) {
    if (p.kind === "event_promote" && p.source === "supertimeline" && p.status === "pending") return HOST_SAFE + btn(p.id, "apply", applyLabel(p.kind));
    if (p.status === "pending") return HOST_SAFE + btn(p.id, "apply", applyLabel(p.kind)) + btn(p.id, "reject", "Reject");
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
    return `<div class="watson-why">Watson removed the finding. It kept ${n}, because other findings cite ${kept.length === 1 ? "it" : "them"}${cited ? `: ${cited}` : ""}</div>`;
  }

  function stepBody(p) {
    const s = p.after || {};
    return (
      `<div><span class="step-priority">${esc(String(s.priority || "").toUpperCase())}</span> <strong>${esc(s.action)}</strong></div>` +
      (s.rationale ? `<div class="watson-why">${esc(s.rationale)}</div>` : "") +
      (s.pointer ? `<div class="watson-why">→ ${esc(s.pointer)}</div>` : "")
    );
  }

  // A change to a step already in the case: done (it leaves the list) or a new priority, with Watson's why.
  function stepUpdateBody(p) {
    const s = p.before || {};
    const change = p.after
      ? `Priority ${esc(String(s.priority || "").toUpperCase())} → ${esc(String(p.after.priority || "").toUpperCase())}`
      : "Done: it leaves the next steps";
    return (
      `<div><strong>${esc(s.action)}</strong></div>` +
      `<div class="watson-step-change">${change}</div>` +
      (p.why ? `<div class="watson-why">${esc(p.why)}</div>` : "")
    );
  }

  // #2682: Watson's demotion or dismissal of a synthesis finding, with its reason and cited events.
  // A High or Critical one waits for the analyst even in Auto mode.
  function reviewBody(p) {
    const f = p.before || {};
    const change = p.action === "dismiss"
      ? "Dismiss: the cited events disprove it"
      : `Severity ${esc(f.severity)} → ${esc(p.severity)}`;
    const ids = Array.isArray(p.eventIds) ? p.eventIds : [];
    const cited = typeof citeEvents === "function" ? citeEvents(ids) : "";
    const held = p.status === "pending" && (f.severity === "High" || f.severity === "Critical");
    return (
      `<div><span class="sev-${esc(f.severity)}">${esc(f.severity)}</span> <strong>${esc(f.title)}</strong></div>` +
      `<div class="watson-step-change">${change}</div>` +
      (p.why ? `<div class="watson-why">${esc(p.why)}</div>` : "") +
      (cited ? `<div class="watson-why">cited events: ${cited}</div>` : "") +
      (held ? `<div class="watson-meta">This finding is High or Critical. Watson changes it only when you approve.</div>` : "")
    );
  }

  function reportBody(p) {
    return `<div class="watson-lbl">${esc(FIELD_LABEL[p.field] || p.field)}</div><div class="watson-text">${esc(p.after)}</div>`;
  }

  function heldBody(p) {
    const rows = Array.isArray(p.events) ? p.events : [];
    return (
      `<div>${esc(String(rows.length))} rows wait for you${p.status === "pending" ? " · Apply or reject them" : ""}</div>` +
      rowLines(rows)
    );
  }

  const rowLines = (rows) =>
    pre(rows.slice(0, HELD_SHOWN).map((e) => `[${e.severity}] ${e.description}`).join("\n")) +
    (rows.length > HELD_SHOWN ? `<div class="watson-why">and ${esc(String(rows.length - HELD_SHOWN))} more</div>` : "");

  // Rows from the raw super-timeline. Applied or undone: the rows that landed (landedRows, else the
  // created ids). Pending: nothing is confirmed, so the text names the cited rows and claims no promotion.
  function promotedBody(p) {
    const cited = Array.isArray(p.events) ? p.events : [];
    if (p.status === "pending") {
      return (
        `<div>Watson started to promote ${esc(String(cited.length))} super-timeline ${cited.length === 1 ? "row" : "rows"}. ` +
        `The promotion is not complete. Press Apply to finish it.</div>` +
        rowLines(cited)
      );
    }
    const landed = Array.isArray(p.landedRows) ? p.landedRows : null;
    const n = landed ? landed.length : landedIds(p).length || cited.length;
    const old = cited.length - n;
    return (
      `<div>Watson promoted ${esc(String(n))} super-timeline ${n === 1 ? "row" : "rows"} from its answer</div>` +
      (old > 0 ? `<div class="watson-why">${esc(String(old))} ${old === 1 ? "row was" : "rows were"} already in the case. Undo does not remove ${old === 1 ? "it" : "them"}.</div>` : "") +
      rowLines(landed || (landedIds(p).length ? [] : cited))
    );
  }

  const eventBody = (p) => (p.source === "supertimeline" ? promotedBody(p) : heldBody(p));

  const BODY = { finding_new: findingBody, finding_update: findingBody, next_step_new: stepBody, next_step_update: stepUpdateBody, finding_review: reviewBody, report_text: reportBody, event_promote: eventBody };

  // The title follows the source: a super-timeline promotion is not a held paste.
  const titleOf = (p) => (p.kind === "event_promote" && p.source === "supertimeline" ? "Promoted events" : TITLE[p.kind] || "Proposal");

  // uiError: the server's message when this card's action was refused (a 409 on undo).
  function watsonCardHtml(p) {
    if (p.kind === "velo_launch" && typeof watsonVeloCardHtml === "function") return watsonVeloCardHtml(p);
    if (p.kind === "cs_search" && typeof watsonCsCardHtml === "function") return watsonCsCardHtml(p); // #2666
    const body = Object.prototype.hasOwnProperty.call(BODY, p.kind) ? BODY[p.kind](p) : "";
    return (
      `<div class="watson-prop watson-prop-${escAttr(p.kind)} watson-prop-${escAttr(p.status)}" data-pid="${escAttr(p.id)}">` +
      `<div class="watson-lbl">${esc(titleOf(p))} · ${esc(p.status)}</div>` +
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
      ? `<div class="watson-turn watson-warn watson-paused">Watson stopped its reactions: ${esc(PAUSED[reason])}. Send a message to start them again.</div>`
      : "";
  }

  window.watsonCardHtml = watsonCardHtml;
  window.watsonApplyLabel = applyLabel;
  window.watsonApplyNoun = applyNoun;
  window.watsonWroteHtml = watsonWroteHtml;
  window.watsonPausedHtml = watsonPausedHtml;
})();
