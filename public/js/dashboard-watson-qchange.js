// Watson's question-change highlight in the chat. Two parts:
//  - A question update that Watson applied by itself (Auto mode) stays marked ("New change") until the
//    analyst clicks the card. Updates the analyst applied, or that still wait for approval, are not
//    marked: the analyst already saw those.
//  - Every question-update card marks the parts that changed (status, answer, pointer) in yellow and
//    shows the old status and answer on one "was:" line.
//
// Seen card ids are kept per case in this browser (localStorage, in memory when it is blocked). The
// first time a case is opened here, every update already in its chat counts as seen, so old history
// does not light up. dashboard-watson.js calls watsonQChangeSync on each render and routes the
// "qSeen" verb to watsonQChangeSeen; dashboard-watson-view.js calls watsonQChangeIsNew and
// watsonQChangeBody when it draws a question card.
//
// Every model and analyst string goes through esc() (dashboard-escape.js).
(function () {
  const AUTO_ACTOR = "Watson (Auto)"; // WATSON_AUTO_ACTOR in companion/src/analysis/ai/watson/autoApply.ts
  const KEY_PREFIX = "dfir.watson.qseen.";
  const KEEP = 500; // seen ids kept per case; the oldest drop first

  const memory = new Map(); // caseId -> Set of seen ids (the copy every read uses)
  let caseId = "";

  function readStored(id) {
    try {
      const raw = localStorage.getItem(KEY_PREFIX + id);
      if (raw === null) return null;
      const list = JSON.parse(raw);
      return Array.isArray(list) ? list.filter((x) => typeof x === "string") : [];
    } catch {
      return undefined; // blocked or broken store: memory only
    }
  }

  function writeStored(id, seen) {
    try {
      localStorage.setItem(KEY_PREFIX + id, JSON.stringify([...seen].slice(-KEEP)));
    } catch {
      /* a blocked store must not break the chat; memory still holds it */
    }
  }

  const watched = (p) => !!p && p.kind === "question_update" && p.status === "applied" && p.appliedBy === AUTO_ACTOR;

  // The case the chat shows and its proposals. A case seen here for the first time starts with every
  // update it already has marked as seen.
  function watsonQChangeSync(id, proposals) {
    caseId = String(id || "");
    if (!caseId || memory.has(caseId)) return;
    const stored = readStored(caseId);
    if (Array.isArray(stored)) return void memory.set(caseId, new Set(stored));
    const seen = new Set((Array.isArray(proposals) ? proposals : []).filter(watched).map((p) => p.id));
    memory.set(caseId, seen);
    if (stored === null) writeStored(caseId, seen);
  }

  function watsonQChangeIsNew(p) {
    const seen = memory.get(caseId);
    return !!seen && watched(p) && !seen.has(p.id);
  }

  // The "qSeen" verb: the analyst clicked a marked card. True when the mark was cleared.
  function watsonQChangeSeen(el) {
    const pid = el && el.dataset ? el.dataset.pid : "";
    const seen = memory.get(caseId);
    if (!pid || !seen || seen.has(pid)) return false;
    const next = new Set(seen);
    next.add(pid);
    memory.set(caseId, next);
    writeStored(caseId, next);
    return true;
  }

  const norm = (v) => String(v == null ? "" : v).trim();
  const mark = (changed, html) => (changed ? `<span class="watson-chg">${html}</span>` : html);

  // The card's status/answer line, pointer line and "was:" line. badge(status) draws a status badge.
  function watsonQChangeBody(p, badge) {
    const a = p.after || {};
    const b = p.kind === "question_update" && p.before ? p.before : null;
    const diff = (f) => !!b && norm(a[f]) !== norm(b[f]);
    const statusLine = `<div>${mark(diff("status"), badge(a.status))} ${mark(diff("answer"), esc(a.answer || ""))}</div>`;
    const pointer = a.pointer ? `<div class="watson-why">${mark(diff("pointer"), "→ " + esc(a.pointer))}</div>` : "";
    const was = b ? `<div class="watson-was">was: <s>${badge(b.status)} ${esc(b.answer || "unknown")}</s></div>` : "";
    return statusLine + pointer + was;
  }

  window.watsonQChangeSync = watsonQChangeSync;
  window.watsonQChangeIsNew = watsonQChangeIsNew;
  window.watsonQChangeSeen = watsonQChangeSeen;
  window.watsonQChangeBody = watsonQChangeBody;
})();
