// Pure value derivations: labels, keys, lookups and predicates (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// The cohesion rule here is mechanical rather than thematic -- each of these maps data to a scalar
// (a label, a storage key, a boolean, a small record) with no DOM reach and no shared dashboard
// state. Several take an ELEMENT as an argument (swCanvasXY, paletteVisible, isSectionDataOpen,
// stabHidden, updateJobRow, veloTimeScopeBody); receiving a node is not the same as reaching for
// one, and it is what makes them testable against a stub.

// 1–2 letter initials for the assignee chip: first+last initial for a full name, else first two chars.
function _workflowInitials(name) {
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function pbLocalStats(tasks) {
  const total = tasks.length, done = tasks.filter(t => t.status === "done").length;
  return { total, done, completionPct: total ? Math.round(done / total * 100) : 0 };
}

// --- Push findings to a ticket system (#297) -------------------------------------
// `target` is the route segment — "jira" or "servicenow". Both routes are idempotent per
// finding: a re-push UPDATES the ticket the Companion already opened rather than duplicating it.
function ticketLabel(target) { return target === "jira" ? "Jira" : "ServiceNow"; }

// Read the run form's time-scope control into the request body shape the server expects.
// Returns undefined for "All time" (the default) so an unscoped run is byte-identical to before.
// The datetime-local inputs are wall-clock with no zone, so they're read as UTC to match the label
// (and the visible "UTC" badges beside them). NOTE: appending ":00" to make a full-second timestamp
// is only safe because these inputs have no `step` attribute and therefore never return seconds —
// if a future edit adds step="1" for sub-minute precision, this needs to stop assuming :00.
// veloTimeScopeBody also returns undefined when mode is "custom" but no start date has been entered
// yet — that is NOT "All time" and must never be treated as one; see veloTimeScopeIncomplete below,
// which both the preview and the launch path check separately since this return value alone can't
// distinguish the two cases.
function veloTimeScopeBody(form) {
  const mode = form.querySelector(".velo-timescope").value;
  if (!mode) return undefined;
  if (mode !== "custom") return { preset: mode };
  const start = form.querySelector(".velo-ts-start").value;
  const end = form.querySelector(".velo-ts-end").value;
  if (!start) return undefined;
  return { start: start + ":00Z", ...(end ? { end: end + ":00Z" } : {}) };
}

// True when "custom range…" is selected but no start date has been entered — a half-finished
// scope that must never silently fall through to an unscoped ("All time") run. Without this check,
// an analyst who picks "custom", forgets the date, and clicks Run gets a fully unscoped hunt with no
// warning; the only trace is the ABSENCE of a "⏱ scoped" line on the resulting job card, which reads
// exactly like "no activity occurred" rather than "you forgot to set a date".
function veloTimeScopeIncomplete(form) {
  return form.querySelector(".velo-timescope").value === "custom" && !form.querySelector(".velo-ts-start").value;
}

// Resolve which CONFIGURED tool handles a file extension (server preference order), from /tools/status.
function toolForExt(ext, status) {
  const t = (status && status.tools || []).find((x) => x.configured && (x.extensions || []).includes(ext));
  return t ? t.id : null;
}

function suggestToolForExt(ext, status) {
  const t = (status && status.tools || []).find((x) => (x.extensions || []).includes(ext));
  return t ? t.id : null;
}

// Every CONFIGURED tool claiming this extension, not just the first. SO-CRATES and a local
// Suricata run different rulesets, so an analyst may legitimately want both verdicts.
function toolsForExt(ext, status) {
  return ((status && status.tools) || []).filter((t) => t.configured && (t.extensions || []).includes(ext));
}

function jobMenuView(j) {
  const cancel = (j.status === "running" || j.status === "queued") && j.cancellable;
  const resume = j.resumable && (j.status === "interrupted" || (j.status === "failed" && j.failure && j.failure.retryable));
  const progress = j.progress ? ` ${j.progress.done}/${j.progress.total}` : "";
  const speed = j.throughputPerSecond ? ` · ${Number(j.throughputPerSecond).toFixed(1)}/s` : "";
  const eta = j.etaAt ? ` · ETA ${new Date(j.etaAt).toLocaleTimeString()}` : "";
  const checkpoint = j.lastCheckpoint ? ` · durable checkpoint ${j.lastCheckpoint.progress.done}/${j.lastCheckpoint.progress.total}` : "";
  const warnings = Array.isArray(j.warnings) && j.warnings.length ? ` · ${j.warnings.length} warning(s)` : "";
  const detail = j.detail || progress || j.error ? `${j.detail || j.error || ""}${progress}${speed}${eta}${checkpoint}${warnings}` : "";
  return { job: j, cancel, resume, detail };
}

function updateJobRow(row, view) {
  const status = row.querySelector(".job-st");
  const detail = row.querySelector(".job-detail");
  row.querySelector(".job-kind").textContent = view.job.kind;
  row.querySelector(".job-label").textContent = view.job.label || "";
  status.className = `job-st job-${view.job.status}`;
  status.textContent = view.job.status;
  detail.textContent = view.detail;
  detail.style.display = view.detail ? "" : "none";
}

function deepPassResultKey(cid) { return `dfir.deepPassResult:${cid}`; }

function swCanvasXY(e, canvas) {
  const rect = canvas.getBoundingClientRect();
  return {
    x: (e.clientX - rect.left) * (canvas.width / rect.width),
    y: (e.clientY - rect.top) * (canvas.height / rect.height),
  };
}

// Real navigable URL for a "cited event" badge (issue #222 follow-up) — without a genuine href,
// browsers won't offer "Open link in new tab/window" on right-click, only a plain non-link
// context menu. Left-click is still intercepted (see the delegated .ev-jump handlers) and jumps
// in place; opening this URL fresh reloads the case then jumpToEventFromHash() finishes the jump.
function eventDeepLink(caseId, id) {
  return `?caseId=${encodeURIComponent(caseId)}#event=${encodeURIComponent(id)}`;
}

function rvStatusLabel(workflow) {
  const status = workflow?.status || "draft";
  return status === "peer-review" ? "Peer review" : status[0].toUpperCase() + status.slice(1);
}

function analysisRunLabel(run) {
  const model = run.configuration?.provider
    ? ` · ${run.configuration.provider}${run.configuration.model ? "/" + run.configuration.model : ""}`
    : "";
  return `${run.kind}${model} · ${new Date(run.startedAt).toLocaleString()}`;
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",", 2)[1] || "");
    r.onerror = () => reject(new Error("read failed"));
    r.readAsDataURL(file);
  });
}

// display:none / detached elements have no client rects; offsetParent would report the same for
// these but lies about position:fixed ancestors, and the toolbar may end up inside one.
function paletteVisible(el) {
  return !!el && el.getClientRects().length > 0;
}

// Panel labels double as their own keywords, so "swimlane" or "kill chain" finds the section
// even though every label is prefixed with the same "Go to".
function paletteSectionKeywords(label) {
  return label.toLowerCase().split(/[^a-z0-9]+/).filter(w => w.length > 1);
}

// A few sections only make sense once the case actually holds the evidence they read (e.g.
// Memory Next Steps needs Volatility/Rekall events). Those carry a data-gate-open attribute
// that their own render path sets to "1"; an absent attribute means the section has no gate.
// Both conditions must hold to show it: the user hasn't hidden it AND its data exists.
function isSectionDataOpen(el) {
  const gate = el.dataset.gateOpen;
  return gate === undefined || gate === "1";
}

// Deliberately attribute-based, not offsetParent-based: this runs while the modal is still
// closed (openSettingsModal sets the mode before adding .open), when nothing has a layout box.
function stabHidden(btn, mode) {
  return mode === "essential" && !btn.hasAttribute("data-essential");
}

// ── Generic step rendering (every non-AI step) ──
function wizFieldId(envKey) { return "wizf-" + envKey; }

function ntfChannelToBody(ch) {
  const body = { type: ch.type, name: ch.name, enabled: ch.enabled, minSeverity: ch.minSeverity, events: ch.events };
  if (ch.type === "email" && ch.smtp) {
    body.smtp = { host: ch.smtp.host, port: ch.smtp.port, secure: !!ch.smtp.secure, from: ch.smtp.from, to: ch.smtp.to, username: ch.smtp.username || "", password: "" };
    if (ch.smtp.rejectUnauthorized !== undefined) body.smtp.rejectUnauthorized = ch.smtp.rejectUnauthorized;
  } else if (ch.type === "telegram" && ch.telegram) {
    body.telegram = { botToken: "", chatId: ch.telegram.chatId }; // blank token → server keeps the saved (redacted) value
  } else {
    body.webhookUrl = ""; // blank → server keeps the saved (redacted) URL
  }
  return body;
}

// Turn the chats the war-room bot is bound to into what the Chat ID box shows: the first as a
// pre-filled value, all of them as pickable options labelled with the case each is bound to. The
// label carries the case because a bare chat id is unrecognisable — "12345678" tells you nothing,
// "12345678 — bound to demo" tells you which conversation it is.
function ntfChatPrefill(chats) {
  const list = Array.isArray(chats) ? chats.filter((c) => c && c.chatId) : [];
  return {
    value: list.length ? String(list[0].chatId) : "",
    options: list.map((c) => ({
      value: String(c.chatId),
      label: c.caseId ? `${c.chatId} — bound to ${c.caseId}` : String(c.chatId),
    })),
  };
}

function ntfEventsSummary(ev) {
  const on = [];
  if (ev.critical_finding) on.push("findings");
  if (ev.playbook_update) on.push("playbook");
  if (ev.milestone) on.push("milestones");
  if (ev.mention) on.push("mentions");
  return on.length ? on.join(", ") : "nothing";
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirValues = {
  _workflowInitials,
  pbLocalStats,
  ticketLabel,
  toolForExt,
  suggestToolForExt,
  toolsForExt,
  jobMenuView,
  updateJobRow,
  deepPassResultKey,
  swCanvasXY,
  eventDeepLink,
  rvStatusLabel,
  analysisRunLabel,
  fileToBase64,
  paletteVisible,
  paletteSectionKeywords,
  isSectionDataOpen,
  stabHidden,
  wizFieldId,
  veloTimeScopeBody,
  veloTimeScopeIncomplete,
  ntfChannelToBody,
  ntfChatPrefill,
  ntfEventsSummary,
};
