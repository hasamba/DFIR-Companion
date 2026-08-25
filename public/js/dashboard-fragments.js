// HTML fragment builders: data in, escaped markup string out (#415).
//
// NOT AN ES MODULE, AND NOT DEFERRED. See js/dashboard-escape.js for the whole argument; the
// short form is that dashboard.html's inline script calls these by bare name at 427 sites, one of
// them while the page is still parsing, so the declarations have to be real globals that exist
// before <script nonce> at line 6538 runs.
//
// The same cohesion rule js/diagnostics-panel.js established in #414 -- these build STRINGS from a
// data object, touching no DOM, no fetch and no shared dashboard state -- applied to the other 16
// renderers that met it. They belong to unrelated panels (tickets, VQL, jobs, compliance, the
// cockpit, review, the setup wizard, notifications); what they have in common is the contract, and
// the contract is what makes them movable and testable.
//
// esc/escAttr come from js/dashboard-escape.js and cockpitAge from js/dashboard-time.js, both
// resolved as globals at CALL time, so the tag order in <head> is documentation rather than a
// requirement.

// The Executive Summary / Narrative Timeline body: one escaped <p> per paragraph, with the split
// done by proseParagraphs in js/dashboard-text.js (resolved as a global at CALL time, like esc).
//
// The container is the caller's: `.prose` in the markup carries the measure and the leading, so a
// panel can wrap this in whatever it already has. Empty text returns "" rather than an empty <p>,
// so a panel with nothing to show collapses instead of leaving a blank line behind.
function proseHtml(text) {
  return proseParagraphs(text).map((p) => `<p>${esc(p)}</p>`).join("");
}

// Highlight @name tokens as chips in a comment body. esc() first (so the raw text can never
// inject markup), then the @token regex only ever matches already-escaped, HTML-safe text.
function mentionHtml(text) {
  // `@` must not follow a word/handle char so emails/IOCs (bob@example.com) aren't chipped as
  // mentions, and a handle must start AND end alphanumeric so trailing sentence punctuation
  // ("ping @bob.") stays outside the chip. Runs over esc()'d text; keep in sync with
  // MENTION_RE in analysis/comments.ts.
  return esc(text).replace(/(?<![A-Za-z0-9._@-])@([a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?)/g, '<span class="mention-chip">@$1</span>');
}

// Per-finding ticket-push chips (#297). Always emitted; CSS keeps each one hidden until the
// matching integration reports itself configured, so a late /jira/status answer still reveals
// the chips on rows that rendered before it arrived.
function ticketPushChips(id) {
  const fid = escAttr(String(id));
  return `<button class="jira-push-btn" data-jira-fid="${fid}" title="File this finding as a Jira issue. Re-pushing UPDATES the issue it created instead of filing a duplicate.">Jira</button>` +
    `<button class="snow-push-btn" data-snow-fid="${fid}" title="Open this finding as a ServiceNow incident. Re-pushing UPDATES the incident it opened instead of opening a duplicate.">SNow</button>`;
}

function renderVqlRows(j) {
  const rows = j.rows || [];
  if (!rows.length) return "<div data-safe-style='color:var(--text-muted);font-size:12px'>0 rows.</div>";
  const cols = [...new Set(rows.flatMap((r) => (r && typeof r === "object" ? Object.keys(r) : [])))].slice(0, 12);
  const cell = (v) => esc(v == null ? "" : (typeof v === "object" ? JSON.stringify(v) : String(v)));
  const head = cols.map((col) => `<th>${esc(col)}</th>`).join("");
  const trs = rows.slice(0, 200).map((r) => `<tr>${cols.map((col) => `<td>${cell(r && r[col])}</td>`).join("")}</tr>`).join("");
  return `<div class="vql-result-wrap"><table class="vql-result"><thead><tr>${head}</tr></thead><tbody>${trs}</tbody></table></div>`
    + `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-top:4px">${esc(j.total)} row(s)${j.truncated ? " (capped)" : ""}${cols.length === 12 ? " · first 12 columns" : ""}</div>`;
}

// --- Ask the LLM about this case ----------------------------------------------
function askStatusBadge(s) {
  const m = { answered: ["#1e3a2a", "#6bcB77"], partial: ["#3a3320", "#ffd93b"], unknown: ["#2a2f3a", "#9aa4b2"] };
  const [bg, fg] = m[s] || m.unknown;
  return `<span data-safe-style="background:${bg};color:${fg};padding:1px 8px;border-radius:10px;font-size:11px">${esc(s || "unknown")}</span>`;
}

function jobRowHtml(view) {
  const j = view.job;
  const cancel = view.cancel ? `<button class="job-cancel" data-job="${esc(j.id)}" title="Cancel this job">✕ Cancel</button>` : "";
  const resume = view.resume ? `<button class="job-resume" data-job="${esc(j.id)}" title="Resume from the last durable checkpoint">↻ Resume</button>` : "";
  return `<div class="job-row" data-job-id="${esc(j.id)}"><span class="job-kind">${esc(j.kind)}</span>`
    + `<span class="job-label">${esc(j.label || "")}</span>`
    + `<span class="job-st job-${esc(j.status)}">${esc(j.status)}</span>`
    + cancel + resume
    + `<span class="job-detail"${view.detail ? "" : ' data-safe-style="display:none"'}>${esc(view.detail)}</span></div>`;
}

function qaSpan(type, val, ctx) {
  const evid = ctx && ctx.evid != null ? ` data-evid="${escAttr(String(ctx.evid))}"` : "";
  const iocid = ctx && ctx.iocid != null ? ` data-iocid="${escAttr(String(ctx.iocid))}"` : "";
  return `<span class="qa-val" data-vtype="${escAttr(type)}" data-val="${escAttr(val)}"${evid}${iocid}>${esc(val)}</span>`;
}

// Numbered, clickable citation footnotes for the findings an AI-suggested hunt names as its
// trigger (issue #222). Mirrors citeEvents but jumps to a Finding card (reuses the existing
// .finding-jump / jumpToFinding delegated-click mechanism).
function citeFindings(ids) {
  const list = Array.from(new Set((ids || []).map(String).filter(Boolean)));
  if (!list.length) return "";
  return list.map((id, i) =>
    `<a class="finding-jump cite-badge" data-fid="${escAttr(id)}" title="Jump to finding ${escAttr(id)}">[${i + 1}]</a>`
  ).join(" ");
}

function complianceDueBadge(deadline) {
  if (!deadline) return "";
  const cls = deadline.status === "overdue" ? "cmp-due-overdue"
    : deadline.status === "due-soon" ? "cmp-due-soon" : "cmp-due-open";
  const label = deadline.status === "overdue" ? "OVERDUE"
    : `${esc(deadline.remainingDays)}d left`;
  return `<span class="cmp-due ${cls}">${label}</span> due ${esc(String(deadline.dueAt).slice(0, 10))}`;
}

function ceChip(value, kind, auto) {
  return `<span class="ce-chip${auto ? " auto" : ""}" title="${auto ? "auto-discovered in the investigation — checked automatically" : "remove with ×"}">${esc(value)}`
    + (auto ? " <small>auto</small>" : ` <span class="x" data-kind="${escAttr(kind)}" data-val="${escAttr(value)}">×</span>`) + "</span>";
}

// Clickable links to the underlying evidence (screenshot or imported CSV). Each
// opens the artifact in a new tab via GET /cases/:id/evidence/:file.
function evidenceLinks(caseId, files) {
  const list = Array.from(new Set((files || []).filter(Boolean)));
  if (!caseId || !list.length) return "";
  const links = list.map(fn =>
    `<a href="/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(fn)}" ` +
    `target="_blank" rel="noopener" data-safe-style="color:var(--accent)" title="Open evidence: ${escAttr(fn)}">📎 ${esc(fn)}</a>`
  ).join(" · ");
  return `<br><small data-safe-style="color:var(--text-muted)">evidence: ${links}</small>`;
}

function cockpitCardControls(card, parked) {
  const id = escAttr(card.id);
  const view = `<button data-act="cockpitOpenTarget" data-id="${id}">Open</button>`;
  if (card.kind !== "lead" && card.kind !== "hypothesis") return view;
  if (parked) {
    return `${view}<button data-act="cockpitAction" data-cockpit-action="restore" data-id="${id}">Restore</button>`;
  }
  const pin = card.pinned
    ? `<button data-act="cockpitAction" data-cockpit-action="unpin" data-id="${id}">Unpin</button>`
    : `<button data-act="cockpitAction" data-cockpit-action="pin" data-id="${id}">Pin</button>`;
  return `${view}${pin}` +
    `<button data-act="cockpitAction" data-cockpit-action="dismiss" data-id="${id}">Dismiss</button>` +
    `<button data-act="cockpitAction" data-cockpit-action="defer" data-id="${id}">Defer</button>` +
    `<button data-act="cockpitAction" data-cockpit-action="assign" data-id="${id}">${card.assignee ? "Reassign" : "Assign"}</button>`;
}

function cockpitCardHtml(card, parked) {
  const severity = card.severity || "Info";
  const evidence = (card.evidenceIds || []).slice(0, 3).map(id =>
    `<button class="now-evidence" data-act="cockpitJumpEvent" data-id="${escAttr(id)}" title="Open exact supporting event">${esc(id)}</button>`
  ).join("");
  const meta = [
    card.confidence !== undefined ? `${esc(String(card.confidence))}% confidence` : "",
    card.assignee ? `owner: ${esc(card.assignee)}` : "",
    card.deferredUntil ? `deferred until ${esc(new Date(card.deferredUntil).toLocaleString())}` : "",
    card.occurredAt ? cockpitAge(card.occurredAt) : "",
  ].filter(Boolean).map(item => `<span>${item}</span>`).join("");
  return `<article class="now-card sev-${escAttr(severity)}" data-cockpit-id="${escAttr(card.id)}">` +
    `<div class="now-card-title">${card.pinned ? `<span class="now-pin" title="Pinned">◆</span>` : ""}<strong>${esc(card.title)}</strong></div>` +
    (card.summary ? `<div class="now-card-summary">${esc(card.summary)}</div>` : "") +
    (card.action ? `<div class="now-card-action">Next → ${esc(card.action)}</div>` : "") +
    `<div class="now-card-meta">${meta}${evidence}${cockpitCardControls(card, parked)}</div>` +
    `</article>`;
}

function rvAnnotationRows(workflow) {
  const annotations = workflow?.annotations || [];
  if (!annotations.length) return "";
  return `<div data-safe-style="margin:5px 0 0 12px;color:var(--text-muted)">${annotations.map(a => {
    const state = a.resolvedAt ? `resolved by ${esc(a.resolvedByDisplayName || "investigator")}` : "unresolved";
    const resolve = a.resolvedAt ? "" : ` <button data-rv-resolve="${escAttr(a.id)}" data-version="${escAttr(workflow.versionId)}" data-safe-style="font-size:10px;padding:1px 5px">Resolve</button>`;
    return `<div>↳ ${esc(a.category)} · ${esc(a.impact)} · ${esc(a.targetType)}:${esc(a.targetId)} — ${esc(a.message)} (${state})${resolve}</div>`;
  }).join("")}</div>`;
}

// f.browse turns the field into a path picker (the string is the browse modal's title) and
// f.download adds the "download the latest release" button beside it — the same two controls
// Settings → Integrations has on the Velociraptor paths, which the wizard was missing.
// wirePathBrowseControls (js/dashboard-velo-fs-browse.js) binds them from these data-attributes.
function wizRenderFields(fields) {
  return fields.map(f => {
    const id = wizFieldId(f.key);
    const ph = f.secret ? "(not set)" : (f.hint ? "" : "");
    const type = f.secret ? 'type="password" autocomplete="new-password"' : 'autocomplete="off"';
    const input = '<input id="' + id + '" ' + type + ' placeholder="' + esc(ph) + '" />';
    const control = !f.browse ? input :
      '<div class="wiz-combo">' + input +
      '<button type="button" class="wiz-btn secondary" data-wiz-browse="' + escAttr(id) +
      '" data-wiz-browse-title="' + escAttr(f.browse) + '">Browse…</button>' +
      (f.download ? '<button type="button" class="wiz-btn secondary" data-wiz-download="' + escAttr(id) +
        '" title="Fetches the current Velociraptor release for this server\u2019s OS from the official GitHub releases and fills this field with the saved path. Runs only when you click it.">\u2B07 Download latest</button>' : '') +
      '</div>' +
      (f.download ? '<div class="wiz-modelhint" data-wiz-download-msg="' + escAttr(id) + '"></div>' : '');
    return '<div class="wiz-field"><label>' + esc(f.label) +
      (f.hint ? '<span class="wiz-hint">' + esc(f.hint) + '</span>' : '') +
      '</label>' + control + '</div>';
  }).join("");
}

// Case Statistics panel (#241) — totals/source-breakdown/import-velocity for the current case.
function caseStatsBarChart(days) {
  if (!days.length) return `<div data-safe-style="color:#7e8aa0">no imports yet</div>`;
  const barW = 16, gap = 3, h = 46;
  const maxRows = Math.max(1, ...days.map(d => d.rows));
  const bars = days.map((d, i) => {
    const barH = Math.max(2, Math.round((d.rows / maxRows) * (h - 12)));
    const x = i * (barW + gap);
    return `<rect x="${x}" y="${h - barH}" width="${barW}" height="${barH}" rx="2" fill="#7ec8e3">
      <title>${esc(d.date)}: ${d.imports} import${d.imports !== 1 ? "s" : ""}, ${d.rows.toLocaleString()} rows</title>
    </rect>`;
  }).join("");
  const w = days.length * (barW + gap) - gap;
  return `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" data-safe-style="max-width:100%">${bars}</svg>
    <div data-safe-style="display:flex;justify-content:space-between;color:#7e8aa0;font-size:10px;margin-top:2px">
      <span>${esc(days[0].date)}</span><span>${esc(days[days.length - 1].date)}</span>
    </div>`;
}

function ntfTargetSummary(ch) {
  if (ch.type === "email" && ch.smtp) return `${esc(ch.smtp.host)}:${esc(String(ch.smtp.port))} → ${esc((ch.smtp.to || []).join(", "))}${ch.smtp.hasPassword ? " 🔑" : ""}`;
  // usesEnvBotToken = borrowed from the war-room bot's DFIR_TELEGRAM_BOT_TOKEN rather than typed
  // here. Named explicitly so the channel doesn't look mis-configured to whoever reads it next.
  if (ch.type === "telegram" && ch.telegram) return `${ch.telegram.hasBotToken ? (ch.telegram.usesEnvBotToken ? "token from .env" : "token configured") : "<span data-safe-style='color:var(--tag-red-text)'>no token</span>"} → chat: ${esc(ch.telegram.chatId || "?")}`;
  return ch.hasWebhookUrl ? "webhook configured" : "<span data-safe-style='color:var(--tag-red-text)'>no webhook URL</span>";
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirFragments = {
  proseHtml,
  mentionHtml,
  ticketPushChips,
  renderVqlRows,
  askStatusBadge,
  jobRowHtml,
  qaSpan,
  citeFindings,
  complianceDueBadge,
  ceChip,
  evidenceLinks,
  cockpitCardControls,
  cockpitCardHtml,
  rvAnnotationRows,
  wizRenderFields,
  caseStatsBarChart,
  ntfTargetSummary,
};
