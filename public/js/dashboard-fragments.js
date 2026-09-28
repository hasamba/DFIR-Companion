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
  // Always emitted, hidden when empty — see updateJobRow. The popover patches rows in place far
  // more often than it rebuilds them, and a span conditional on the FIRST render is a node the
  // patch path cannot find. Placed after the status and its buttons so the header line is exactly
  // what it was before the model existed; the CSS gives it the next line, above the detail.
  // #1601: modelLabel is the server's "sonnet → Sonnet 5" / "sonnet (last run: Sonnet 5)"; the bare
  // alias is the fallback for a row from a server that does not send one.
  const modelText = j.modelLabel || j.model || "";
  const model = `<span class="job-model"${modelText ? "" : ' data-safe-style="display:none"'}`
    + ` title="The AI model this job uses. After the arrow: the version that answered. Last run: the version this model answered with most recently.">${esc(modelText)}</span>`;
  // The progress bar (#1428), same rule as the model span: always emitted, hidden until the job
  // reports progress, so the in-place patch has a node to fill. jobBarPercent is a global from
  // js/dashboard-values.js, loaded before this file.
  const pct = jobBarPercent(j);
  const bar = `<span class="job-bar" role="progressbar" aria-label="Job progress" aria-valuemin="0" aria-valuemax="100"`
    + ` aria-valuenow="${pct === null ? 0 : pct}"${pct === null ? ' data-safe-style="display:none"' : ""}>`
    + `<span class="job-bar-fill" data-safe-style="width:${pct === null ? 0 : pct}%"></span></span>`;
  return `<div class="job-row" data-job-id="${esc(j.id)}"><span class="job-kind">${esc(j.kind)}</span>`
    + `<span class="job-label">${esc(j.label || "")}</span>`
    + `<span class="job-st job-${esc(j.status)}">${esc(j.status)}</span>`
    + cancel + resume + model + bar
    + `<span class="job-detail"${view.detail ? "" : ' data-safe-style="display:none"'}>${esc(view.detail)}</span>`
    // Always the LAST line of the row, below the detail, so every row reads the same way.
    + `<span class="job-when"${view.when ? "" : ' data-safe-style="display:none"'}>${esc(view.when || "")}</span>`
    + jobFilesHtml(j.files) + `</div>`;
}

// Every file a drop sweep covers, folded. The label counts them and the detail names only the last
// one processed, so without this list "drop import (24 files)" showed one name. The list is fixed
// at registration, so the in-place patch never needs to touch it.
function jobFilesHtml(files) {
  if (!Array.isArray(files) || !files.length) return "";
  const n = files.length;
  return `<details class="job-files"><summary>${n} file${n === 1 ? "" : "s"}</summary><ol>`
    + files.map((name) => `<li>${esc(name)}</li>`).join("") + `</ol></details>`;
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

// An import-evidence card also offers the other way to fill an empty case: collect it from the
// fleet. openFleetCollection (dashboard-data-act.js) reveals the case-scoped Velociraptor panel.
function cockpitCardControls(card, parked) {
  const id = escAttr(card.id);
  const fleet = card.target && card.target.panel === "import"
    ? `<button data-act="openFleetCollection" title="Collect evidence from a Velociraptor client into this case">Fleet collection</button>`
    : "";
  const view = `<button data-act="cockpitOpenTarget" data-id="${id}">Open</button>${fleet}`;
  if (card.kind !== "lead" && card.kind !== "hypothesis" && card.kind !== "step") return view;
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

// The Executive Summary panel: a fact strip, the AI summary on the left and the synthesis's
// known-vs-unknown ledger (state.uncertainties, #73) on the right. Every piece is read from state
// the dashboard already holds, so the layout needs no AI call and applies to existing cases at once.
// The facts come from the High/Critical events — the attack, not the whole collection — and fall
// back to every event only when nothing is graded that high.
//
// No module-level constants: a top-level `const` in a classic script joins the page's global
// lexical scope (see proseSentences in js/dashboard-text.js), so the limits live in the functions.

function execSummaryHtml(state) {
  const s = state || {};
  const summary = String(s.lastSummary || "").trim();
  const facts = execFactsHtml(s);
  const ledger = execLedgerHtml(Array.isArray(s.uncertainties) ? s.uncertainties : []);
  const none = "No executive summary yet — run Synthesize.";
  if (!summary && !facts && !ledger) return emptyStateHtml(none);
  const what = `<div class="exec-what">${summary ? `<div class="prose">${proseHtml(summary)}</div>` : emptyStateHtml(none)}</div>`;
  const body = ledger
    ? `<div class="exec-cols">${what}<div class="exec-assess">${ledger}</div></div>`
    : what;
  return facts + body;
}

// "A, B +2": the most frequent names first, then alphabetical so a tie renders the same each time.
function execTopNames(values) {
  const counts = new Map();
  for (const v of values) if (v) counts.set(v, (counts.get(v) || 0) + 1);
  const maxNames = 2;
  const ranked = [...counts.keys()].sort((a, b) => counts.get(b) - counts.get(a) || a.localeCompare(b));
  const more = ranked.length - maxNames;
  return ranked.length ? ranked.slice(0, maxNames).join(", ") + (more > 0 ? ` +${more}` : "") : "";
}

// "2026-09-24 08:49:00 → 09:04:47 UTC" plus its span. The date shows once when both ends share it.
// UTC on purpose: the forensic timeline and the report state times in UTC, not in the viewer's zone.
function execWindow(events) {
  const times = [];
  for (const e of events) {
    for (const t of [e.timestamp, e.endTimestamp]) {
      const ms = Date.parse(t || "");
      if (Number.isFinite(ms)) times.push(ms);
    }
  }
  if (!times.length) return null;
  const first = Math.min(...times);
  const last = Math.max(...times);
  const fmt = (ms) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");
  const a = fmt(first);
  const b = fmt(last);
  const label = `${a} → ${a.slice(0, 10) === b.slice(0, 10) ? b.slice(11) : b} UTC`;
  const min = Math.floor((last - first) / 60000);
  const span =
    min < 60 ? `${min} min` : min < 1440 ? `${Math.floor(min / 60)} h ${min % 60} min` : `${Math.floor(min / 1440)} d ${Math.floor((min % 1440) / 60)} h`;
  return { label, span };
}

function execFactsHtml(s) {
  const all = Array.isArray(s.forensicTimeline) ? s.forensicTimeline : [];
  const key = all.filter((e) => e && (e.severity === "Critical" || e.severity === "High"));
  const events = key.length ? key : all.filter(Boolean);
  const chip = (k, v, cls) =>
    `<span class="exec-chip${cls ? " " + cls : ""}"><span class="exec-k">${esc(k)}</span><span class="exec-v">${esc(v)}</span></span>`;
  const chips = [];
  const hosts = execTopNames(events.map((e) => e.asset));
  if (hosts) chips.push(chip(hosts.includes(",") ? "Hosts" : "Host", hosts));
  const accounts = execTopNames(
    events.map((e) => (e.canonical?.actor?.kind === "account" ? e.canonical.actor.name : "")),
  );
  if (accounts) chips.push(chip(accounts.includes(",") ? "Accounts" : "Account", accounts));
  const win = execWindow(events);
  if (win) chips.push(chip(key.length ? "High+ activity" : "Activity", win.label), chip("Span", win.span));
  const live = (Array.isArray(s.findings) ? s.findings : []).filter((f) => f && f.status !== "dismissed");
  const crit = live.filter((f) => f.severity === "Critical").length;
  const high = live.filter((f) => f.severity === "High").length;
  if (crit || high) {
    const parts = [crit ? `${crit} Critical` : "", high ? `${high} High` : ""].filter(Boolean);
    chips.push(chip("Findings", parts.join(" · "), crit ? "exec-crit" : ""));
  }
  return chips.length ? `<div class="exec-facts">${chips.join("")}</div>` : "";
}

// Confirmed and inferred claims are the assessment, strongest first. Speculated and unknown ones are
// what the case still cannot say, each with the gap that would settle it.
function execLedgerHtml(uncertainties) {
  const rank = { confirmed: 0, inferred: 1 };
  const valid = uncertainties.filter((u) => u && String(u.topic || "").trim());
  const known = valid.filter((u) => u.status in rank).sort((a, b) => rank[a.status] - rank[b.status]);
  const open = valid.filter((u) => !(u.status in rank));
  const item = (u, detail) =>
    `<li class="exec-u exec-${escAttr(u.status || "unknown")}"${u.basis ? ` title="${escAttr(u.basis)}"` : ""}>` +
    `<span class="exec-status">${esc(u.status || "unknown")}</span><span>${esc(u.topic)}</span>` +
    (detail ? `<span class="exec-gap">${esc(detail)}</span>` : "") +
    `</li>`;
  const block = (title, rows) =>
    rows.length ? `<div class="exec-block"><h4>${title}</h4><ul>${rows.join("")}</ul></div>` : "";
  return (
    block("Assessment", known.map((u) => item(u, ""))) +
    block("Still unconfirmed", open.map((u) => item(u, u.gap)))
  );
}

// The Narrative Timeline as a time rail. The model writes one moment per paragraph and opens most of
// them with a time ("At 08:49, …", "From 08:55 onward, …"); the rail moves that time into its own
// column, makes the first sentence the lead, and links each time to the most severe event of that
// minute, so a claim in the story is one click from its evidence. Times are read as UTC, the zone
// the forensic timeline and the report use. Text the reader cannot place — fewer than two
// paragraphs opening with a time — keeps the plain prose layout, so nothing is lost or reordered.
// A panel with nothing in it yet says so in a muted sentence (#1765-#1768), the same shape as the
// IOC panel's "No IOCs yet" — a bare "—" read as "broken" to an analyst on a new case.
function emptyStateHtml(text) {
  return `<div class="empty-state" data-safe-style="color:var(--text-muted)">${esc(text)}</div>`;
}

// The Narrative Timeline view. "—" and blank are the editor's "nothing written yet" value (see
// dashboard-narrative.js): they stay in data-raw so the editor opens empty, and only the VIEW shows
// the sentence — it must never load into the textarea or be saved as the narrative.
function narrativeViewHtml(text, events) {
  const raw = String(text == null ? "" : text).trim();
  if (!raw || raw === "—") return emptyStateHtml("No narrative yet — ✨ Generate one from the Attack Path.");
  return narrativeHtml(text, events);
}

function narrativeHtml(text, events) {
  const paras = proseParagraphs(text);
  const leads = paras.map(narrativeLead);
  if (leads.filter(Boolean).length < 2) return proseHtml(text);
  const timed = [];
  for (const e of Array.isArray(events) ? events : []) {
    const ms = Date.parse((e && e.timestamp) || "");
    if (Number.isFinite(ms)) timed.push({ ms, e });
  }
  timed.sort((a, b) => a.ms - b.ms);
  const caseDates = [...new Set(timed.map((t) => new Date(t.ms).toISOString().slice(0, 10)))];
  let day = null; // the day the story last named; later bare times belong to it
  const items = paras.map((para, i) => {
    const lead = leads[i];
    if (lead && lead.date) day = lead.date;
    const dates = day ? [day, ...caseDates.filter((d) => d > day)] : caseDates;
    const hits = (lead ? lead.times : []).map((t) => ({ t, hit: narrativeEventAt(timed, dates, t) }));
    const sev = narrativeTopSeverity(hits.map((h) => h.hit && h.hit.severity));
    // The dot's tooltip names what its color means: the severity and the time it came from.
    const top = sev ? hits.find((h) => h.hit && h.hit.severity.toLowerCase() === sev) : null;
    const dotTip = top
      ? `Most severe event at ${top.t}: ${top.hit.severity}`
      : hits.length
        ? `No event in the forensic timeline at ${hits.map((h) => h.t).join(" or ")}`
        : lead && lead.date
          ? "Starts with a date but no time, so there is no event to match"
          : "Does not start with a time, so there is no event to match";
    const link = (h, bold) => {
      const label = bold ? `<b>${esc(h.t)}</b>` : esc(h.t);
      return h.hit
        ? `<button type="button" class="nt-jump" data-act="narrativeJumpToEvent" data-id="${escAttr(h.hit.id)}" title="Open the Forensic Timeline at ${escAttr(h.hit.at)} UTC">${label}</button>`
        : `<span class="nt-time">${label}</span>`;
    };
    let when = "";
    if (lead && lead.dateLabel) when += hits.length ? `<span class="nt-day">${esc(lead.dateLabel)}</span>` : `<b>${esc(lead.dateLabel)}</b>`;
    if (hits.length) when += link(hits[0], true) + hits.slice(1).map((h) => link(h, false)).join("");
    if (lead && lead.sub) when += `<span class="nt-sub">${esc(lead.sub)}</span>`;
    const [first, ...more] = proseSentences(lead ? lead.rest : para);
    const body = `<span class="nt-lede">${esc(first || "")}</span>${more.length ? " " + esc(more.join(" ")) : ""}`;
    return `<li><div class="nt-when">${when}</div><div class="nt-spine${sev ? " nt-sev-" + sev : ""}" title="${escAttr(dotTip)}"></div><div class="nt-body">${body}</div></li>`;
  });
  return `<ol class="nt-rail">${items.join("")}</ol>`;
}

// A paragraph's opening time phrase, split from the rest — or null when it opens with none. Only
// the OPENING is read: a time in the middle of a sentence is part of the claim, not its place on
// the rail. `sub` is the qualifier worth keeping beside the time ("onward", "shortly after").
function narrativeLead(para) {
  const text = String(para || "");
  const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  const T = "\\d{1,2}:\\d{2}(?::\\d{2})?";
  let pos = 0;
  let date = null;
  const dm = /^On\s+(?:(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})|([A-Za-z]{3,9})\s+(\d{1,2}),?\s+(\d{4})|(\d{4})-(\d{2})-(\d{2}))(?:,\s*|\s+(?=at\s)|\s+)/.exec(text);
  if (dm) {
    const mon = months.indexOf(String(dm[2] || dm[4] || "").slice(0, 3).toLowerCase());
    const y = dm[3] || dm[6] || dm[7];
    const mo = dm[8] || (mon >= 0 ? String(mon + 1).padStart(2, "0") : "");
    const d = String(dm[1] || dm[5] || dm[9] || "").padStart(2, "0");
    if (mo) {
      date = `${y}-${mo}-${d}`;
      pos = dm[0].length;
    }
  }
  const tm = new RegExp(
    `^(At|By|Around|From|Between|After|Before|Until|Shortly after|Just after|Just before|Soon after|Starting at|Beginning at)\\s+(${T})(?:\\s*(?:UTC|Z)\\b)?((?:\\s*,?\\s*(?:and|to|until|through|-|–)\\s+(?:again\\s+)?(?:at\\s+)?${T}(?:\\s*(?:UTC|Z)\\b)?)*)(\\s+onwards?)?(?:,\\s*|\\s+)`,
    "i",
  ).exec(text.slice(pos));
  const times = [];
  let sub = "";
  if (tm) {
    times.push(tm[2], ...(tm[3].match(new RegExp(T, "g")) || []));
    const kw = tm[1].toLowerCase();
    const keep = !["at", "from", "starting at", "beginning at"].includes(kw);
    const tail = tm[4] || (kw === "from" ? " onward" : "");
    sub = [keep ? kw : "", tail.trim()].filter(Boolean).join(" · ");
    pos += tm[0].length;
  }
  if (!date && !times.length) return null;
  const rest = text.slice(pos);
  const dateLabel = date ? `${Number(date.slice(8))} ${months[Number(date.slice(5, 7)) - 1].replace(/^./, (c) => c.toUpperCase())} ${date.slice(0, 4)}` : "";
  return { date, dateLabel, times, sub, rest: rest.charAt(0).toUpperCase() + rest.slice(1) };
}

// The most severe event in that minute (or that second, when the text gives seconds) on the first
// of `dates` that has one. `timed` is sorted by time, so a tie goes to the earliest event.
function narrativeEventAt(timed, dates, hhmm) {
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  const [h, m, sec] = hhmm.split(":");
  for (const d of dates) {
    const start = Date.parse(`${d}T${h.padStart(2, "0")}:${m}:${sec || "00"}Z`);
    if (!Number.isFinite(start)) continue;
    const end = start + (sec ? 1000 : 60000);
    let best = null;
    for (const t of timed) {
      if (t.ms < start || t.ms >= end) continue;
      if (!best || (rank[t.e.severity] ?? -1) > (rank[best.e.severity] ?? -1)) best = t;
    }
    if (best) {
      return {
        id: String(best.e.id),
        severity: best.e.severity,
        asset: String(best.e.asset || ""),
        at: new Date(best.ms).toISOString().slice(0, 19).replace("T", " "),
      };
    }
  }
  return null;
}

function narrativeTopSeverity(severities) {
  const order = ["Critical", "High", "Medium", "Low"];
  const top = order.find((s) => severities.includes(s));
  return top ? top.toLowerCase() : "";
}

// Published for the inline script and the other helper modules. EVERY function this file
// defines is listed: a helper that stays private here but is still called by name from
// dashboard.html is a ReferenceError, which is the mistake #414 shipped and then fixed.
window.DfirFragments = {
  proseHtml,
  execSummaryHtml,
  execTopNames,
  execWindow,
  execFactsHtml,
  execLedgerHtml,
  emptyStateHtml,
  narrativeViewHtml,
  narrativeHtml,
  narrativeLead,
  narrativeEventAt,
  narrativeTopSeverity,
  mentionHtml,
  ticketPushChips,
  renderVqlRows,
  askStatusBadge,
  jobFilesHtml,
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
