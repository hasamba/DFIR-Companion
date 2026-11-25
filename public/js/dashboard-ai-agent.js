// AI Agent Forensics panel (#2690): "has an AI coding agent on these endpoints been tampered with?"
//
// Pick endpoints, optionally tick the slow scopes, press Run. Velociraptor runs the ai-dfir-toolkit
// YARA and Sigma rules on each endpoint, lists the AI tools and MCP servers present, and preserves the
// AI-agent artifacts. This panel shows the results-only report: per endpoint inventory, hits, coverage,
// the rules not run and why, the rule version, and a link to the collection in Velociraptor.
//
// Two places, one renderer:
//   inside a case  — the #sec-aiagent section; hits also become forensic-timeline events;
//   no case open   — the toolbar button opens #aiAgentOverlay in SWEEP mode: each run lives in a hidden
//                    sweep case, and "Add to case…" files its hits into a real case later.
//
// Every endpoint-, rule- and file-derived string (matched text above all — it is an instruction an
// attacker planted for an AI) is written with textContent only, never innerHTML.
(function () {
  "use strict";

  const byId = (id) => document.getElementById(id);
  let rules = null;
  // Each render of a box bumps its generation; an older render that finishes late paints nothing, so a
  // slow load can never show (or Run against) the previous case.
  const renderGens = new Map();

  function el(tag, text, cls) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  }

  function caseNow() {
    const box = byId("caseId");
    return box && typeof box.value === "string" ? box.value.trim() : "";
  }

  async function call(url, opts) {
    try {
      const res = await fetch(url, opts);
      let body = {};
      try {
        body = await res.json();
      } catch {
        body = {};
      }
      // A locked case answers 401 { error: "locked", caseId } like every lock gate (#2798): say it.
      if (res.status === 401 && body && body.error === "locked")
        body = { ...body, error: `${body.caseId ? `Case ${body.caseId}` : "This case"} is locked — unlock it first.` };
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      return { ok: false, status: 0, body: { error: String((e && e.message) || e) } };
    }
  }

  const post = (url, body) =>
    call(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  const runsUrl = (caseId) => `/cases/${encodeURIComponent(caseId)}/ai-agent/runs`;

  function rulesBlock() {
    const box = el("div", null, "aa-rules");
    if (!rules) return box;
    box.appendChild(el("p", `Rules: ${rules.version}`, "aa-note"));
    box.appendChild(el("p", "Severity grades are a first estimate: they have not yet been checked against real developer machines, so some may change.", "aa-note aa-provisional"));
    if (rules.problem) box.appendChild(el("p", rules.problem, "aa-warn"));
    box.appendChild(packControls());
    return box;
  }

  // The separate AI-agent rule pack (aiagent-rules-*): check → review the changes → Install, or roll back.
  function packControls() {
    const wrap = el("div", null, "aa-actions");
    const msg = el("span", "", "aa-msg");
    msg.setAttribute("role", "status");
    const check = el("button", "Rule pack: check for updates");
    check.type = "button";
    const back = el("button", "Use the bundled rules");
    back.type = "button";
    const done = (r, text) => {
      msg.textContent = r.ok ? text : r.body.error || `Failed (HTTP ${r.status}).`;
      if (r.ok) rules = null; // the next render re-reads the rule version
    };
    check.addEventListener("click", async () => {
      msg.textContent = "Checking…";
      const r = await post("/ai-agent/pack/check");
      if (!r.ok || r.body.status !== "found") {
        msg.textContent = r.ok ? (r.body.status === "current" ? `Up to date (${r.body.version}).` : r.body.message || "No pack.") : r.body.error || `Failed (HTTP ${r.status}).`;
        return;
      }
      const d = r.body.diff || {};
      const list = (label, xs) => (xs && xs.length ? `${label}: ${xs.join(", ")}. ` : "");
      msg.textContent =
        `${r.body.version} — ` +
        (list("Rules added", d.added) + list("Rules removed", d.removed) + list("Files changed", d.changedFiles) +
          list("Files added", d.addedFiles) + list("Files removed", d.removedFiles) || "no change in any file. ");
      const install = el("button", `Install ${r.body.version}`);
      install.type = "button";
      install.addEventListener("click", async () => done(await post("/ai-agent/pack/install", { version: r.body.version }), "Installed — the next run uses it. Reopen the panel to see the version."));
      msg.appendChild(install);
    });
    back.addEventListener("click", async () => done(await post("/ai-agent/pack/rollback", { to: "bundled" }), "Back to the bundled rules for the next run."));
    wrap.append(check, back, msg);
    return wrap;
  }

  function notRunBlock(groups) {
    const details = el("details", null, "aa-notrun");
    const total = groups.reduce((n, g) => n + g.rules.length, 0);
    details.appendChild(el("summary", `Rules not run (${total}), and why`));
    for (const g of groups) {
      const p = el("p", `${g.reason} (${g.rules.length}): `);
      p.appendChild(el("span", g.rules.join(", "), "aa-muted"));
      details.appendChild(p);
    }
    return details;
  }

  async function endpointPicker(caseId) {
    const wrap = el("div", null, "aa-endpoints");
    const filter = el("input");
    filter.type = "search";
    filter.placeholder = "Filter endpoints";
    filter.setAttribute("aria-label", "Filter endpoints");
    const list = el("div", null, "aa-endpoint-list");
    list.setAttribute("role", "group");
    list.setAttribute("aria-label", "Endpoints to check");
    wrap.append(filter, list);
    // Inside a case: the case's own endpoint list (case writers, #2725). No case: the fleet inventory,
    // which — like a run with no case open — is the administrator's.
    const inv = await call(caseId ? `/cases/${encodeURIComponent(caseId)}/ai-agent/endpoints` : "/velociraptor/clients");
    const clients = (inv.ok && inv.body.clients) || [];
    if (inv.status === 403)
      list.appendChild(el("p", caseId ? "You need write access to this case to list its endpoints — ask the case owner or an administrator." : "Only an administrator can list endpoints and run with no case open — open a case you can write to.", "aa-note"));
    else if (!inv.ok) list.appendChild(el("p", (inv.body && inv.body.error) || `Could not list endpoints (HTTP ${inv.status}).`, "aa-note"));
    else if (!clients.length)
      list.appendChild(el("p", "No Velociraptor client inventory yet — an administrator can refresh it in Settings → Velociraptor.", "aa-note"));
    // #2887: a list the server cut at its row limit says so; the filter searches the WHOLE list and
    // only the drawn rows are capped (js/dashboard-velo-clients.js). Picks live in a Set, so a pick
    // survives a filter that hides its row.
    const cut = inv.ok ? veloClientsCutNotice(inv.body) : "";
    if (cut) wrap.insertBefore(el("p", cut, "aa-note"), list);
    const note = el("p", null, "aa-note");
    note.hidden = true;
    wrap.insertBefore(note, list);
    const picked = new Set();
    function draw() {
      const view = veloPickerRows(clients, filter.value);
      note.textContent = veloPickerNote(view);
      note.hidden = !note.textContent;
      list.replaceChildren();
      for (const c of view.rows) {
        const label = el("label", null, "aa-endpoint");
        const box = el("input");
        box.type = "checkbox";
        box.value = c.clientId;
        box.checked = picked.has(c.clientId);
        box.addEventListener("change", () => (box.checked ? picked.add(c.clientId) : picked.delete(c.clientId)));
        label.append(box, document.createTextNode(` ${veloPickerLabel(c)}`));
        list.appendChild(label);
      }
    }
    // Only a real list is drawn: typing over a refusal or an empty inventory keeps its message.
    if (inv.ok && clients.length) {
      draw();
      filter.addEventListener("input", draw);
    }
    return { wrap, selected: () => [...picked] };
  }

  function scopeBoxes() {
    const wrap = el("div", null, "aa-scopes");
    const boxes = [];
    for (const s of (rules && rules.scopes) || []) {
      const label = el("label");
      const box = el("input");
      box.type = "checkbox";
      box.value = s.id;
      box.checked = !!s.default;
      label.append(box, document.createTextNode(` ${s.label}`));
      wrap.appendChild(label);
      boxes.push(box);
    }
    return { wrap, selected: () => boxes.filter((b) => b.checked).map((b) => b.value) };
  }

  async function runForm(caseId, onStarted) {
    const form = el("div", null, "aa-form");
    const picker = await endpointPicker(caseId);
    const scopes = scopeBoxes();
    const capLabel = el("label", "Upload cap per matched file (MB) ");
    const cap = el("input");
    cap.type = "number";
    cap.min = "0";
    cap.value = "50";
    cap.className = "aa-cap";
    capLabel.appendChild(cap);
    const run = el("button", "Run");
    run.type = "button";
    const msg = el("p", "", "aa-msg"); // its own line under Run, so a refusal is not lost beside the button
    msg.setAttribute("role", "status");
    run.addEventListener("click", async () => {
      const clientIds = picker.selected();
      if (!clientIds.length) {
        msg.textContent = "Pick at least one endpoint.";
        msg.classList.add("aa-warn");
        return;
      }
      if (caseId && caseId !== caseNow()) {
        msg.textContent = "The open case changed — reopen the panel before running.";
        msg.classList.add("aa-warn");
        return;
      }
      run.disabled = true;
      msg.textContent = "Starting…";
      msg.classList.remove("aa-warn");
      const body = { clientIds, scopes: scopes.selected(), uploadMaxBytes: Math.round(Number(cap.value || 50) * 1024 * 1024) };
      if (caseId) body.caseId = caseId;
      const r = await post("/ai-agent/runs", body);
      run.disabled = false;
      msg.textContent = r.ok
        ? `Started on ${r.body.run.endpoints.length} endpoint(s). Results are read after the hunt finishes (or press Refresh results).`
        : r.body.error || `Not started (HTTP ${r.status}).`;
      msg.classList.toggle("aa-warn", !r.ok);
      if (r.ok) onStarted();
    });
    form.append(picker.wrap, scopes.wrap, capLabel, run, msg);
    form.appendChild(
      el("p", caseId ? "Hits become events in this case's forensic timeline. Collected files stay in Velociraptor." : "Outside a case: results stay in this panel until you add them to a case.", "aa-note"),
    );
    return form;
  }

  // #2722: the file's hash (taken after the YARA scan), the preserved copy's hash and whether they
  // match. A report stored before the check existed never recorded it. YARA, the hash and the upload
  // are separate reads, so "same" claims only "unchanged since hashing" (Codex review).
  const HASH_LABELS = {
    same: "same: unchanged between hashing and preservation",
    differs: "differs: changed between hashing and preservation",
  };
  const HASH_CAVEAT =
    "File hashes are taken after the YARA scan. The bytes YARA read are not separately hashed, so \"same\" shows only that the file did not change between hashing and preservation; that the preserved copy holds the matched bytes is not proven.";
  function hashCell(h) {
    const td = el("td", null, "aa-hash");
    td.appendChild(el("div", `after scan: ${h.sha256 || "none"}`));
    td.appendChild(el("div", `preserved: ${h.preservedSha256 || "none"}`));
    const check = h.hashCheck || "not recorded";
    td.appendChild(el("div", HASH_LABELS[check] || check, check === "differs" ? "aa-warn" : "aa-muted"));
    return td;
  }

  // #2722: one row per Sigma rule of the rule set, one column per endpoint. A rule that sent no row
  // from an endpoint was not recorded there — never "did not run".
  function sigmaTable(report) {
    const rules = report.sigmaRules || [];
    if (!rules.length) return null;
    const wrap = el("details", null, "aa-sigma");
    wrap.appendChild(el("summary", `Sigma coverage per rule and endpoint (${rules.length} rule(s))`));
    const table = el("table", null, "aa-hits");
    const head = el("tr");
    for (const h of ["Rule", "Basis", ...report.endpoints.map((e) => e.host)]) head.appendChild(el("th", h));
    table.appendChild(head);
    for (const r of rules) {
      const tr = el("tr");
      tr.append(el("td", r.rule), el("td", r.basis));
      for (const e of report.endpoints) {
        const cell = (e.sigma || []).find((c) => c.rule === r.rule);
        tr.appendChild(el("td", cell ? `${cell.status}, ${cell.hits} hit(s)` : "not recorded", cell ? "" : "aa-muted"));
      }
      table.appendChild(tr);
    }
    wrap.appendChild(table);
    return wrap;
  }

  function hitsTable(hits) {
    if (!hits.length) return el("p", "No rule matched on these endpoints and scopes.", "aa-note");
    const table = el("table", null, "aa-hits");
    const head = el("tr");
    for (const h of ["Grade", "Endpoint", "Rule", "File", "Latest time the content could have been planted", "Matched text", "File SHA-256 after scan / preserved", "Rule"])
      head.appendChild(el("th", h));
    table.appendChild(head);
    for (const h of hits) {
      const tr = el("tr");
      tr.appendChild(el("td", `${h.severity}${h.selfScan ? " (self-scan)" : ""}`, `sev-${String(h.severity).toLowerCase()}`));
      tr.appendChild(el("td", h.host));
      tr.appendChild(el("td", h.rule));
      tr.appendChild(el("td", h.path));
      tr.appendChild(el("td", `${h.time} (${h.timeBasis})`));
      tr.appendChild(el("td", h.snippet, "aa-snippet"));
      tr.appendChild(hashCell(h));
      const ruleCell = el("td", h.author ? `${h.author} ` : "");
      if (h.link && /^https:\/\/github\.com\//.test(h.link)) {
        const a = el("a", "rule");
        a.href = h.link;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        ruleCell.appendChild(a);
      }
      tr.appendChild(ruleCell);
      table.appendChild(tr);
    }
    const wrap = el("div");
    wrap.append(table, el("p", HASH_CAVEAT, "aa-note"));
    return wrap;
  }

  function endpointLines(endpoints) {
    const ul = el("ul", null, "aa-endpoint-summary");
    for (const e of endpoints) {
      const tools = e.tools.length ? e.tools.join(", ") : "no AI tools found";
      const cred = e.credentialStores ? ` · credential store present` : "";
      const li = el("li", `${e.host} — ${tools} · ${e.mcpServers.length} MCP server(s) · ${e.hits} hit(s)${cred}`);
      for (const m of e.mcpServers) li.appendChild(el("div", `MCP "${m.name}" in ${m.tool}: runs ${m.command || "?"} (${m.argCount} argument(s) not shown)`, "aa-muted"));
      for (const c of e.coverage) li.appendChild(el("div", `${c.source}: ${c.status}${c.detail ? ` — ${c.detail}` : ""}`, "aa-muted"));
      ul.appendChild(li);
    }
    return ul;
  }

  async function addToCase(sweepId, run, msg) {
    const list = await call("/cases");
    const cases = (list.ok && Array.isArray(list.body) ? list.body : []).map((c) => `${c.caseId} — ${c.name}`);
    const pick = window.prompt(`Add this sweep's hits to which case? Type its case id.\n\n${cases.slice(0, 30).join("\n")}`);
    if (!pick) return;
    const target = pick.split(" — ")[0].trim();
    msg.textContent = "Adding…";
    const r = await post(`${runsUrl(sweepId)}/${encodeURIComponent(run.runId)}/add-to-case`, { targetCaseId: target });
    msg.textContent = r.ok ? `Added to ${target}: +${r.body.addedEvents} event(s).` : r.body.error || `Could not add (HTTP ${r.status}).`;
  }

  function runCard(caseId, run, sweep, rerender) {
    const card = el("div", null, "aa-run");
    const head = el("div", null, "aa-run-head");
    head.appendChild(el("strong", `Run ${run.launchedAt.replace("T", " ").slice(0, 16)} · ${run.endpoints.length} endpoint(s)`));
    head.appendChild(el("span", " SENSITIVE", "aa-sensitive"));
    card.appendChild(head);
    card.appendChild(el("p", `Rules: ${run.ruleSetVersion} · scopes: ${run.scopes.join(", ")} · preserved: ${run.preserved ? "yes" : "no — artifacts not preserved"}`, "aa-note"));
    card.appendChild(el("p", "Sensitive: preservation may have copied credential files into Velociraptor's file store. The Companion never reads the collected files (manifest only).", "aa-note"));
    for (const w of run.warnings || []) card.appendChild(el("p", w, "aa-warn"));
    for (const f of run.failedEndpoints || []) card.appendChild(el("p", `${f.clientId}: not added (${f.error})`, "aa-warn"));
    const actions = el("div", null, "aa-actions");
    const msg = el("span", "", "aa-msg");
    msg.setAttribute("role", "status");
    const refresh = el("button", "Refresh results");
    refresh.type = "button";
    refresh.addEventListener("click", async () => {
      msg.textContent = "Reading results…";
      const r = await post(`${runsUrl(caseId)}/${encodeURIComponent(run.runId)}/refresh`);
      msg.textContent = r.ok ? "" : r.body.error || `Could not read results (HTTP ${r.status}).`;
      if (r.ok) rerender();
    });
    actions.appendChild(refresh);
    if (run.guiUrl && /^https?:\/\//.test(run.guiUrl)) {
      const a = el("a", "Open collection in Velociraptor ↗");
      a.href = run.guiUrl;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      actions.appendChild(a);
    }
    for (const fmt of ["md", "csv"]) {
      const a = el("a", `Report .${fmt}`);
      a.href = `${runsUrl(caseId)}/${encodeURIComponent(run.runId)}/report.${fmt}`;
      actions.appendChild(a);
    }
    const sigmaCsv = el("a", "Sigma coverage .csv");
    sigmaCsv.href = `${runsUrl(caseId)}/${encodeURIComponent(run.runId)}/sigma-coverage.csv`;
    actions.appendChild(sigmaCsv);
    if (sweep) {
      const add = el("button", "Add to case…");
      add.type = "button";
      add.addEventListener("click", () => addToCase(caseId, run, msg));
      actions.appendChild(add);
      for (const a of run.addedTo || []) card.appendChild(el("p", `Added to ${a.caseId} (${a.events} event(s))`, "aa-note"));
    }
    actions.appendChild(msg);
    card.appendChild(actions);
    if (run.reportError) card.appendChild(el("p", run.reportError, "aa-warn"));
    for (const x of run.readIncomplete || [])
      card.appendChild(
        el("p", `Not read in full: ${x.artifact} — only ${x.rowsRead} rows were read. Add to case stays refused until a refresh reads everything.`, "aa-warn"),
      );
    const r = run.report;
    if (!r) {
      card.appendChild(el("p", "Results not read yet.", "aa-note"));
      return card;
    }
    card.appendChild(endpointLines(r.endpoints));
    card.appendChild(hitsTable(r.hits));
    const sigma = sigmaTable(r);
    if (sigma) card.appendChild(sigma);
    card.appendChild(notRunBlock(r.notRun));
    if (run.manifest) card.appendChild(el("p", `Preserved in Velociraptor: ${run.manifest.total} file(s), ${run.manifest.totalBytes} bytes (manifest only).`, "aa-note"));
    if (r.unreadableRows) card.appendChild(el("p", `${r.unreadableRows} result row(s) could not be read.`, "aa-warn"));
    return card;
  }

  async function renderPanel(box, caseId) {
    if (!box) return;
    const gen = (renderGens.get(box.id) || 0) + 1;
    renderGens.set(box.id, gen);
    const stale = () => renderGens.get(box.id) !== gen || (caseId && caseId !== caseNow());
    box.replaceChildren(el("p", "Loading…", "aa-note"));
    if (!rules) {
      const r = await call("/ai-agent/rules");
      rules = r.ok ? r.body : null;
    }
    const again = () => renderPanel(box, caseId);
    const parts = [rulesBlock(), await runForm(caseId, again)];
    if (caseId) {
      const r = await call(runsUrl(caseId));
      for (const run of (r.ok && r.body.runs) || []) parts.push(runCard(caseId, run, false, again));
    } else {
      const r = await call("/ai-agent/sweeps");
      if (!r.ok) parts.push(el("p", r.body.error || `Sweeps are not available (HTTP ${r.status}).`, "aa-warn"));
      for (const s of (r.ok && r.body.sweeps) || []) if (s.run) parts.push(runCard(s.caseId, s.run, true, again));
    }
    if (stale()) return;
    box.replaceChildren(...parts);
  }

  function loadAiAgentPanel(caseId) {
    return renderPanel(byId("aiAgentPanel"), caseId || caseNow());
  }

  function openSweepOverlay() {
    const overlay = byId("aiAgentOverlay");
    if (!overlay) return;
    overlay.classList.add("open");
    renderPanel(byId("aiAgentSweepPanel"), "");
  }

  function initAiAgentPanel() {
    const button = byId("aiAgentBtn");
    const close = byId("aiAgentOverlayClose");
    if (close) close.addEventListener("click", () => byId("aiAgentOverlay").classList.remove("open"));
    if (!button) return;
    button.addEventListener("click", () => {
      const section = byId("sec-aiagent");
      if (caseNow() && section) {
        if (typeof markSectionRevealed === "function") markSectionRevealed("sec-aiagent");
        section.classList.remove("collapsed");
        section.scrollIntoView({ behavior: "smooth", block: "start" });
        loadAiAgentPanel(caseNow());
      } else openSweepOverlay();
    });
  }

  window.initAiAgentPanel = initAiAgentPanel;
  window.loadAiAgentPanel = loadAiAgentPanel;
})();
