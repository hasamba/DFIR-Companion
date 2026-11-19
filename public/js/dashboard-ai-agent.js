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
    box.appendChild(el("p", "Grades are provisional until measured on real developer profiles.", "aa-note aa-provisional"));
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
      const d = r.body.diff || { added: [], removed: [], changedFiles: [] };
      msg.textContent = `${r.body.version}: +${d.added.length} rule(s), -${d.removed.length}, ${d.changedFiles.length} changed file(s). `;
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
    const inv = await call(`/velociraptor/clients${caseId ? `?caseId=${encodeURIComponent(caseId)}` : ""}`);
    const clients = (inv.ok && inv.body.clients) || [];
    if (!clients.length)
      list.appendChild(el("p", "No Velociraptor client inventory yet — refresh it in Settings → Velociraptor.", "aa-note"));
    for (const c of clients.slice(0, 2000)) {
      const label = el("label", null, "aa-endpoint");
      const box = el("input");
      box.type = "checkbox";
      box.value = c.clientId;
      label.append(box, document.createTextNode(` ${c.hostname || c.fqdn || c.clientId} (${c.clientId})`));
      list.appendChild(label);
    }
    filter.addEventListener("input", () => {
      const q = filter.value.trim().toLowerCase();
      for (const label of list.querySelectorAll("label")) label.hidden = q && !label.textContent.toLowerCase().includes(q);
    });
    return { wrap, selected: () => [...list.querySelectorAll("input:checked")].map((b) => b.value) };
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
    const msg = el("span", "", "aa-msg");
    msg.setAttribute("role", "status");
    run.addEventListener("click", async () => {
      const clientIds = picker.selected();
      if (!clientIds.length) {
        msg.textContent = "Pick at least one endpoint.";
        return;
      }
      run.disabled = true;
      msg.textContent = "Starting…";
      const body = { clientIds, scopes: scopes.selected(), uploadMaxBytes: Math.round(Number(cap.value || 50) * 1024 * 1024) };
      if (caseId) body.caseId = caseId;
      const r = await post("/ai-agent/runs", body);
      run.disabled = false;
      msg.textContent = r.ok
        ? `Started on ${r.body.run.endpoints.length} endpoint(s). Results are read after the hunt finishes (or press Refresh results).`
        : r.body.error || `Could not start (HTTP ${r.status}).`;
      if (r.ok) onStarted();
    });
    form.append(picker.wrap, scopes.wrap, capLabel, run, msg);
    form.appendChild(
      el("p", caseId ? "Hits become events in this case's forensic timeline. Collected files stay in Velociraptor." : "Outside a case: results stay in this panel until you add them to a case.", "aa-note"),
    );
    return form;
  }

  function hitsTable(hits) {
    if (!hits.length) return el("p", "No rule matched on these endpoints and scopes.", "aa-note");
    const table = el("table", null, "aa-hits");
    const head = el("tr");
    for (const h of ["Grade", "Endpoint", "Rule", "File", "Latest time the content could have been planted", "Matched text", "Rule"])
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
    return table;
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
    const r = run.report;
    if (!r) {
      card.appendChild(el("p", "Results not read yet.", "aa-note"));
      return card;
    }
    card.appendChild(endpointLines(r.endpoints));
    card.appendChild(hitsTable(r.hits));
    card.appendChild(notRunBlock(r.notRun));
    if (run.manifest) card.appendChild(el("p", `Preserved in Velociraptor: ${run.manifest.total} file(s), ${run.manifest.totalBytes} bytes (manifest only).`, "aa-note"));
    if (r.unreadableRows) card.appendChild(el("p", `${r.unreadableRows} result row(s) could not be read.`, "aa-warn"));
    return card;
  }

  async function renderPanel(box, caseId) {
    if (!box) return;
    box.replaceChildren(el("p", "Loading…", "aa-note"));
    if (!rules) {
      const r = await call("/ai-agent/rules");
      rules = r.ok ? r.body : null;
    }
    const again = () => renderPanel(box, caseId);
    const parts = [rulesBlock(), await runForm(caseId, again)];
    if (rules) parts.push(notRunBlock(rules.notRun || []));
    if (caseId) {
      const r = await call(runsUrl(caseId));
      for (const run of (r.ok && r.body.runs) || []) parts.push(runCard(caseId, run, false, again));
    } else {
      const r = await call("/ai-agent/sweeps");
      if (!r.ok) parts.push(el("p", r.body.error || `Sweeps are not available (HTTP ${r.status}).`, "aa-warn"));
      for (const s of (r.ok && r.body.sweeps) || []) if (s.run) parts.push(runCard(s.caseId, s.run, true, again));
    }
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
