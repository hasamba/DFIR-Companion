// MCP Analysis (#296) — the analyst states a forensic goal and the MCP-backed agent chooses tools
// and arguments; a manual single-tool call stays under Advanced for debugging and tightly
// constrained workflows (#415 tier 3).
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE. Six mutable bindings (the discovered server list, the watch
// token that lets a stale poll retire itself, the active and preview job ids, the retry thunk) are
// read by nothing else on the page — the extraction measured exactly one name crossing the
// boundary, loadMcpRun, which the lazy-section table calls. In a CLASSIC script a top-level `let`
// joins the shared global lexical environment, so these would still be reachable by name from every
// other script; wrapping them is what makes "owns its state" true rather than aspirational.
//
// ITS DOM WIRING IS AN INITIALIZER, NOT LOAD-TIME WORK. This file is a <head> script, so the
// `document.getElementById("mcpRunServer")` calls that used to sit at the bottom of the inline
// block would now run before #sec-mcp exists and wire nothing at all — silently. initMcp() is
// called from the page where that block used to be. See js/dashboard-tickets.js for the same shape.
//
// Depends on esc (js/dashboard-escape.js), fileToBase64 (js/dashboard-values.js) and
// mcpJobDuration (js/dashboard-time.js), all of which are tagged before this file.
(function () {

  // MCP Analysis section (#296): the analyst states the forensic goal and the MCP-backed agent
  // chooses tools and arguments. A manual single-tool call remains under Advanced for debugging
  // and tightly constrained workflows.
  let _mcpRunServers = [];
  let _mcpWatchToken = 0;
  let _mcpActiveJobId = "";
  let _mcpRetry = null;
  const MCP_BROWSER_FILE_MAX_MB = 180; // base64 overhead keeps this under the default 256 MB JSON limit
  function mcpRunCaseId() { const el = document.getElementById("caseId"); return el && typeof el.value === "string" ? el.value.trim() : ""; }
  function mcpRunBrowserFile() {
    const el = document.getElementById("mcpRunFile");
    return el && el.files && el.files[0] ? el.files[0] : null;
  }
  function mcpRunFileChanged() {
    const file = mcpRunBrowserFile();
    if (!file) return;
    const target = document.getElementById("mcpRunTarget");
    target.value = file.name;
    target.dataset.browserFile = file.name;
    document.getElementById("mcpRunMsg").textContent =
      `${file.name} selected from this browser (${Math.max(1, Math.round(file.size / 1024))} KB)`;
  }
  function mcpRunTargetChanged() {
    const target = document.getElementById("mcpRunTarget");
    const file = mcpRunBrowserFile();
    // Typing after a Browse selection switches back to the case-path mode. Otherwise the visible
    // path and the bytes actually uploaded could silently name two different files.
    if (file && target.value.trim() !== file.name) {
      document.getElementById("mcpRunFile").value = "";
      delete target.dataset.browserFile;
    }
  }
  function loadMcpRun() {
    const form = document.getElementById("mcpRunForm");
    const none = document.getElementById("mcpRunUnavailable");
    if (!form || !none) return;
    resumeMcpJob();
    fetch("/mcp/status").then(r => r.ok ? r.json() : null).then(j => {
      _mcpRunServers = ((j && j.servers) || []).filter(s => s.enabled);
      if (!_mcpRunServers.length) { form.style.display = "none"; none.style.display = ""; return; }
      none.style.display = "none"; form.style.display = "";
      const sel = document.getElementById("mcpRunServer");
      const keep = sel.value;
      sel.innerHTML = _mcpRunServers.map(s => `<option value="${esc(s.id)}">${esc(s.label)}</option>`).join("");
      if (keep && _mcpRunServers.some(s => s.id === keep)) sel.value = keep;
      mcpRunServerChanged();
    }).catch(() => { form.style.display = "none"; none.style.display = ""; });
    loadMcpRunTargets();
    loadMcpReports();
  }
  // The evidence already under custody is the best available answer to "what can I point this at",
  // and it needs no new endpoint. Free text still works for anything not yet recorded.
  function loadMcpRunTargets() {
    const dl = document.getElementById("mcpRunTargets");
    const cid = mcpRunCaseId();
    if (!dl || !cid) return;
    fetch(`/cases/${encodeURIComponent(cid)}/custody`).then(r => r.ok ? r.json() : null).then(j => {
      const paths = [...new Set(((j && j.records) || []).map(r => r.artifactPath).filter(Boolean))];
      dl.innerHTML = paths.map(p => `<option value="${esc(p)}"></option>`).join("");
    }).catch(() => {});
  }
  function mcpRunServerChanged() {
    const server = _mcpRunServers.find(s => s.id === document.getElementById("mcpRunServer").value);
    const msg = document.getElementById("mcpRunMsg");
    if (!server) return;
    fillMcpRunTools(server);
    // A server with no allowlist may run everything it offers, so there is nothing to warn about.
    // Only an allowlist the operator DID set can be narrower than what they want.
    msg.textContent = "";
    mcpRunToolChanged();
  }
  // Names come from whatever Claude Code last reported for this server, narrowed by the allowlist
  // when one is set. The field stays free text either way — the list is a convenience, not a gate.
  function fillMcpRunTools(server) {
    const dl = document.getElementById("mcpRunTools");
    if (!dl) return;
    const offered = server.tools || [];
    const allowed = server.allowedTools || [];
    const names = allowed.length
      ? (offered.length ? offered.filter(t => allowed.includes(t)) : allowed)
      : offered;
    dl.innerHTML = names.map(t => `<option value="${esc(t)}"></option>`).join("");
  }
  function mcpRunToolChanged() {
    const box = document.getElementById("mcpRunArgs");
    if (!box) return;
    // Only prefill an untouched box — never clobber something the analyst is editing.
    if (box.value.trim() && box.dataset.touched === "1") return;
    box.value = "{}";
  }
  function listMcpRunTools() {
    const server = document.getElementById("mcpRunServer").value;
    const msg = document.getElementById("mcpRunMsg");
    const btn = document.getElementById("mcpRunListToolsBtn");
    if (!server) return;
    btn.disabled = true; msg.textContent = "asking Claude Code…";
    fetch(`/mcp/servers/${encodeURIComponent(server)}/tools`, { method: "POST" })
      .then(r => r.json()).then(j => {
        btn.disabled = false;
        if (!j.ok) { msg.textContent = j.error || "could not list tools"; return; }
        msg.textContent = `${(j.tools || []).length} tool(s) offered`;
        // Refresh from /mcp/status so the cached list and the allowlist stay in one place.
        loadMcpRun();
      }).catch(e => { btn.disabled = false; msg.textContent = "could not list tools: " + e.message; });
  }
  async function runMcpTool() {
    const cid = mcpRunCaseId();
    const msg = document.getElementById("mcpRunMsg");
    const jobEl = document.getElementById("mcpRunJob");
    const btn = document.getElementById("mcpRunBtn");
    if (!cid) { msg.textContent = "connect a case first"; return; }
    const serverId = document.getElementById("mcpRunServer").value;
    const tool = document.getElementById("mcpRunTool").value;
    if (!tool) { msg.textContent = "name a tool to run — press List tools to see what this server offers"; return; }
    let args;
    try { args = JSON.parse(document.getElementById("mcpRunArgs").value || "{}"); }
    catch (e) { msg.textContent = "arguments are not valid JSON: " + e.message; return; }
    const targetPath = (document.getElementById("mcpRunTarget").value || "").trim();
    const browserFile = mcpRunBrowserFile();
    if (browserFile && browserFile.size > MCP_BROWSER_FILE_MAX_MB * 1024 * 1024) {
      msg.textContent = `${browserFile.name} is too large for browser upload — enter its path inside the case instead`;
      return;
    }

    const preview = !!(document.getElementById("mcpRunPreview") || {}).checked;
    _mcpRetry = runMcpTool;
    btn.disabled = true; msg.textContent = browserFile ? `reading ${browserFile.name}…` : "starting…"; jobEl.textContent = "";
    hideMcpPreview();
    let endpoint = `/cases/${encodeURIComponent(cid)}/mcp/${encodeURIComponent(serverId)}/run`;
    let body = { tool, args, preview, ...(targetPath ? { targetPath } : {}) };
    if (browserFile) {
      try {
        const dataBase64 = await fileToBase64(browserFile);
        endpoint = `/cases/${encodeURIComponent(cid)}/mcp/${encodeURIComponent(serverId)}/run-upload`;
        body = { tool, args, preview, filename: browserFile.name, dataBase64 };
      } catch (e) {
        btn.disabled = false;
        msg.textContent = `could not read ${browserFile.name}: ${e.message}`;
        return;
      }
    }
    msg.textContent = "starting…";
    fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(r => r.json().then(j => ({ ok: r.ok, j }))).then(({ ok, j }) => {
      btn.disabled = false;
      if (!ok) { msg.textContent = (j && j.error) || "run failed"; return; }
      msg.textContent = `running ${serverId}/${tool}…`;
      watchMcpJob(cid, j.jobId, preview);
    }).catch(e => { btn.disabled = false; msg.textContent = "run failed: " + e.message; });
  }
  async function runMcpAgent() {
    const cid = mcpRunCaseId();
    const msg = document.getElementById("mcpRunMsg");
    const jobEl = document.getElementById("mcpRunJob");
    const btn = document.getElementById("mcpAgentBtn");
    if (!cid) { msg.textContent = "connect a case first"; return; }
    const serverId = document.getElementById("mcpRunServer").value;
    const prompt = (document.getElementById("mcpAgentPrompt").value || "").trim();
    if (!prompt) { msg.textContent = "describe what you want investigated"; return; }
    const targetPath = (document.getElementById("mcpRunTarget").value || "").trim();
    const browserFile = mcpRunBrowserFile();
    if (browserFile && browserFile.size > MCP_BROWSER_FILE_MAX_MB * 1024 * 1024) {
      msg.textContent = `${browserFile.name} is too large for browser upload — enter its path inside the case instead`;
      return;
    }
    const preview = !!(document.getElementById("mcpRunPreview") || {}).checked;
    _mcpRetry = runMcpAgent;
    btn.disabled = true;
    msg.textContent = browserFile ? `reading ${browserFile.name}…` : "starting investigation…";
    jobEl.textContent = "";
    hideMcpPreview();
    let endpoint = `/cases/${encodeURIComponent(cid)}/mcp/agent`;
    let body = { prompt, servers: [serverId], preview, ...(targetPath ? { targetPath } : {}) };
    if (browserFile) {
      try {
        const dataBase64 = await fileToBase64(browserFile);
        endpoint = `/cases/${encodeURIComponent(cid)}/mcp/agent-upload`;
        body = { prompt, servers: [serverId], preview, filename: browserFile.name, dataBase64 };
      } catch (e) {
        btn.disabled = false;
        msg.textContent = `could not read ${browserFile.name}: ${e.message}`;
        return;
      }
    }
    msg.textContent = "investigation started…";
    fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(r => r.json().then(j => ({ ok: r.ok, j }))).then(({ ok, j }) => {
      btn.disabled = false;
      if (!ok) { msg.textContent = (j && j.error) || "investigation failed"; return; }
      msg.textContent = `investigating with ${serverId}…`;
      watchMcpJob(cid, j.jobId, preview);
    }).catch(e => { btn.disabled = false; msg.textContent = "investigation failed: " + e.message; });
  }
  let _mcpPreviewJob = null;
  function hideMcpPreview() {
    _mcpPreviewJob = null;
    const p = document.getElementById("mcpPreviewPanel"); if (p) p.style.display = "none";
    const m = document.getElementById("mcpPreviewMsg"); if (m) m.textContent = "";
  }
  // Show what the run fetched, before any of it reaches the case. A tool that returns a capability
  // listing rather than evidence is indistinguishable to any detector — both are timestamp-free
  // JSON — so the analyst who asked for it is the only reliable judge.
  function showMcpPreview(caseIdStr, jobId) {
    fetch(`/cases/${encodeURIComponent(caseIdStr)}/mcp/preview/${encodeURIComponent(jobId)}`)
      .then(r => r.ok ? r.json() : null).then(p => {
        if (!p) { document.getElementById("mcpRunMsg").textContent = "preview unavailable"; return; }
        _mcpPreviewJob = jobId;
        document.getElementById("mcpPreviewHead").textContent =
          `${p.server}/${p.tool} — ${p.bytes} byte(s), would import as "${p.kind}"${p.truncated ? " (showing the first 8 KB)" : ""}`;
        document.getElementById("mcpPreviewText").textContent = p.text;
        document.getElementById("mcpPreviewPanel").style.display = "";
        document.getElementById("mcpPreviewImportBtn").style.display = p.imported ? "none" : "";
        document.getElementById("mcpPreviewDiscardBtn").style.display = p.imported ? "none" : "";
        document.getElementById("mcpPreviewMsg").textContent = p.imported
          ? "Imported and preserved in analysis history."
          : "";
        document.getElementById("mcpRunMsg").textContent = p.imported
          ? "analysis imported"
          : "review the output, then import or discard";
      }).catch(() => {});
  }
  function importMcpPreview() {
    const cid = mcpRunCaseId(); const jobId = _mcpPreviewJob;
    const m = document.getElementById("mcpPreviewMsg");
    if (!cid || !jobId) return;
    m.textContent = "importing…";
    fetch(`/cases/${encodeURIComponent(cid)}/mcp/preview/${encodeURIComponent(jobId)}/import`, { method: "POST" })
      .then(r => r.json().then(j => ({ ok: r.ok, j }))).then(({ ok, j }) => {
        if (!ok) { m.textContent = (j && j.error) || "import failed"; return; }
        document.getElementById("mcpPreviewImportBtn").style.display = "none";
        document.getElementById("mcpPreviewDiscardBtn").style.display = "none";
        m.textContent = "Imported and preserved in analysis history.";
        const updated = j.updatedFindings ? `, ${j.updatedFindings} finding(s) updated` : "";
        document.getElementById("mcpRunMsg").textContent = `imported — ${j.addedFindings || 0} finding(s) added${updated}, ${j.addedEvents} event(s), ${j.addedIocs} IOC(s)`;
        loadMcpRunTargets();
        loadMcpReports(j.reportId);
      }).catch(e => { m.textContent = "import failed: " + e.message; });
  }
  function discardMcpPreview() {
    const cid = mcpRunCaseId(); const jobId = _mcpPreviewJob;
    if (!cid || !jobId) return;
    fetch(`/cases/${encodeURIComponent(cid)}/mcp/preview/${encodeURIComponent(jobId)}`, { method: "DELETE" })
      .then(() => { hideMcpPreview(); document.getElementById("mcpRunMsg").textContent = "discarded — nothing was imported"; })
      .catch(() => {});
  }
  function showMcpReport(reportId) {
    const cid = mcpRunCaseId();
    if (!cid || !reportId) return;
    fetch(`/cases/${encodeURIComponent(cid)}/mcp/reports/${encodeURIComponent(reportId)}`)
      .then(r => r.ok ? r.json() : null).then(report => {
        if (!report) return;
        const counts = report.counts || {};
        document.getElementById("mcpReportHead").textContent =
          `${new Date(report.importedAt).toLocaleString()} — ${report.server}/${report.tool} — ` +
          `${counts.addedFindings || 0} finding(s) added, ${counts.updatedFindings || 0} updated, ` +
          `${counts.addedEvents || 0} event(s), ${counts.addedIocs || 0} IOC(s)`;
        document.getElementById("mcpReportText").textContent = report.text || "";
        document.getElementById("mcpReportView").style.display = "";
        document.getElementById("mcpReportHistory").open = true;
      }).catch(() => {});
  }
  function loadMcpReports(openReportId) {
    const cid = mcpRunCaseId();
    const list = document.getElementById("mcpReportList");
    if (!list) return;
    list.textContent = "";
    if (!cid) { document.getElementById("mcpReportCount").textContent = ""; return; }
    fetch(`/cases/${encodeURIComponent(cid)}/mcp/reports`).then(r => r.ok ? r.json() : { reports: [] }).then(j => {
      const reports = Array.isArray(j.reports) ? j.reports : [];
      document.getElementById("mcpReportCount").textContent = reports.length ? `(${reports.length})` : "(none yet)";
      reports.forEach(report => {
        const button = document.createElement("button");
        button.type = "button";
        button.style.cssText = "padding:3px 8px;font-size:11px";
        button.textContent = `${new Date(report.importedAt).toLocaleString()} — ${report.server}/${report.tool}`;
        button.onclick = () => showMcpReport(report.id);
        list.appendChild(button);
      });
      if (openReportId) showMcpReport(openReportId);
    }).catch(() => {});
  }
  function setMcpJobButtons(job) {
    const cancel = document.getElementById("mcpRunCancelBtn");
    const retry = document.getElementById("mcpRunRetryBtn");
    const running = job && (job.status === "running" || job.status === "queued");
    cancel.style.display = running && job.cancellable ? "" : "none";
    retry.style.display = job && (job.status === "failed" || job.status === "interrupted" || job.status === "cancelled") ? "" : "none";
  }
  function cancelMcpJob() {
    if (!_mcpActiveJobId) return;
    const btn = document.getElementById("mcpRunCancelBtn");
    btn.disabled = true;
    fetch(`/api/jobs/${encodeURIComponent(_mcpActiveJobId)}/cancel`, { method: "POST" })
      .then(r => r.json().then(j => ({ ok: r.ok, j }))).then(({ ok, j }) => {
        btn.disabled = false;
        if (!ok) document.getElementById("mcpRunMsg").textContent = (j && j.error) || "cancel failed";
      }).catch(e => { btn.disabled = false; document.getElementById("mcpRunMsg").textContent = "cancel failed: " + e.message; });
  }
  function retryMcpJob() {
    document.getElementById("mcpRunRetryBtn").style.display = "none";
    (_mcpRetry || runMcpAgent)();
  }
  function resumeMcpJob() {
    const cid = mcpRunCaseId();
    if (!cid) return;
    const token = ++_mcpWatchToken;
    fetch(`/api/jobs?caseId=${encodeURIComponent(cid)}`).then(r => r.ok ? r.json() : null).then(d => {
      if (token !== _mcpWatchToken) return;
      const job = ((d && d.jobs) || []).find(j => j.kind === "mcp" && (j.status === "running" || j.status === "queued"));
      if (!job) return;
      _mcpRetry = (job.label || "").startsWith("agent (") ? runMcpAgent : runMcpTool;
      watchMcpJob(cid, job.id, /\(preview\)/.test(job.label || ""));
    }).catch(() => {});
  }
  // The run is a background job (a real Volatility run outlives any request), so follow it here.
  // Monitoring has no arbitrary retry cap: a multi-hour memory run remains visible until the
  // backend records a terminal state, and loadMcpRun reattaches after a page refresh.
  function watchMcpJob(caseIdStr, jobId, preview) {
    const jobEl = document.getElementById("mcpRunJob");
    const msg = document.getElementById("mcpRunMsg");
    if (!jobId) return;
    const token = ++_mcpWatchToken;
    _mcpActiveJobId = jobId;
    const mcpTick = () => {
      if (token !== _mcpWatchToken) return;
      fetch(`/api/jobs?caseId=${encodeURIComponent(caseIdStr)}`).then(r => r.ok ? r.json() : null).then(d => {
        if (token !== _mcpWatchToken) return;
        const job = ((d && d.jobs) || []).find(x => x.id === jobId);
        if (!job) { setTimeout(mcpTick, 1500); return; }
        const elapsed = job.startedAt ? mcpJobDuration(Date.now() - Date.parse(job.startedAt)) : "";
        const activityAge = job.updatedAt ? Date.now() - Date.parse(job.updatedAt) : 0;
        const stale = (job.status === "running" || job.status === "queued") && activityAge > 20000
          ? ` — no update for ${mcpJobDuration(activityAge)}; it may be stalled`
          : "";
        const progress = job.progress && job.progress.total ? ` [${job.progress.done}/${job.progress.total}]` : "";
        jobEl.textContent = `${job.status}${progress}${job.detail ? " — " + job.detail : ""}${elapsed ? " — total " + elapsed : ""}${stale}`;
        setMcpJobButtons(job);
        if (job.status === "running" || job.status === "queued") { setTimeout(mcpTick, 1000); return; }
        _mcpActiveJobId = "";
        if (job.status === "succeeded" && preview) { showMcpPreview(caseIdStr, jobId); }
        else if (job.status === "succeeded") { msg.textContent = "done — result imported"; loadMcpRunTargets(); }
        else { msg.textContent = job.status === "cancelled" ? "cancelled" : (job.error || "failed"); }
      }).catch(() => { if (token === _mcpWatchToken) setTimeout(mcpTick, 3000); });
    };
    mcpTick();
  }

  // Everything the block below used to do at the bottom of the inline script, deferred to a call
  // from the page. The order is unchanged — it is the behaviour.
  function initMcp() {
    const s = document.getElementById("mcpRunServer"); if (s) s.onchange = mcpRunServerChanged;
    const t = document.getElementById("mcpRunTool"); if (t) t.onchange = mcpRunToolChanged;
    const lt = document.getElementById("mcpRunListToolsBtn"); if (lt) lt.onclick = listMcpRunTools;
    const a = document.getElementById("mcpRunArgs"); if (a) a.oninput = () => { a.dataset.touched = "1"; };
    const browse = document.getElementById("mcpRunBrowseBtn"); if (browse) browse.onclick = () => document.getElementById("mcpRunFile").click();
    const file = document.getElementById("mcpRunFile"); if (file) file.onchange = mcpRunFileChanged;
    const target = document.getElementById("mcpRunTarget"); if (target) target.oninput = mcpRunTargetChanged;
    const agent = document.getElementById("mcpAgentBtn"); if (agent) agent.onclick = runMcpAgent;
    const b = document.getElementById("mcpRunBtn"); if (b) b.onclick = runMcpTool;
    const i = document.getElementById("mcpPreviewImportBtn"); if (i) i.onclick = importMcpPreview;
    const d = document.getElementById("mcpPreviewDiscardBtn"); if (d) d.onclick = discardMcpPreview;
    const c = document.getElementById("mcpRunCancelBtn"); if (c) c.onclick = cancelMcpJob;
    const r = document.getElementById("mcpRunRetryBtn"); if (r) r.onclick = retryMcpJob;
  }

  window.loadMcpRun = loadMcpRun;
  window.initMcp = initMcp;
})();
