// Push a case or a finding to an external platform (#297) — DFIR-IRIS, Timesketch, MISP, Notion,
// ClickUp, Jira, ServiceNow (#415 tier 3).
//
// The ninth and last of the zero-escape features, held back from the other eight because it is the
// only one whose work is mostly at LOAD time rather than in its functions: four `getElementById`
// captures, three status fetches that reveal menu options, and a dozen listener registrations, all
// of which ran where they sat in the inline script — after the markup.
//
// These modules are <head> scripts. Running that block on load would query for elements that do not
// exist yet: the captures would be null, the listeners would attach to nothing, and the feature
// would be silently absent with no error anywhere. So it is wrapped in initTicketIntegrations() and
// the page calls it at the point the block used to occupy. Same fix as js/dashboard-custody.js,
// where the vm loader caught the same hazard.
//
// WHAT THIS BUYS. Seventeen names leave the shared global lexical environment — every one of the
// six bindings and eleven of the fourteen functions. Only three are called from elsewhere in the
// page, and openIrisImportModal is published from inside init because its one caller is an onclick
// arrow, resolved when the analyst clicks rather than when the listener is registered.
//
// NOT AN ES MODULE: the inline script calls the published names by bare name.
(function () {
  function pushFindingToTicket(target, findingId) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !findingId) { showToast("connect to a case first", "warn"); return; }
    const label = ticketLabel(target);
    showToast(`pushing finding to ${label}…`);
    fetch(`/cases/${encodeURIComponent(caseId)}/push/${target}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ findingId }),
    })
      .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
      .then((res) => {
        const ref = (target === "jira" ? res.issue : res.incident) || {};
        const name = ref.key || ref.number || "ticket";
        showToast(`${label} ${name} ${res.created ? "created" : "updated"}`);
        if (ref.url) document.getElementById("reportLinks").innerHTML =
          `<a href="${escAttr(ref.url)}" target="_blank" rel="noopener">Open ${esc(label)} ${esc(name)}</a>`;
      })
      .catch((err) => showToast(`${label} push failed: ` + err.message, "warn"));
  }
  // The bulk route answers 200 even when it could not file some of the batch, so the summary has
  // to name the skipped ones — otherwise a half-pushed selection reads as a clean success.
  function bulkPushFindingsToTicket(target) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !DfirSelection.findings.count()) return;
    const findingIds = DfirSelection.findings.ids();
    const label = ticketLabel(target);
    showToast(`pushing ${findingIds.length} finding(s) to ${label}…`);
    fetch(`/cases/${encodeURIComponent(caseId)}/push/${target}/bulk`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ findingIds }),
    })
      .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
      .then((res) => {
        const skipped = res.skipped || 0;
        showToast(`${label}: +${res.created} created, ${res.updated} updated` + (skipped ? `, ${skipped} skipped — see the browser console` : ""),
          skipped ? "warn" : undefined);
        const url = target === "jira" ? res.issueUrl : res.incidentUrl;
        if (url) document.getElementById("reportLinks").innerHTML =
          `<a href="${escAttr(url)}" target="_blank" rel="noopener">Open in ${esc(label)}</a>`;
        if (res.warnings && res.warnings.length) console.warn(`${target} bulk push warnings:`, res.warnings);
      })
      .catch((err) => showToast(`${label} push failed: ` + err.message, "warn"));
  }

  // Guards against a second call. Nothing calls it twice today, but it is a published entry point
  // now, and running it again would fire seven status requests a second time and stack a duplicate
  // listener on each of the four overlays — every "click outside to close" would then run twice.
  //
  // SET ON THE INITIALIZER'S LAST LINE, NOT ITS FIRST. Latching on ENTRY turned one missing element
  // into a permanent outage: the call that threw had already flipped the flag, so every later call
  // returned without wiring anything — and returned SILENTLY, no second error, nothing on screen.
  // Latching on SUCCESS instead leaves a failed run retryable.
  //
  // The retry re-runs the part that already succeeded, and that is the cheap half of the trade
  // here, because this feature's wiring is almost all assignment: ten of the fourteen handlers go
  // on as `el.onclick =` / `el.onchange =`, which a second pass overwrites rather than stacks. Only
  // the four overlay `addEventListener("click", …)` calls really duplicate, and their handler does
  // nothing but remove the .open class — running it twice is indistinguishable from once. The seven
  // status GETs repeat too, and addPushOption() already ignores an option it has added before.
  let initialised = false;

  // Everything below ran at top level in the inline script, in this order. It stays in that order,
  // inside a function the page calls at the same point — the ordering is the behaviour.
  function initTicketIntegrations() {
    if (initialised) return;
    // ── Push to an external platform (DFIR-IRIS / Timesketch / MISP) ──────────
    // Each option appears in the Push menu only when the server has that target configured
    // (GET /iris/status, /timesketch/status, /misp/status); the menu stays hidden until at least one does.
    const pushSelect = document.getElementById("pushSelect");
    function addPushOption(value, label) {
      if ([...pushSelect.options].some((o) => o.value === value)) return;
      const opt = document.createElement("option");
      opt.value = value; opt.textContent = label;
      pushSelect.appendChild(opt);
      pushSelect.style.display = "";
    }
    // Reveal the "From DFIR-IRIS" choice in the Import-case chooser (only when IRIS is configured).
    function addIrisImportOption() {
      document.getElementById("importCaseIris").style.display = "";
    }
    fetch("/iris/status").then((r) => r.json()).then((s) => {
      if (s && s.configured) { addPushOption("iris", "Push to DFIR-IRIS"); addIrisImportOption(); }
    }).catch(() => {});
    fetch("/timesketch/status").then((r) => r.json()).then((s) => {
      if (s && s.configured) {
        addPushOption("timesketch", "Timesketch export (Forensic Timeline)");
        addPushOption("timesketch-super", "Timesketch export (Super Timeline)");
      }
    }).catch(() => {});
    // Names what actually goes: IOCs + the FORENSIC timeline (never the super-timeline). Timesketch
    // above offers both timelines because it's a timeline viewer; MISP is an intel platform, so
    // shipping raw Info-severity telemetry there would be noise — and at one round-trip per
    // attribute, a large MFT import would take hours and hit the push cap immediately. Spelling out
    // the scope stops the single entry reading as a missing "(Super Timeline)" counterpart.
    fetch("/misp/status").then((r) => r.json()).then((s) => { if (s && s.configured) addPushOption("misp", "Push to MISP (IOCs + Forensic Timeline)"); }).catch(() => {});
    // Notion export: a configured token shows the option; a default DB/parent hides the modal's
    // target input (it's only needed for a "new page" when no default is set).
    let notionHasDefault = false;
    fetch("/notion/status").then((r) => r.json()).then((s) => {
      if (s && s.configured) { addPushOption("notion", "Export to Notion"); notionHasDefault = !!(s.hasDatabase || s.hasParent); }
    }).catch(() => {});
    // ClickUp: a configured token shows the option; the modal asks for the target list id.
    let clickupDefaultList = "";
    fetch("/clickup/status").then((r) => r.json()).then((s) => {
      if (s && s.configured) { addPushOption("clickup", "Push to ClickUp"); clickupDefaultList = s.defaultListId || ""; }
    }).catch(() => {});
    // Jira / ServiceNow (#297): these push a FINDING, not the whole case, so they live on the finding
    // rows and the finding bulk bar rather than in this case-level Push menu. All a configured target
    // does here is reveal those controls — see the .jira-push-btn / .snow-push-btn CSS switch.
    fetch("/jira/status").then((r) => r.json()).then((s) => { if (s && s.configured) document.body.classList.add("has-jira"); }).catch(() => {});
    fetch("/servicenow/status").then((r) => r.json()).then((s) => { if (s && s.configured) document.body.classList.add("has-servicenow"); }).catch(() => {});
    pushSelect.onchange = (e) => {
      const sel = e.target;
      const target = sel.value;
      sel.value = ""; // reset to the "Push to…" placeholder
      const caseId = document.getElementById("caseId").value.trim();
      if (!target || !caseId) return;
      // Notion/ClickUp/IRIS need a target question first, so they open a modal instead of an immediate POST.
      if (target === "notion") { openNotionModal(); return; }
      if (target === "clickup") { openClickupModal(caseId); return; }
      if (target === "iris") { openIrisPushModal(caseId); return; }
      const c = encodeURIComponent(caseId);
      sel.disabled = true;
      const targetLabel = target === "timesketch" ? "Timesketch (Forensic Timeline)"
        : target === "timesketch-super" ? "Timesketch (Super Timeline)"
        : "MISP";
      document.getElementById("status").textContent = `pushing to ${targetLabel}…`;
      document.getElementById("reportLinks").innerHTML = "";
      fetch(`/cases/${c}/push/${target}`, { method: "POST" })
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((res) => {
          if (target === "timesketch" || target === "timesketch-super") {
            const verb = res.created ? "created" : "updated";
            document.getElementById("status").textContent =
              `Timesketch sketch #${res.sketchId} ${verb}: ${res.events} event(s) → "${res.timelineName}"` +
              (res.replacedTimeline ? " (replaced)" : "") +
              (res.warnings && res.warnings.length ? `, ${res.warnings.length} warning(s)` : "");
            if (res.sketchUrl) document.getElementById("reportLinks").innerHTML = `<a href="${escAttr(res.sketchUrl)}" target="_blank" rel="noopener">Open in Timesketch</a>`;
          } else {
            const verb = res.created ? "created" : "updated";
            document.getElementById("status").textContent =
              `MISP event #${res.eventId} ${verb}: ${res.attributes.added} attribute(s) added` +
              (res.attributes.existing ? ` (${res.attributes.existing} existing)` : "") +
              (res.timeline ? `, ${res.timeline.added} timeline event(s) added` : "") +
              (res.timeline && res.timeline.existing ? ` (${res.timeline.existing} existing)` : "") +
              (res.tags ? `, ${res.tags} tag(s)` : "") +
              (res.warnings && res.warnings.length ? `, ${res.warnings.length} warning(s)` : "");
            if (res.eventUrl) document.getElementById("reportLinks").innerHTML = `<a href="${escAttr(res.eventUrl)}" target="_blank" rel="noopener">Open in MISP</a>`;
          }
          if (res.warnings && res.warnings.length) console.warn("push warnings:", res.warnings);
        })
        .catch((err) => document.getElementById("status").textContent = "push failed: " + err.message)
        .finally(() => { sel.disabled = false; });
    };

    // ── Export to Notion modal (new vs existing page) ─────────────────────────
    const notionOverlay = document.getElementById("notionOverlay");
    function notionMode() { const r = document.querySelector('input[name="notionMode"]:checked'); return r ? r.value : "new"; }
    function syncNotionRows() {
      const mode = notionMode();
      // The "new page" target input is only needed when no server default DB/parent is configured.
      document.getElementById("notionNewRow").style.display = (mode === "new" && !notionHasDefault) ? "" : "none";
      document.getElementById("notionExistingRow").style.display = mode === "existing" ? "" : "none";
    }
    function openNotionModal() {
      document.getElementById("notionMsg").textContent = "";
      syncNotionRows();
      notionOverlay.classList.add("open");
    }
    function closeNotionModal() { notionOverlay.classList.remove("open"); }
    [...document.querySelectorAll('input[name="notionMode"]')].forEach((r) => { r.onchange = syncNotionRows; });
    document.getElementById("notionCancel").onclick = closeNotionModal;
    notionOverlay.addEventListener("click", (e) => { if (e.target === notionOverlay) closeNotionModal(); });
    document.getElementById("notionExportBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) { document.getElementById("notionMsg").textContent = "connect to a case first"; return; }
      const c = encodeURIComponent(caseId);
      const mode = notionMode();
      const body = { mode };
      if (mode === "existing") {
        const page = document.getElementById("notionPageUrl").value.trim();
        if (!page) { document.getElementById("notionMsg").textContent = "paste the Notion page URL or ID"; return; }
        body.page = page;
      } else {
        const tgt = document.getElementById("notionNewTarget").value.trim();
        if (tgt) { body.database = tgt; body.parent = tgt; } // server picks whichever id resolves
        else if (!notionHasDefault) { document.getElementById("notionMsg").textContent = "enter a database or parent page ID (or set a default in .env)"; return; }
      }
      const btn = document.getElementById("notionExportBtn");
      btn.disabled = true;
      document.getElementById("notionMsg").textContent = "exporting…";
      fetch(`/cases/${c}/push/notion`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((res) => {
          const verb = res.created ? "created" : "updated";
          document.getElementById("status").textContent =
            `Notion page ${verb}: +${res.blocksAppended} block(s)` +
            (res.containerRecreated ? " (managed block recreated)" : "") +
            (res.warnings && res.warnings.length ? `, ${res.warnings.length} warning(s)` : "");
          if (res.pageUrl) document.getElementById("reportLinks").innerHTML = `<a href="${escAttr(res.pageUrl)}" target="_blank" rel="noopener">Open in Notion</a>`;
          if (res.warnings && res.warnings.length) console.warn("notion export warnings:", res.warnings);
          closeNotionModal();
        })
        .catch((err) => document.getElementById("notionMsg").textContent = "failed: " + err.message + " — restart the companion server if this 404s")
        .finally(() => { btn.disabled = false; });
    };

    // ── Import from DFIR-IRIS modal (issue #88) ───────────────────────────────
    const irisImportOverlay = document.getElementById("irisImportOverlay");
    function closeIrisImportModal() { irisImportOverlay.classList.remove("open"); }
    function openIrisImportModal() {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) { document.getElementById("status").textContent = "connect to a case first"; return; }
      const sel = document.getElementById("irisCaseSelect");
      const msg = document.getElementById("irisImportMsg");
      msg.textContent = "";
      document.getElementById("irisCaseIdInput").value = "";
      sel.innerHTML = '<option value="">loading cases…</option>';
      irisImportOverlay.classList.add("open");
      fetch("/iris/cases")
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((j) => {
          const cases = (j && j.cases) || [];
          if (!cases.length) { sel.innerHTML = '<option value="">(no cases found — enter an id below)</option>'; return; }
          sel.innerHTML = '<option value="">— select a case —</option>' +
            cases.map((c) => `<option value="${escAttr(String(c.caseId))}">${esc(c.caseName)} (#${esc(String(c.caseId))})</option>`).join("");
        })
        .catch((err) => { sel.innerHTML = '<option value="">(could not list cases)</option>'; msg.textContent = "list failed: " + err.message; });
    }
    // openIrisImportModal is invoked from the "Import case" chooser (importCaseIris button).
    document.getElementById("irisImportCancel").onclick = closeIrisImportModal;
    irisImportOverlay.addEventListener("click", (e) => { if (e.target === irisImportOverlay) closeIrisImportModal(); });
    document.getElementById("irisImportRun").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) { document.getElementById("irisImportMsg").textContent = "connect to a case first"; return; }
      const c = encodeURIComponent(caseId);
      const manualId = document.getElementById("irisCaseIdInput").value.trim();
      const selected = document.getElementById("irisCaseSelect").value.trim();
      const body = {};
      if (manualId) { body.irisCaseId = Number(manualId); if (!Number.isFinite(body.irisCaseId)) { document.getElementById("irisImportMsg").textContent = "case id must be a number"; return; } }
      else if (selected) body.irisCaseId = Number(selected);
      else { document.getElementById("irisImportMsg").textContent = "pick a case or enter an id"; return; }
      const btn = document.getElementById("irisImportRun");
      btn.disabled = true;
      document.getElementById("irisImportMsg").textContent = "importing…";
      fetch(`/cases/${c}/iris-import`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((res) => {
          document.getElementById("status").textContent =
            `importing DFIR-IRIS case ${res.caseName || ("#" + res.irisCaseId)}: ${res.timeline} timeline + ${res.assets} asset(s), ${res.iocs} IOC(s) — analyzing…`;
          closeIrisImportModal();
        })
        .catch((err) => document.getElementById("irisImportMsg").textContent = "failed: " + err.message + " — restart the companion server if this 404s")
        .finally(() => { btn.disabled = false; });
    };

    // Published HERE, the moment its own section is wired, rather than at the end of init. The
    // Import-case chooser is already registered by this point, and an exception in the reconnect,
    // ClickUp or IRIS-push wiring below would otherwise leave that control calling a name that was
    // never published — the one feature the analyst can already see, broken by an unrelated one.
    window.openIrisImportModal = openIrisImportModal;

    // ── Settings → Integrations "Test connection" ─────────────────────────────
    // DFIR-IRIS was the only integration on that tab with one of these. Every other target was
    // configure-and-hope: type a URL and a token, close Settings, and find out the credentials were
    // wrong the next time a push failed in the middle of an investigation. They all answer the same
    // {configured, ok, error} shape from the server, so the differences are data — the route, what
    // to call it, and what a success makes newly available.
    //
    // save:true IS THE HALF THAT IS EASY TO MISS. The probe runs SERVER-side, against .env, so a
    // token typed into the field but not yet saved would be tested in its previous value — a green
    // result for a configuration that was never applied. Where the dashboard owns the config, the
    // handler saves first. Jira and ServiceNow are deliberately read-only here (.env + restart), so
    // they have nothing to save and their route only pings the live client; the copy says so rather
    // than implying a failed test can be fixed in this modal.
    const INTEGRATION_TESTS = [
      {
        btn: "irisReconnectBtn", msg: "irisReconnectMsg", url: "/iris/reconnect", save: true,
        missing: "not configured — set IRIS URL + key above and reconnect",
        onOk: () => { addPushOption("iris", "Push to DFIR-IRIS"); addIrisImportOption(); },
      },
      {
        btn: "timesketchReconnectBtn", msg: "timesketchReconnectMsg", url: "/timesketch/reconnect", save: true,
        missing: "not configured — set the Timesketch URL, user + password above and reconnect",
        onOk: () => {
          addPushOption("timesketch", "Timesketch export (Forensic Timeline)");
          addPushOption("timesketch-super", "Timesketch export (Super Timeline)");
        },
      },
      {
        btn: "notionReconnectBtn", msg: "notionReconnectMsg", url: "/notion/reconnect", save: true,
        missing: "not configured — set the Notion integration token above and reconnect",
        // Carries the same two flags /notion/status does, because a reconnect can ADD a default
        // database/parent — without them the export modal would keep demanding a target the
        // analyst has just configured.
        onOk: (res) => {
          addPushOption("notion", "Export to Notion");
          notionHasDefault = !!(res.hasDatabase || res.hasParent);
        },
      },
      {
        btn: "clickupReconnectBtn", msg: "clickupReconnectMsg", url: "/clickup/reconnect", save: true,
        missing: "not configured — set the ClickUp API token above and reconnect",
        onOk: (res) => {
          addPushOption("clickup", "Push to ClickUp");
          clickupDefaultList = res.defaultListId || clickupDefaultList;
        },
      },
      {
        // On the ENRICHMENT tab, not Integrations: the same two keys feed the IOC provider, and the
        // reconnect rebuilds both. Wired from here anyway — this module owns the Push menu the test
        // reveals, and a second module for one button would split the table that keeps them alike.
        btn: "mispReconnectBtn", msg: "mispReconnectMsg", url: "/misp/reconnect", save: true,
        missing: "not configured — set the MISP URL + key above and reconnect",
        onOk: () => addPushOption("misp", "Push to MISP (IOCs + Forensic Timeline)"),
      },
      // YETI and OpenCTI are threat-intel PROVIDERS, not push targets, so they reveal nothing on
      // success and carry no onOk: the enrichment modal rebuilds its provider list and re-reads
      // /enrich-health every time it opens, and the route has already recorded this probe's verdict
      // in that same health gate — so the ● dot agrees with what the button just said.
      {
        btn: "yetiReconnectBtn", msg: "yetiReconnectMsg", url: "/enrichment/yeti/reconnect", save: true,
        missing: "not configured — set the YETI URL + key above and reconnect",
      },
      {
        btn: "openctiReconnectBtn", msg: "openctiReconnectMsg", url: "/enrichment/opencti/reconnect", save: true,
        missing: "not configured — set the OpenCTI URL + token above and reconnect",
      },
      {
        btn: "jiraTestBtn", msg: "jiraTestMsg", url: "/jira/test", save: false,
        missing: "not configured — set DFIR_JIRA_URL, DFIR_JIRA_USER and DFIR_JIRA_TOKEN in .env, then restart",
        onOk: () => document.body.classList.add("has-jira"),
      },
      {
        btn: "snowTestBtn", msg: "snowTestMsg", url: "/servicenow/test", save: false,
        missing: "not configured — set DFIR_SERVICENOW_URL, DFIR_SERVICENOW_USER and DFIR_SERVICENOW_PASSWORD in .env, then restart",
        onOk: () => document.body.classList.add("has-servicenow"),
      },
    ];
    for (const t of INTEGRATION_TESTS) {
      const btn = document.getElementById(t.btn);
      if (!btn) continue;
      btn.onclick = async () => {
        const msg = document.getElementById(t.msg);
        btn.disabled = true;
        msg.style.color = "var(--text-muted)";
        if (t.save) {
          msg.textContent = "saving…";
          const saved = await saveSettings();
          if (!saved) {
            msg.style.color = "var(--danger-bg)";
            msg.textContent = "save failed — fix the error above and retry";
            btn.disabled = false;
            return;
          }
        }
        msg.textContent = t.save ? "reconnecting…" : "testing…";
        fetch(t.url, { method: "POST" })
          .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
          .then((res) => {
            if (res.ok) {
              msg.style.color = "var(--badge-success-text)";
              msg.textContent = "✓ connected" +
                (res.baseUrl ? " to " + res.baseUrl : "") + (res.user ? " as " + res.user : "");
              if (t.onOk) t.onOk(res);   // reveal the actions this integration makes available
            } else if (res.configured) {
              msg.style.color = "var(--danger-bg)";
              msg.textContent = "✗ configured but unreachable: " + (res.error || "ping failed");
            } else {
              msg.style.color = "var(--text-muted)";
              msg.textContent = t.missing;
            }
          })
          .catch((err) => { msg.style.color = "var(--danger-bg)"; msg.textContent = "test failed: " + err.message; })
          .finally(() => { btn.disabled = false; });
      };
    }

    // ── Push playbook to ClickUp modal ────────────────────────────────────────
    const clickupOverlay = document.getElementById("clickupOverlay");
    function openClickupModal(caseId) {
      document.getElementById("clickupMsg").textContent = "";
      const input = document.getElementById("clickupListId");
      input.value = clickupDefaultList;   // default; overwritten by the saved list if present
      fetch(`/cases/${encodeURIComponent(caseId)}/clickup-export`).then((r) => r.ok ? r.json() : null)
        .then((s) => { if (s && s.listId) input.value = s.listId; }).catch(() => {});
      clickupOverlay.classList.add("open");
    }
    function closeClickupModal() { clickupOverlay.classList.remove("open"); }
    document.getElementById("clickupCancel").onclick = closeClickupModal;
    clickupOverlay.addEventListener("click", (e) => { if (e.target === clickupOverlay) closeClickupModal(); });
    document.getElementById("clickupPushBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) { document.getElementById("clickupMsg").textContent = "connect to a case first"; return; }
      const listId = document.getElementById("clickupListId").value.trim();
      if (!listId) { document.getElementById("clickupMsg").textContent = "enter a ClickUp list ID"; return; }
      const btn = document.getElementById("clickupPushBtn");
      btn.disabled = true;
      document.getElementById("clickupMsg").textContent = "pushing…";
      fetch(`/cases/${encodeURIComponent(caseId)}/push/clickup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ listId }) })
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((res) => {
          document.getElementById("status").textContent =
            `ClickUp: +${res.created} created, ${res.updated} updated` +
            (res.skipped ? `, ${res.skipped} skipped` : "") +
            (res.warnings && res.warnings.length ? `, ${res.warnings.length} warning(s)` : "");
          if (res.taskUrl) document.getElementById("reportLinks").innerHTML = `<a href="${escAttr(res.taskUrl)}" target="_blank" rel="noopener">Open in ClickUp</a>`;
          if (res.warnings && res.warnings.length) console.warn("clickup push warnings:", res.warnings);
          closeClickupModal();
        })
        .catch((err) => document.getElementById("clickupMsg").textContent = "failed: " + err.message + " — restart the companion server if this 404s")
        .finally(() => { btn.disabled = false; });
    };

    // ── Push to DFIR-IRIS modal (stable per-case name + override) ─────────────
    const irisPushOverlay = document.getElementById("irisPushOverlay");
    function openIrisPushModal(caseId) {
      document.getElementById("irisPushMsg").textContent = "";
      const input = document.getElementById("irisPushCaseName");
      input.value = caseId; // placeholder until the saved/default name loads below
      fetch(`/cases/${encodeURIComponent(caseId)}/iris-export`).then((r) => r.ok ? r.json() : null)
        .then((s) => { if (s) input.value = s.caseName || s.defaultCaseName || caseId; }).catch(() => {});
      irisPushOverlay.classList.add("open");
    }
    function closeIrisPushModal() { irisPushOverlay.classList.remove("open"); }
    document.getElementById("irisPushCancel").onclick = closeIrisPushModal;
    irisPushOverlay.addEventListener("click", (e) => { if (e.target === irisPushOverlay) closeIrisPushModal(); });
    document.getElementById("irisPushBtn").onclick = () => {
      const caseId = document.getElementById("caseId").value.trim();
      if (!caseId) { document.getElementById("irisPushMsg").textContent = "connect to a case first"; return; }
      const caseName = document.getElementById("irisPushCaseName").value.trim();
      if (!caseName) { document.getElementById("irisPushMsg").textContent = "enter an IRIS case name"; return; }
      const btn = document.getElementById("irisPushBtn");
      btn.disabled = true;
      document.getElementById("irisPushMsg").textContent = "pushing…";
      fetch(`/cases/${encodeURIComponent(caseId)}/push/iris`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ caseName }) })
        .then(async (r) => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; })
        .then((res) => {
          const verb = res.created ? "created" : "updated";
          document.getElementById("status").textContent =
            `IRIS case #${res.caseId} ${verb}: assets +${res.assets.added} (${res.assets.existing} existing), ` +
            `IOCs +${res.iocs.added} (${res.iocs.existing} existing), timeline +${res.timeline.added}, ` +
            `tasks +${res.tasks.added}, notes ${res.notes}` +
            (res.warnings && res.warnings.length ? `, ${res.warnings.length} warning(s)` : "");
          if (res.caseUrl) document.getElementById("reportLinks").innerHTML = `<a href="${escAttr(res.caseUrl)}" target="_blank" rel="noopener">Open in IRIS</a>`;
          if (res.warnings && res.warnings.length) console.warn("iris push warnings:", res.warnings);
          closeIrisPushModal();
        })
        .catch((err) => document.getElementById("irisPushMsg").textContent = "failed: " + err.message)
        .finally(() => { btn.disabled = false; });
    };

    // LAST LINE, on purpose — see the declaration above.
    initialised = true;
  }

  // The names the inline script calls by bare name. Everything else — all six bindings and eleven
  // of the fourteen functions — stays inside the closure.
  window.pushFindingToTicket = pushFindingToTicket;
  window.bulkPushFindingsToTicket = bulkPushFindingsToTicket;
  window.initTicketIntegrations = initTicketIntegrations;
})();
