// Live CLIENT_EVENT monitoring (#84) — the Velociraptor event monitors running on the fleet, and
// starting or stopping them (#415 tier 3).
//
// ONE OF TWO FEATURES UNDER ITS BANNER. The other is the triage-bundle builder below it; the
// cohesion check reported clusters of 10 and 8 and nothing in one calls anything in the other.
//
// NO INITIALIZER: the per-row buttons are wired by renderVeloMonitors() as the rows are built.
(function () {
  // Declared in the inline block until #415 tier 3 and used only here. This module's binding now.
  let _veloEventArtifacts = []; // last-loaded CLIENT_EVENT artifact list (monitor picker)

  // ── Live CLIENT_EVENT monitoring (#84) ────────────────────────────────────────────────────
  function loadVeloMonitors(caseId) {
    // Populate the CLIENT_EVENT picker once when Velociraptor is on, so the dropdown isn't empty
    // and the analyst doesn't have to click "Browse" first (it can still be re-browsed manually).
    if (veloEnabled && !veloMonAutoBrowsed()) {
      setVeloMonAutoBrowsed(true);
      veloMonBrowse();
    }
    if (!caseId) {
      renderVeloMonitors([]);
      return;
    }
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/monitors`)
      .then((r) => (r.ok ? r.json() : []))
      .then((j) => renderVeloMonitors(Array.isArray(j) ? j : []))
      .catch(() => {});
  }
  // Update the toolbar "🔴 LIVE n" badge from the monitor list.
  function renderVeloMonitorBadge(monitors) {
    const badge = document.getElementById("veloMonitorBadge");
    if (!badge) return;
    const active = monitors.filter((m) => m.status === "active").length;
    const errored = monitors.filter((m) => m.status === "error").length;
    if (!active && !errored) {
      badge.style.display = "none";
      badge.textContent = "";
      return;
    }
    badge.style.display = "";
    badge.style.color = errored && !active ? "#ff9f43" : "#ff5a5a";
    badge.textContent = `🔴 LIVE ${active}${errored ? ` · ⚠ ${errored}` : ""}`;
    badge.onclick = () => openSettingsTab("velociraptor");
  }
  function renderVeloMonitors(monitors) {
    renderVeloMonitorBadge(monitors);
    const el = document.getElementById("veloMonitorList");
    if (!el) return;
    if (!monitors.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No live monitors — start one below to stream a client-monitoring artifact into this case.</div>";
      return;
    }
    const colors = { active: "#4cd964", stopped: "#9aa4b2", error: "#ff9f43" };
    el.innerHTML = monitors
      .map((m) => {
        const dot =
          m.status === "active" ? "🔴" : m.status === "error" ? "⚠" : "⏸";
        const badge = `<span data-safe-style="color:${colors[m.status] || "#9aa4b2"};font-weight:600">${esc(m.status)}</span>`;
        const host = m.allClients
          ? `🌐 <span title="all enrolled clients">all clients</span>`
          : esc(m.hostname || m.clientId);
        const stats = `${m.addedEvents || 0} event(s) · ${m.polls || 0} poll(s) · last ${veloMonAge(m.lastPolledAt)}`;
        const err =
          m.status === "error" && m.lastError
            ? `<div data-safe-style="font-size:12px;color:var(--sev-high);margin-top:3px">error: ${esc(m.lastError)}</div>`
            : "";
        const toggle =
          m.status === "stopped"
            ? `<button class="vmon-start" data-id="${escAttr(m.id)}" title="Resume this monitor">▶ Resume</button>`
            : `<button class="vmon-stop" data-id="${escAttr(m.id)}" title="Stop polling (keeps the cursor)">⏸ Stop</button>`;
        return `<div class="synth-meta" data-safe-style="margin:0 0 8px;padding:8px 10px;border:1px solid var(--border-color);border-radius:6px">
        <div data-safe-style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <div>${dot} <strong>${esc(m.artifact)}</strong> · ${host} · ${badge} · every ${esc(m.pollSeconds)}s</div>
          <div data-safe-style="display:flex;gap:6px">
            <button class="vmon-poll" data-id="${escAttr(m.id)}" title="Poll now (don't wait for the timer)">Poll now</button>
            ${toggle}
            <button class="vmon-del" data-id="${escAttr(m.id)}" title="Delete this monitor">✕</button>
          </div>
        </div>
        <div data-safe-style="font-size:12px;color:var(--text-muted);margin-top:4px">${esc(stats)}</div>${err}
      </div>`;
      })
      .join("");
    el.querySelectorAll(".vmon-stop").forEach(
      (b) => (b.onclick = () => veloMonAction(b.dataset.id, "stop", b)),
    );
    el.querySelectorAll(".vmon-start").forEach(
      (b) => (b.onclick = () => veloMonAction(b.dataset.id, "start", b)),
    );
    el.querySelectorAll(".vmon-poll").forEach(
      (b) => (b.onclick = () => veloMonAction(b.dataset.id, "poll", b)),
    );
    el.querySelectorAll(".vmon-del").forEach(
      (b) => (b.onclick = () => veloMonDelete(b.dataset.id, b)),
    );
  }
  function veloMonAction(id, action, btn) {
    const caseId = veloCaseId();
    if (!caseId) return;
    const method =
      action === "stop" || action === "start" || action === "poll"
        ? "POST"
        : "POST";
    if (btn) btn.disabled = true;
    fetch(
      `/cases/${encodeURIComponent(caseId)}/velociraptor/monitors/${encodeURIComponent(id)}/${action}`,
      { method },
    )
      .then((r) =>
        r
          .json()
          .then((j) => ({ ok: r.ok, j }))
          .catch(() => ({ ok: r.ok, j: {} })),
      )
      .then(({ ok, j }) => {
        if (!ok) console.warn("monitor " + action + " failed", j);
        loadVeloMonitors(caseId);
      })
      .catch((e) => console.warn("monitor " + action + " error", e))
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function veloMonDelete(id, btn) {
    const caseId = veloCaseId();
    if (!caseId) return;
    if (btn) btn.disabled = true;
    fetch(
      `/cases/${encodeURIComponent(caseId)}/velociraptor/monitors/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    )
      .then(() => loadVeloMonitors(caseId))
      .catch((e) => console.warn("monitor delete error", e))
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function veloMonBrowse() {
    const sel = document.getElementById("veloMonArtifact");
    const btn = document.getElementById("veloMonBrowseBtn");
    if (!veloEnabled) {
      const m = document.getElementById("veloMonMsg");
      if (m)
        m.textContent =
          "Velociraptor API not configured (set the API config path on Integrations, then restart).";
      return;
    }
    if (btn) btn.disabled = true;
    if (sel) sel.innerHTML = `<option value="">loading…</option>`;
    fetch("/velociraptor/event-artifacts?refresh=1")
      .then((r) => r.json().then((j) => ({ ok: r.ok, j }))) // see veloBrowseArtifacts: deliberate Browse bypasses the catalog cache
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (sel)
            sel.innerHTML = `<option value="">error: ${esc(j.error || "failed")}</option>`;
          return;
        }
        _veloEventArtifacts = j.artifacts || [];
        if (sel) {
          const head = _veloEventArtifacts.length
            ? `— pick a CLIENT_EVENT artifact (${_veloEventArtifacts.length}) —`
            : `— none found — type a name below instead —`;
          sel.innerHTML =
            `<option value="">${esc(head)}</option>` +
            _veloEventArtifacts
              .map(
                (a) =>
                  `<option value="${escAttr(a.name)}" title="${escAttr(a.description || "")}">${esc(a.name)}</option>`,
              )
              .join("");
        }
      })
      .catch((e) => {
        if (sel)
          sel.innerHTML = `<option value="">error: ${esc(e.message)}</option>`;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  // Grey out the client field when "all enrolled clients" is ticked.
  function veloMonSyncAllClients() {
    const all = document.getElementById("veloMonAllClients");
    const client = document.getElementById("veloMonClient");
    if (all && client) {
      client.disabled = all.checked;
      client.placeholder = all.checked
        ? "(all enrolled clients)"
        : "client id (C.xxxxxxxx)";
    }
  }
  function veloMonStart() {
    const caseId = veloCaseId();
    const msg = document.getElementById("veloMonMsg");
    if (!caseId) {
      if (msg) msg.textContent = "connect to a case first";
      return;
    }
    if (!veloEnabled) {
      if (msg) msg.textContent = "Velociraptor API not configured";
      return;
    }
    const artifact =
      document.getElementById("veloMonArtifactManual").value.trim() ||
      document.getElementById("veloMonArtifact").value.trim();
    const allClients = document.getElementById("veloMonAllClients").checked;
    const clientId = document.getElementById("veloMonClient").value.trim();
    const pollSeconds =
      Number(document.getElementById("veloMonPoll").value) || 30;
    const minSeverity = document.getElementById("veloMonMinSev").value;
    if (!artifact) {
      if (msg) msg.textContent = "pick or type a CLIENT_EVENT artifact";
      return;
    }
    if (!allClients && !/^C\.[A-Za-z0-9]+$/.test(clientId)) {
      if (msg)
        msg.textContent =
          "enter a valid client id (C.xxxxxxxx), or tick All enrolled clients";
      return;
    }
    const host =
      (veloClientsList() || []).find((c) => c.clientId === clientId) || {};
    const body = allClients
      ? { allClients: true, artifact, pollSeconds, minSeverity }
      : {
          clientId,
          artifact,
          pollSeconds,
          minSeverity,
          hostname: host.hostname || host.fqdn || "",
        };
    const btn = document.getElementById("veloMonStartBtn");
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "starting…";
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/monitors`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        if (msg) msg.textContent = "";
        document.getElementById("veloMonArtifactManual").value = "";
        loadVeloMonitors(caseId);
      })
      .catch((e) => {
        if (msg)
          msg.textContent =
            "error: " +
            e.message +
            " — restart the companion server if this 404s";
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  // Discover every artifact already enabled in Velociraptor's Client Monitoring table and start an
  // all-clients monitor for each.
  function veloMonAuto() {
    const caseId = veloCaseId();
    const msg = document.getElementById("veloMonAutoMsg");
    if (!caseId) {
      if (msg) msg.textContent = "connect to a case first";
      return;
    }
    if (!veloEnabled) {
      if (msg) msg.textContent = "Velociraptor API not configured";
      return;
    }
    const btn = document.getElementById("veloMonAutoBtn");
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "discovering configured client events…";
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/monitors/auto`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg) msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        const n = (j.started || []).length;
        if (msg)
          msg.textContent = `started ${n} all-clients monitor(s): ${(j.discovered || []).join(", ")}`;
        loadVeloMonitors(caseId);
      })
      .catch((e) => {
        if (msg)
          msg.textContent =
            "error: " +
            e.message +
            " — restart the companion server if this 404s";
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  // The four monitor controls. They were bound by the bundle builder's wireVeloTriage() —
  // adjacent in the inline block, but they drive THIS feature. With them left there, removing
  // the bundles module killed the monitors' Start button and the chip named the wrong feature.
  function initVeloMonitors() {
    const monBrowse = document.getElementById("veloMonBrowseBtn");
    if (monBrowse) monBrowse.onclick = veloMonBrowse;
    const monStart = document.getElementById("veloMonStartBtn");
    if (monStart) monStart.onclick = veloMonStart;
    const monAuto = document.getElementById("veloMonAutoBtn");
    if (monAuto) monAuto.onclick = veloMonAuto;
    const monAll = document.getElementById("veloMonAllClients");
    if (monAll) monAll.onchange = veloMonSyncAllClients;
  }
  window.initVeloMonitors = initVeloMonitors;
  window.loadVeloMonitors = loadVeloMonitors;
  window.veloMonBrowse = veloMonBrowse;
  window.veloMonSyncAllClients = veloMonSyncAllClients;
  window.veloMonStart = veloMonStart;
  window.veloMonAuto = veloMonAuto;
})();
