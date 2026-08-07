// Settings → Tools, MCP servers, and the update check (#127) (#415 tier 3).
//
// THREE PANELS, ONE MODULE, and the banner comment in the inline block named only the last of them.
// They ship together because they are one Settings screen and share nothing with anything else: the
// external tool list and its per-tool rules, the MCP server registry, and the opt-in "newer release
// available" notice. Only loadTools and loadUpdateCheck are called from outside; the other ten
// functions belong to this screen.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: _mcpDiscovered, the last discovery result the server picker
// reads back. One binding, but this is a CLASSIC script, so unwrapped it would join the shared
// global lexical environment and be reachable by name from every other script on the page.
//
// ITS WIRING IS AN INITIALIZER, and there is more of it than it looks. SIX statements ran at module
// scope, not the three that a search for lines beginning `document.` finds — three of them are bare
// `{ … }` blocks that scope a `const b` around one button. In a <head> script every one of those
// queries its element before the markup exists and binds nothing, silently, which is the failure
// this whole pattern exists to prevent. They were split out by parsing the block, not by matching
// line shapes.
(function () {
  // --- Update check (#127) — opt-in "newer release available" notice; Settings → Updates ----------
  function renderUpdateBanner(j) {
    const banner = document.getElementById("updateBanner");
    if (!banner) return;
    const dismissed =
      sessionStorage.getItem("updDismissed") === (j.latestTag || "");
    if (j && j.isNewer && j.htmlUrl && !dismissed) {
      banner.innerHTML =
        `🔔 A newer DFIR Companion (<strong>${esc(j.latestTag || j.latest)}</strong>) is available — you're on ${esc(j.current)}. ` +
        `<a href="${escAttr(j.htmlUrl)}" target="_blank" rel="noopener">View release</a> ` +
        `<a href="#" id="updDismiss" data-safe-style="margin-left:8px;color:#9aa4b2">dismiss</a>`;
      banner.style.display = "block";
      const d = document.getElementById("updDismiss");
      if (d)
        d.onclick = (e) => {
          e.preventDefault();
          sessionStorage.setItem("updDismissed", j.latestTag || "");
          banner.style.display = "none";
        };
    } else {
      banner.style.display = "none";
    }
  }

  // External forensic tools (#211): show which tools are configured + wire the per-tool Update-rules
  //
  // `wireToolRules` was `wire`. The "leaves nothing behind" census compares bindings at ANY depth on
  // both sides, and the page has an unrelated `const wire` of its own inside another function, so
  // the plain name read as a leftover. The longer name says what it wires and is better here either
  // way — but the gate's false positive is real: a duplicate that matters is one that can shadow.
  // buttons. Env fields are populated by the generic fetchEnvSettings (like every other settings tab).
  function loadTools() {
    const wireToolRules = () => {
      document
        .querySelectorAll("#stab-tools .tool-update")
        .forEach(
          (b) =>
            (b.onclick = () => updateToolRules(b.getAttribute("data-tool"), b)),
        );
    };
    fetch("/tools/status")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        const el = document.getElementById("toolsStatus");
        if (!el) return wireToolRules();
        if (!j || !j.enabled) {
          el.innerHTML = `Tool runner not available — restart the companion server if this 404s.`;
          return wireToolRules();
        }
        const rows = (j.tools || [])
          .map((t) => {
            const state = t.configured
              ? `<span data-safe-style="color:#7fd08a">configured</span>${t.autoRun ? " · auto-run on" : " · auto-run off"}`
              : `<span data-safe-style="color:var(--text-dim)">off</span>`;
            return `<div>${esc(t.label)} — ${state}${t.hasUpdate ? "" : " · no update command"}</div>`;
          })
          .join("");
        el.innerHTML = rows || "no tools";
        wireToolRules();
      })
      .catch(() => wireToolRules());
    loadCustomTools();
    loadMcpServers();
  }
  // Custom tools (#211): list existing + wire delete; the add form posts /tools/custom.
  function loadCustomTools() {
    const el = document.getElementById("customToolList");
    if (!el) return;
    fetch("/tools/custom")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        const tools = (j && j.tools) || [];
        if (!tools.length) {
          el.innerHTML = `<div data-safe-style="color:var(--text-dim);font-size:12px">No custom tools yet.</div>`;
          return;
        }
        el.innerHTML = tools
          .map(
            (t) =>
              `<div data-safe-style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:6px 8px;border:1px solid var(--border-color);border-radius:6px;margin-bottom:6px">
          <strong>${esc(t.name)}</strong>
          <span data-safe-style="color:var(--text-muted);font-size:12px">${esc((t.extensions || []).join(", ") || "no extensions")}${t.autoRun ? " · auto-run on" : ""}</span>
          <code data-safe-style="font-size:11px;color:var(--text-dim)">${esc(t.binary)} ${esc(t.runArgs || "")}</code>
          <button class="ct-del" data-id="${esc(t.id)}" type="button" data-safe-style="margin-left:auto;padding:1px 8px;font-size:11px">Delete</button>
        </div>`,
          )
          .join("");
        el.querySelectorAll(".ct-del").forEach(
          (b) =>
            (b.onclick = () => deleteCustomTool(b.getAttribute("data-id"))),
        );
      })
      .catch(() => {
        el.innerHTML = `<div data-safe-style="color:var(--text-dim);font-size:12px">Custom tools unavailable — restart the companion server if this 404s.</div>`;
      });
  }
  function addCustomTool() {
    const msg = document.getElementById("ctMsg");
    const body = {
      name: (document.getElementById("ctName").value || "").trim(),
      binary: (document.getElementById("ctBinary").value || "").trim(),
      runArgs: (document.getElementById("ctRunArgs").value || "").trim(),
      updateCommand: (
        document.getElementById("ctUpdateCmd").value || ""
      ).trim(),
      extensions: (document.getElementById("ctExtensions").value || "").trim(),
      autoRun: /^(on|true|yes|1)$/i.test(
        (document.getElementById("ctAutoRun").value || "").trim(),
      ),
    };
    if (!body.name || !body.binary) {
      if (msg) msg.textContent = "name and binary path are required";
      return;
    }
    if (msg) msg.textContent = "adding…";
    fetch("/tools/custom", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) {
          if (msg)
            msg.textContent =
              (j && j.error ? j.error : "add failed") +
              " — restart the companion server if this 404s";
          return;
        }
        if (msg) msg.textContent = `added "${j.tool.name}"`;
        [
          "ctName",
          "ctBinary",
          "ctRunArgs",
          "ctUpdateCmd",
          "ctExtensions",
          "ctAutoRun",
        ].forEach((id) => {
          const e = document.getElementById(id);
          if (e) e.value = "";
        });
        loadCustomTools(); // shows the new one + a fresh empty form to add another
      })
      .catch((e) => {
        if (msg) msg.textContent = "add failed: " + e.message;
      });
  }
  function deleteCustomTool(id) {
    if (!id) return;
    fetch(`/tools/custom/${encodeURIComponent(id)}`, { method: "DELETE" })
      .then(() => loadCustomTools())
      .catch(() => {});
  }

  // MCP servers (#296). The Companion holds no URL and no token — Claude Code is configured with
  // the servers and does the talking. /mcp/status is cache-only, so opening this tab never spawns
  // the CLI; "Refresh from Claude Code" is what asks.
  let _mcpDiscovered = [];
  function loadMcpServers() {
    const el = document.getElementById("mcpServerList");
    if (!el) return;
    fetch("/mcp/status")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (!j || !j.enabled) {
          el.innerHTML = `<div data-safe-style="color:var(--text-dim);font-size:12px">MCP unavailable — restart the companion server if this 404s.</div>`;
          return;
        }
        _mcpDiscovered = (j.claudeCode && j.claudeCode.servers) || [];
        fillMcpServerPicker(j.servers || []);
        const banner =
          j.claudeCode && j.claudeCode.error
            ? `<div data-safe-style="font-size:12px;color:#f0776c;margin-bottom:6px">Claude Code: ${esc(j.claudeCode.error)}</div>`
            : !j.claudeCode
              ? `<div data-safe-style="font-size:12px;color:var(--text-dim);margin-bottom:6px">Claude Code not asked yet — press Refresh to load its server list.</div>`
              : "";
        const servers = j.servers || [];
        if (!servers.length) {
          el.innerHTML =
            banner +
            `<div data-safe-style="color:var(--text-dim);font-size:12px">No servers allowed yet.</div>`;
          return;
        }
        el.innerHTML =
          banner +
          servers
            .map((s) => {
              // Three states, deliberately distinct: not asked, asked and absent, asked and present.
              const known =
                s.knownToClaudeCode === null
                  ? `<span data-safe-style="color:var(--text-dim)">not checked</span>`
                  : !s.knownToClaudeCode
                    ? `<span data-safe-style="color:#f0776c" title="Claude Code has no server by this name">not in Claude Code</span>`
                    : s.connected
                      ? `<span data-safe-style="color:#7fd08a">connected</span>`
                      : `<span data-safe-style="color:#d29922">${esc(s.status || "not connected")}</span>`;
              const tools = (s.allowedTools || []).length
                ? esc(s.allowedTools.join(", "))
                : "all";
              const cmds = (s.allowedCommands || []).length
                ? esc(s.allowedCommands.join(", "))
                : "all";
              const delivery =
                s.delivery && s.delivery.mode === "scp"
                  ? `scp → ${esc((s.delivery.user ? s.delivery.user + "@" : "") + s.delivery.host + ":" + s.delivery.remoteDir)}`
                  : s.delivery && s.delivery.localPrefix
                    ? `shared path ${esc(s.delivery.localPrefix)} → ${esc(s.delivery.remotePrefix)}`
                    : `shared path (same both sides)`;
              return `<div data-safe-style="padding:6px 8px;border:1px solid var(--border-color);border-radius:6px;margin-bottom:6px">
          <div data-safe-style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
            <strong>${esc(s.label || s.id)}</strong>
            <code data-safe-style="font-size:11px;color:var(--text-dim)">${esc(s.id)}</code>
            <span data-safe-style="font-size:12px;color:var(--text-muted)">${known}${s.enabled ? ` · plain-English analysis allowed` : ` · <span data-safe-style="color:#d29922">disabled</span>`}</span>
            <button class="mcp-del" data-id="${esc(s.id)}" type="button" data-safe-style="margin-left:auto;padding:1px 8px;font-size:11px">Remove</button>
          </div>
          <div data-safe-style="font-size:11px;color:var(--text-dim);margin-top:3px">
            ${esc(delivery)} · tools: ${tools} · commands: ${cmds}
          </div>
        </div>`;
            })
            .join("");
        el.querySelectorAll(".mcp-del").forEach(
          (b) => (b.onclick = () => deleteMcpServer(b.getAttribute("data-id"))),
        );
      })
      .catch(() => {
        el.innerHTML = `<div data-safe-style="color:var(--text-dim);font-size:12px">MCP unavailable — restart the companion server if this 404s.</div>`;
      });
  }
  // Offer Claude Code's real server names rather than asking for free text — a typo here is a
  // policy entry that silently never matches anything.
  function fillMcpServerPicker(already) {
    const sel = document.getElementById("mcpServerName");
    if (!sel) return;
    const taken = new Set((already || []).map((s) => s.id));
    const free = _mcpDiscovered.filter((d) => !taken.has(d.name));
    sel.innerHTML = free.length
      ? free
          .map(
            (d) =>
              `<option value="${esc(d.name)}">${esc(d.name)}${d.connected ? "" : " (not connected)"}</option>`,
          )
          .join("")
      : `<option value="">${_mcpDiscovered.length ? "(all of Claude Code's servers are already listed)" : "(press Refresh to load Claude Code's servers)"}</option>`;
  }
  function addMcpServer() {
    const msg = document.getElementById("mcpMsg");
    const val = (id) =>
      (document.getElementById(id) || {}).value
        ? document.getElementById(id).value.trim()
        : "";
    const mode = val("mcpDeliveryMode") || "remote-path";
    const port = parseInt(val("mcpPort"), 10);
    const body = {
      id: val("mcpServerName"),
      label: val("mcpLabel"),
      allowedTools: val("mcpAllowedTools"),
      allowedCommands: val("mcpAllowedCommands"),
      delivery: {
        mode,
        ...(mode === "scp"
          ? {
              host: val("mcpHost"),
              user: val("mcpUser"),
              remoteDir: val("mcpRemoteDir"),
              identityFile: val("mcpIdentityFile"),
              ...(port > 0 ? { port } : {}),
            }
          : {
              localPrefix: val("mcpLocalPrefix"),
              remotePrefix: val("mcpRemotePrefix"),
            }),
      },
    };
    if (!body.id) {
      if (msg)
        msg.textContent =
          "pick one of Claude Code's servers — press Refresh if the list is empty";
      return;
    }
    if (msg) msg.textContent = "saving…";
    fetch("/mcp/servers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) {
          if (msg)
            msg.textContent =
              (j && j.error ? j.error : "save failed") +
              " — restart the companion server if this 404s";
          return;
        }
        if (msg) msg.textContent = `allowed "${j.server.label}"`;
        [
          "mcpLabel",
          "mcpAllowedTools",
          "mcpAllowedCommands",
          "mcpLocalPrefix",
          "mcpRemotePrefix",
          "mcpHost",
          "mcpUser",
          "mcpPort",
          "mcpIdentityFile",
          "mcpRemoteDir",
        ].forEach((id) => {
          const e = document.getElementById(id);
          if (e) e.value = "";
        });
        loadMcpServers();
      })
      .catch((e) => {
        if (msg) msg.textContent = "save failed: " + e.message;
      });
  }
  function deleteMcpServer(id) {
    if (!id) return;
    fetch(`/mcp/servers/${encodeURIComponent(id)}`, { method: "DELETE" })
      .then(() => loadMcpServers())
      .catch(() => {});
  }
  function updateToolRules(toolId, btn) {
    const caseId = (document.getElementById("caseId").value || "").trim();
    const msg = document.getElementById("toolsMsg");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Updating…";
    }
    // Case id is only needed for the route path; use the connected case, or "_" (the command is global).
    fetch(
      `/cases/${encodeURIComponent(caseId || "_")}/tools/${toolId}/update-rules`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    )
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "↻ Update rules";
        }
        if (msg)
          msg.textContent = ok
            ? `${toolId}: ${(j.output || "updated").slice(0, 200)}`
            : (j.error || "update failed") +
              " — restart the companion server if this 404s";
      })
      .catch((e) => {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "↻ Update rules";
        }
        if (msg) msg.textContent = "update failed: " + e.message;
      });
  }

  function loadUpdateCheck() {
    return fetch("/update-check")
      .then((r) => r.json())
      .then((j) => {
        const en = document.getElementById("updEnabled");
        const locked = document.getElementById("updLocked");
        const status = document.getElementById("updStatus");
        if (en) {
          en.checked = !!j.enabled;
          en.disabled = !!j.locked;
        }
        if (locked) locked.style.display = j.locked ? "inline" : "none";
        if (status) {
          if (j.error) status.innerHTML = `last check failed: ${esc(j.error)}`;
          else if (j.checkedAt)
            status.innerHTML = `current ${esc(j.current)} · latest ${esc(j.latest || "?")} · checked ${esc(new Date(j.checkedAt).toLocaleString())}`;
          else status.textContent = `current ${j.current} — not checked yet`;
        }
        renderUpdateBanner(j);
        return j;
      })
      .catch(() => {
        const status = document.getElementById("updStatus");
        if (status)
          status.textContent =
            "unavailable — restart the companion server if this 404s";
      });
  }

  // Health / Diagnostics (#118) moved to js/dashboard-diagnostics.js (#415 tier 3). Its five
  // controls are bound by initDiagnostics(), called from the Settings block above, which is also
  // where a missing file is reported — one report, not two.

  // The six statements the inline block ran at module scope, in their original order.
  function initSettingsTools() {
    {
      const b = document.getElementById("ctAddBtn");
      if (b) b.onclick = addCustomTool;
    }
    {
      const b = document.getElementById("mcpAddBtn");
      if (b) b.onclick = addMcpServer;
    }
    {
      const b = document.getElementById("mcpDiscoverBtn");
      if (b)
        b.onclick = () => {
          const msg = document.getElementById("mcpDiscoverMsg");
          if (msg) msg.textContent = "asking Claude Code…";
          b.disabled = true;
          fetch("/mcp/discover", { method: "POST" })
            .then((r) => r.json())
            .then((j) => {
              b.disabled = false;
              // Claude Code being unavailable is an answer, not a failure — render it.
              if (msg)
                msg.textContent = j.ok
                  ? `${(j.servers || []).length} server(s) configured in Claude Code`
                  : j.error;
              loadMcpServers();
            })
            .catch((e) => {
              b.disabled = false;
              if (msg) msg.textContent = "refresh failed: " + e.message;
            });
        };
    }
    document.getElementById("toolsReconnectBtn").onclick = async () => {
      const msg = document.getElementById("toolsMsg");
      if (msg) msg.textContent = "saving…";
      const saved = await saveSettings();
      if (!saved) {
        if (msg)
          msg.textContent = "save failed — fix the error above and retry";
        return;
      }
      if (msg) msg.textContent = "applying…";
      Promise.all([
        fetch("/tools/reconnect", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }).then((r) => r.json()),
        fetch("/mcp/reconnect", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }).then((r) => r.json()),
      ])
        .then(([tools, mcp]) => {
          if (msg)
            msg.textContent =
              tools.ok && mcp.ok
                ? `applied — ${(tools.configured || []).length} local tool(s), MCP settings refreshed`
                : tools.error || mcp.error || "reconnect failed";
          loadTools();
          loadMcpServers();
        })
        .catch((e) => {
          if (msg)
            msg.textContent =
              "reconnect failed: " +
              e.message +
              " — restart the companion server if this 404s";
        });
    };
    document
      .getElementById("updEnabled")
      ?.addEventListener("change", function () {
        const msg = document.getElementById("updMsg");
        fetch("/update-check/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: this.checked }),
        })
          .then((r) => r.json())
          .then((j) => {
            if (msg) msg.textContent = j.error ? "error: " + j.error : "saved";
            loadUpdateCheck();
          })
          .catch((e) => {
            this.checked = !this.checked;
            if (msg)
              msg.textContent =
                "failed (restart the companion server?): " + e.message;
          });
      });
    document
      .getElementById("updCheckNowBtn")
      ?.addEventListener("click", function () {
        const msg = document.getElementById("updMsg");
        if (msg) msg.textContent = "checking…";
        fetch("/update-check/run", { method: "POST" })
          .then((r) => r.json())
          .then((j) => {
            if (msg) msg.textContent = j.error ? "error: " + j.error : "done";
            loadUpdateCheck();
          })
          .catch((e) => {
            if (msg)
              msg.textContent =
                "failed (restart the companion server?): " + e.message;
          });
      });
  }

  window.loadTools = loadTools;
  window.loadUpdateCheck = loadUpdateCheck;
  window.initSettingsTools = initSettingsTools;
})();
