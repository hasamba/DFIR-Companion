// Velociraptor triage — the bundle list, the client inventory, the hunt jobs and the collection
// they drive (#415 tier 3).
//
// SEVEN BINDINGS CROSSED THE BOUNDARY AND NONE OF THEM IS PUBLISHED. Two already-extracted modules
// read them through the shared global lexical environment that a classic script's top-level `let`s
// live in, and the fix is different for each kind:
//
//   THREE WERE IN THE WRONG FILE. veloArtifactCache, veloEditingId and _veloEventArtifacts are
//   declared here and never touched here — one module writes and reads each. Their declarations
//   moved into that module. There was no escape, only a misplaced `let`.
//
//   FOUR ARE GENUINELY SHARED, so this module keeps the write and hands out the value:
//   veloBundlesList(), veloClientsList() and veloMonAutoBrowsed()/
//   setVeloMonAutoBrowsed(). Publishing the bindings would have kept the coupling and renamed it.
(function () {
  // ── Velociraptor triage bundles ──────────────────────────────────────────────
  // Build named bundles of CLIENT artifacts, run one as a hunt, then auto-collect → import →
  // synthesize after a delay. Bundles are global (shared across cases); the job is per-case.
  let veloCountdownTimer = null; // interval updating the running-job countdown
  let _veloBundles = null; // last-loaded bundle list
  let _veloClients = []; // last-loaded client inventory (host ↔ client id), for the monitor datalist
  let _veloMonAutoBrowsed = false; // one-shot: auto-populate the event-artifact picker when Velociraptor is on
  let veloTsPreviewSeq = 0; // monotonic counter guarding the time-scope preview against out-of-order responses

  function veloCaseId() {
    const el = document.getElementById("caseId");
    return el ? el.value.trim() : "";
  }

  function applyVeloEnabled() {
    const note = document.getElementById("veloDisabledNote");
    if (note) note.style.display = veloEnabled ? "none" : "block";
    if (_veloBundles) renderVeloBundles(_veloBundles); // re-render so Run buttons reflect state
    // As soon as Velociraptor is known-on, pre-load the CLIENT_EVENT picker (once) so it's not empty.
    if (veloEnabled && !_veloMonAutoBrowsed) {
      _veloMonAutoBrowsed = true;
      veloMonBrowse();
    }
  }

  function loadVeloBundles() {
    return fetch("/bundles")
      .then((r) => (r.ok ? r.json() : []))
      .then((b) => {
        _veloBundles = Array.isArray(b) ? b : [];
        renderVeloBundles(_veloBundles);
      })
      .catch(() => {
        _veloBundles = [];
        renderVeloBundles([]);
      });
  }

  function loadVeloTriage(caseId) {
    // The builder's selection belongs to js/dashboard-velo-bundles.js; ask it to clear.
    if (typeof resetVeloSelected === "function") resetVeloSelected();
    renderVeloSelected();
    loadVeloBundles();
    loadVeloHuntJobs(caseId);
    loadVeloClients();
    loadVeloMonitors(caseId);
  }

  function renderVeloClients(inv) {
    _veloClients = inv.clients || [];
    // Feed the live-monitor client datalist (hostname/fqdn → client id) so the analyst can pick a host.
    const dl = document.getElementById("veloMonClientList");
    if (dl)
      dl.innerHTML = _veloClients
        .map(
          (c) =>
            `<option value="${escAttr(c.clientId)}">${escAttr((c.hostname || c.fqdn || "") + " — " + c.clientId)}</option>`,
        )
        .join("");
    const msg = document.getElementById("veloClientsMsg");
    if (!msg) return;
    const n = _veloClients.length;
    msg.textContent = n
      ? `${n} enrolled client${n === 1 ? "" : "s"} · updated ${veloClientsAge(inv.updatedAt)}`
      : veloEnabled
        ? "no clients cached yet — click Refresh to snapshot the fleet"
        : "Velociraptor API not configured";
  }
  function loadVeloClients() {
    fetch("/velociraptor/clients")
      .then((r) => (r.ok ? r.json() : { updatedAt: "", clients: [] }))
      .then(renderVeloClients)
      .catch(() => {});
  }
  function doRefreshVeloClients() {
    const btn = document.getElementById("veloRefreshClientsBtn");
    const msg = document.getElementById("veloClientsMsg");
    if (!veloEnabled) {
      if (msg)
        msg.textContent =
          "Velociraptor API not configured — click Reconnect (after setting the API config path on Integrations)";
      return;
    }
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "querying the Velociraptor server…";
    fetch("/velociraptor/clients/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          if (msg)
            msg.textContent =
              "error: " +
              (j.error || "refresh failed") +
              " — try Reconnect if the server was down";
          return;
        }
        renderVeloClients({ updatedAt: j.updatedAt, clients: j.clients || [] });
      })
      .catch((e) => {
        if (msg) msg.textContent = "error: " + e.message;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  // Save any unsaved field edits, then re-read .env, rebuild the Velociraptor client, and refresh
  // the inventory (the reachability probe). Works even when the API wasn't configured at boot or
  // the server was down — no companion restart.
  async function doVeloReconnect() {
    const btn = document.getElementById("veloReconnectBtn");
    const msg = document.getElementById("veloClientsMsg");
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = "saving…";
    const saved = await saveSettings();
    if (!saved) {
      if (msg) msg.textContent = "save failed — fix the error above and retry";
      if (btn) btn.disabled = false;
      return;
    }
    if (msg) msg.textContent = "reconnecting to the Velociraptor server…";
    fetch("/velociraptor/reconnect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok) {
          if (msg)
            msg.textContent =
              "error: " +
              (j.error || "reconnect failed") +
              " — restart the companion server if this 404s";
          return;
        }
        // Reflect the (possibly newly) configured client across the velo UI without a page reload.
        veloEnabled = !!j.configured;
        applyVeloEnabled();
        if (!j.configured) {
          if (msg)
            msg.textContent =
              "Velociraptor API not configured — set the API config path on the Integrations tab and reconnect";
          return;
        }
        if (!j.ok) {
          if (msg)
            msg.textContent =
              "⚠ configured but unreachable: " +
              (j.error || "the Velociraptor server is not responding");
          return;
        }
        if (msg)
          msg.textContent = `✓ connected — ${j.clients || 0} enrolled client(s)`;
        loadVeloClients();
        _veloMonAutoBrowsed = false; // re-populate the event-artifact picker against the (re)connected server
        loadVeloMonitors(veloCaseId());
      })
      .catch((e) => {
        if (msg) msg.textContent = "error: " + e.message;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }

  function renderVeloBundles(bundles) {
    const el = document.getElementById("veloBundleList");
    if (!el) return;
    if (!bundles.length) {
      el.innerHTML =
        "<div data-safe-style='color:var(--text-muted);font-size:12px'>No bundles yet — build one below.</div>";
      return;
    }
    el.innerHTML = bundles
      .map((b) => {
        const runBtn = veloEnabled
          ? `<button class="velo-run-btn" data-id="${escAttr(b.id)}" title="Run this bundle as a hunt on the configured Velociraptor server">▶ Run</button>`
          : `<button disabled title="Velociraptor API not configured (set the API config path above)">▶ Run</button>`;
        const editBtn = `<button class="velo-edit-btn" data-id="${escAttr(b.id)}" title="Edit this bundle">Edit</button>`;
        const dupBtn = `<button class="velo-dup-btn" data-id="${escAttr(b.id)}" title="Copy into the builder as a new bundle">Duplicate</button>`;
        // Built-ins can be edited in place; "Reset to default" appears once an override exists. Custom
        // bundles get Delete.
        const tailBtn = b.builtIn
          ? b.customized
            ? `<button class="velo-reset-btn" data-id="${escAttr(b.id)}" title="Discard your edits and restore the shipped default" data-safe-style="background:var(--warning-bg-strong);color:var(--tag-orange-text)">Reset to default</button>`
            : ""
          : `<button class="velo-del-btn" data-id="${escAttr(b.id)}" data-safe-style="background:var(--info-bg);color:var(--tag-red-text)">Delete</button>`;
        const badge = b.builtIn
          ? ` <span data-safe-style='color:var(--accent);font-size:11px'>built-in${b.customized ? " · edited" : ""}</span>`
          : "";
        const tuned =
          (b.params ? Object.keys(b.params).length : 0) +
          (b.filters ? Object.keys(b.filters).length : 0);
        const expiryLbl =
          { 3600: "1h", 86400: "1d", 604800: "1w" }[b.expirySeconds || 3600] ||
          `${Math.round((b.expirySeconds || 3600) / 3600)}h`;
        const meta =
          (b.defaultWaitMinutes
            ? ` · wait ${esc(b.defaultWaitMinutes)}m`
            : "") +
          (b.timeoutSeconds ? ` · timeout ${esc(b.timeoutSeconds)}s` : "") +
          ` · expires ${expiryLbl}` +
          (tuned ? ` · ${tuned} tuned` : "");
        return `<div class="velo-bundle" data-safe-style="border:1px solid var(--border-color);border-radius:6px;padding:8px 10px;margin-bottom:8px">
        <div data-safe-style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <div><strong>${esc(b.name)}</strong>${badge} <span data-safe-style="color:var(--text-muted);font-size:11px">${esc(b.artifacts.length)} artifact(s)${meta}</span></div>
          <div data-safe-style="display:flex;gap:6px;flex-wrap:wrap">${runBtn}${editBtn}${dupBtn}${tailBtn}</div>
        </div>
        ${b.description ? `<div data-safe-style="color:var(--text-muted);font-size:12px;margin-top:4px">${esc(b.description)}</div>` : ""}
        <div data-safe-style="color:var(--text-dim);font-size:11px;margin-top:4px">${b.artifacts.map((a) => esc(a)).join(", ")}</div>
        <div class="velo-run-form" data-id="${escAttr(b.id)}" data-safe-style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid var(--border-color)"></div>
      </div>`;
      })
      .join("");
    el.querySelectorAll(".velo-run-btn").forEach(
      (btn) => (btn.onclick = () => toggleVeloRunForm(btn.dataset.id)),
    );
    el.querySelectorAll(".velo-edit-btn").forEach(
      (btn) => (btn.onclick = () => veloEdit(btn.dataset.id)),
    );
    el.querySelectorAll(".velo-dup-btn").forEach(
      (btn) => (btn.onclick = () => veloDuplicate(btn.dataset.id)),
    );
    el.querySelectorAll(".velo-del-btn").forEach(
      (btn) => (btn.onclick = () => veloDeleteBundle(btn.dataset.id)),
    );
    el.querySelectorAll(".velo-reset-btn").forEach(
      (btn) => (btn.onclick = () => veloResetBuiltin(btn.dataset.id)),
    );
  }

  function veloRunForm(id) {
    const forms = document.querySelectorAll(".velo-run-form");
    for (const f of forms) if (f.dataset.id === id) return f;
    return null;
  }
  function toggleVeloRunForm(id) {
    const bundle = (_veloBundles || []).find((b) => b.id === id);
    const form = veloRunForm(id);
    if (!form || !bundle) return;
    if (form.style.display === "block") {
      form.style.display = "none";
      return;
    }
    document
      .querySelectorAll(".velo-run-form")
      .forEach((f) => (f.style.display = "none"));
    const defWait = bundle.defaultWaitMinutes || 10;
    // The collection timeout is a BUNDLE property (set in the editor) — the run uses it, not a re-prompt.
    const timeoutNote = bundle.timeoutSeconds
      ? `${esc(bundle.timeoutSeconds)}s`
      : "600s (Velociraptor default)";
    // Expiry defaults to the bundle's own default (1 hour when unset); it's overridable per run.
    const defExpiry = bundle.expirySeconds || 3600;
    const expiryOpts = [
      [3600, "1 hour"],
      [86400, "1 day"],
      [604800, "1 week"],
    ]
      .map(
        ([v, lbl]) =>
          `<option value="${v}"${v === defExpiry ? " selected" : ""}>expires: ${lbl}</option>`,
      )
      .join("");
    form.innerHTML = `
      <div data-safe-style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <label data-safe-style="font-size:12px;color:var(--text-muted)">Wait <input type="number" class="velo-wait" min="1" max="1440" value="${esc(defWait)}" data-safe-style="width:64px;padding:4px" /> min</label>
        <select class="velo-expiry" title="How long the hunt keeps scheduling on clients that check in later (Velociraptor's own default is a week)">${expiryOpts}</select>
        <select class="velo-os" title="Restrict to a client OS"><option value="">any OS</option><option value="windows">windows</option><option value="linux">linux</option><option value="darwin">darwin</option></select>
        <select class="velo-minsev" title="Only import events at or above this severity (keeps volume down). Telemetry with no severity is always kept."><option value="">all severities</option><option value="info">info+</option><option value="low">low+</option><option value="medium">medium+</option><option value="high">high+</option><option value="critical">critical only</option></select>
        <select class="velo-timescope" title="Collect only data from this window. Applied AT THE SOURCE via each artifact's own date parameters — not filtered after collection.">
          <option value="">All time</option>
          <option value="24h">last 24 hours</option>
          <option value="7d">last 7 days</option>
          <option value="30d">last 30 days</option>
          <option value="90d">last 90 days</option>
          <option value="custom">custom range…</option>
        </select>
        <span class="velo-ts-custom" data-safe-style="display:none;gap:4px;align-items:center">
          <input type="datetime-local" class="velo-ts-start" title="Collect from (UTC)" data-safe-style="padding:4px" />
          <span data-safe-style="font-size:10px;color:var(--text-muted)">UTC</span>
          <span data-safe-style="color:var(--text-dim)">–</span>
          <input type="datetime-local" class="velo-ts-end" title="Collect until (UTC) — leave empty to keep collecting forward" data-safe-style="padding:4px" />
          <span data-safe-style="font-size:10px;color:var(--text-muted)">UTC</span>
        </span>
        <input class="velo-inc" placeholder="include labels (comma-sep)" data-safe-style="flex:1;min-width:140px;padding:4px" />
        <input class="velo-exc" placeholder="exclude labels (comma-sep)" data-safe-style="flex:1;min-width:140px;padding:4px" />
        <button class="velo-run-go">Run hunt</button>
        <span class="velo-run-msg" data-safe-style="font-size:12px;color:var(--text-muted)"></span>
      </div>
      <div data-safe-style="font-size:11px;color:var(--text-dim);margin-top:4px">Runs across all enrolled clients unless you set a label/OS filter. Collection timeout: <strong>${timeoutNote}</strong> — set it on the bundle (<em>Edit</em>) for slow artifacts like THOR. Results (+ any uploaded JSON report) are auto-collected after the wait, then imported + synthesized — or click <em>Collect now</em> on the job card.</div>
      <div class="velo-ts-preview" data-safe-style="font-size:11px;color:var(--text-dim);margin-top:4px"></div>`;
    form.style.display = "block";
    form.querySelector(".velo-run-go").onclick = () => veloRunBundle(id, form);
    const ts = form.querySelector(".velo-timescope");
    const custom = form.querySelector(".velo-ts-custom");
    ts.onchange = () => {
      custom.style.display = ts.value === "custom" ? "inline-flex" : "none";
      veloTimeScopePreview(id, form);
    };
    form.querySelector(".velo-ts-start").onchange = () =>
      veloTimeScopePreview(id, form);
    form.querySelector(".velo-ts-end").onchange = () =>
      veloTimeScopePreview(id, form);
  }

  // Show which artifacts the chosen window will actually bound, before anything is launched. A bad
  // auto-detected mapping must be visible here rather than silently under-collecting.
  function veloTimeScopePreview(bundleId, form) {
    const out = form.querySelector(".velo-ts-preview");
    if (veloTimeScopeIncomplete(form)) {
      out.textContent = "⚠ enter a start date to apply a custom time scope";
      return;
    }
    const body = veloTimeScopeBody(form);
    if (!body) {
      out.textContent = "";
      return;
    }
    out.textContent = "checking which artifacts can be scoped…";
    // Rapid dropdown/date changes fire overlapping fetches with no inherent ordering guarantee; a
    // monotonic sequence number lets a stale response recognize it's been superseded and no-op instead
    // of overwriting the preview with a mapping that doesn't match the currently selected scope.
    const mySeq = ++veloTsPreviewSeq;
    fetch(
      `/velociraptor/bundles/${encodeURIComponent(bundleId)}/time-scope-preview`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
    )
      .then((r) =>
        r
          .json()
          .then((j) => ({ ok: r.ok, j }))
          .catch(() => ({ ok: r.ok, j: {} })),
      )
      .then(({ ok, j }) => {
        if (mySeq !== veloTsPreviewSeq) return; // a newer request superseded this one
        if (!ok || j.error) {
          out.textContent = "⚠ " + (j.error || "preview failed");
          return;
        }
        const total = j.scoped.length + j.unscoped.length;
        // Each row's ".velo-ts-row-dirty" starts hidden and is only revealed by the `oninput` listener
        // wired below — it distinguishes "this is what's actually saved" from "this is what you just
        // typed", since the source label itself is computed once from this response and never updates
        // as the analyst edits the inputs.
        const detail = j.scoped
          .map(
            (
              s,
            ) => `<div class="velo-ts-row" data-artifact="${escAttr(s.artifact)}" data-safe-style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:2px">
          <span data-safe-style="min-width:260px">${esc(s.artifact)}</span>
          <input class="velo-ts-p-start" value="${escAttr(s.startParam || "")}" placeholder="start param" data-safe-style="width:130px;padding:2px;font-size:11px" />
          <input class="velo-ts-p-end" value="${escAttr(s.endParam || "")}" placeholder="end param" data-safe-style="width:130px;padding:2px;font-size:11px" />
          <span data-safe-style="color:var(--text-dim)">${esc(s.source)}${s.manual ? " · manually set" : ""}</span>
          <span class="velo-ts-row-dirty" data-safe-style="display:none;color:var(--tag-orange-text)"> · unsaved</span>
        </div>`,
          )
          .join("");
        const full = j.unscoped.map((u) => esc(u.artifact)).join(", ");
        out.innerHTML = `<details><summary data-safe-style="cursor:pointer">Time scope applies to <strong>${j.scoped.length} of ${total}</strong> artifact(s)${j.unscoped.length ? ` · ${j.unscoped.length} collect in full` : ""}${j.degraded ? ' · <span data-safe-style="color:var(--sev-high)">server reported no parameter metadata — coverage could not be verified</span>' : ""}</summary>
          <div data-safe-style="margin-top:4px">${detail || "<em>none</em>"}</div>
          ${full ? `<div data-safe-style="margin-top:4px;color:var(--text-muted)"><strong>Collects in full:</strong> ${full}</div>` : ""}
          <div data-safe-style="margin-top:6px"><button class="velo-ts-save" title="Save these parameter names on the bundle for future runs">Save mapping</button> <span class="velo-ts-save-msg" data-safe-style="color:var(--text-muted)"></span></div>
        </details>`;
        const saveBtn = out.querySelector(".velo-ts-save");
        if (saveBtn)
          saveBtn.onclick = () => veloSaveTimeScopeParamNames(bundleId, out);
        out.querySelectorAll(".velo-ts-row").forEach((row) => {
          const dirty = row.querySelector(".velo-ts-row-dirty");
          row
            .querySelectorAll(".velo-ts-p-start, .velo-ts-p-end")
            .forEach((inp) => {
              inp.oninput = () => {
                if (dirty) dirty.style.display = "inline";
              };
            });
        });
      })
      .catch((e) => {
        if (mySeq !== veloTsPreviewSeq) return;
        out.textContent = "⚠ " + e.message;
      });
  }

  // Persist the previewed parameter names onto the bundle so a corrected mapping sticks for future
  // runs. The server route is a full REPLACE of timeScopeParamNames (see its doc comment) — it has no
  // way to know which artifacts you meant to leave alone versus never heard of. So this function MUST
  // start from the bundle's currently-stored corrections (already on hand in _veloBundles — GET
  // /bundles returns timeScopeParamNames unfiltered) and only overlay the artifacts that have a
  // rendered row in THIS preview. Building the body from rows alone is the bug this replaced: an
  // artifact whose saved correction supplies only `end` renders as "collects in full" under a relative
  // preset (which never carries an upper bound), so it has no row here — and a naive rows-only save
  // would silently delete that correction while "fixing" an unrelated row.
  function veloSaveTimeScopeParamNames(bundleId, out) {
    const msg = out.querySelector(".velo-ts-save-msg");
    const saveBtn = out.querySelector(".velo-ts-save");
    const stored =
      ((_veloBundles || []).find((b) => b.id === bundleId) || {})
        .timeScopeParamNames || {};
    const timeScopeParamNames = { ...stored };
    out.querySelectorAll(".velo-ts-row").forEach((row) => {
      const artifact = row.dataset.artifact;
      const start = row.querySelector(".velo-ts-p-start").value.trim();
      const end = row.querySelector(".velo-ts-p-end").value.trim();
      // A row with both fields blank is the analyst explicitly clearing that artifact's correction —
      // remove it rather than leaving the stale stored value in place.
      if (start || end)
        timeScopeParamNames[artifact] = {
          ...(start ? { start } : {}),
          ...(end ? { end } : {}),
        };
      else delete timeScopeParamNames[artifact];
    });
    if (saveBtn) saveBtn.disabled = true;
    msg.textContent = "saving…";
    fetch(
      `/velociraptor/bundles/${encodeURIComponent(bundleId)}/time-scope-param-names`,
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ timeScopeParamNames }),
      },
    )
      .then((r) =>
        r
          .json()
          .catch(() => ({}))
          .then((j) => ({ ok: r.ok, j })),
      )
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        msg.textContent = "saved ✓";
        // Patch the saved bundle into the cached list IN PLACE rather than calling loadVeloBundles():
        // that fully re-renders the bundle list, which would collapse this open run form (and the
        // preview/rows/message the analyst needs to read right now) out from under them. Keeping
        // _veloBundles current still means the next preview and the built-in "· edited" badge see the
        // fresh timeScopeParamNames.
        if (_veloBundles) {
          const idx = _veloBundles.findIndex((b) => b.id === bundleId);
          if (idx !== -1) _veloBundles[idx] = j;
        }
        out.querySelectorAll(".velo-ts-row-dirty").forEach((d) => {
          d.style.display = "none";
        });
      })
      // On failure, deliberately do NOT touch _veloBundles or re-render anything — the analyst needs
      // to see the error message in place, and must not be left believing a correction is in force
      // when the save didn't happen.
      .catch((e) => {
        msg.textContent = "error: " + e.message;
      })
      .finally(() => {
        if (saveBtn) saveBtn.disabled = false;
      });
  }

  function veloRunBundle(bundleId, form) {
    const caseId = veloCaseId();
    const msg = form.querySelector(".velo-run-msg");
    if (!caseId) {
      msg.textContent = "connect to a case first";
      return;
    }
    // Never let a half-finished custom time scope silently launch unscoped — see veloTimeScopeIncomplete.
    if (veloTimeScopeIncomplete(form)) {
      msg.textContent = "⚠ enter a start date to apply a custom time scope";
      return;
    }
    const waitMinutes = Number(form.querySelector(".velo-wait").value) || 10;
    const expirySeconds =
      Number(form.querySelector(".velo-expiry").value) || undefined;
    const os = form.querySelector(".velo-os").value;
    const minSeverity = form.querySelector(".velo-minsev").value;
    const includeLabels = form.querySelector(".velo-inc").value;
    const excludeLabels = form.querySelector(".velo-exc").value;
    const go = form.querySelector(".velo-run-go");
    go.disabled = true;
    msg.textContent = "launching hunt…";
    // No timeoutSeconds here on purpose — the server uses the bundle's saved timeout (read fresh from disk).
    const body = {
      bundleId,
      waitMinutes,
      expirySeconds,
      os,
      minSeverity,
      includeLabels,
      excludeLabels,
      timeScope: veloTimeScopeBody(form),
    };
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/run-bundle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        // The server drops artifacts THIS Velociraptor doesn't have, and artifacts whose third-party
        // tool it cannot download — either one would have failed the whole hunt. Say what was dropped.
        const list = (v) => (Array.isArray(v) ? v : []);
        const skipped = list(j.unknownArtifacts).concat(
          list(j.unavailableArtifacts).map((u) => `${u.artifact}: ${u.reason}`),
        );
        if (skipped.length) {
          msg.innerHTML = `launched ✓ — skipped ${skipped.length} artifact(s), not on this server or missing their tool: <span data-safe-style="color:var(--sev-high)">${esc(skipped.join(", "))}</span>`;
        } else {
          msg.textContent = "";
          form.style.display = "none";
        }
        loadVeloHuntJobs(caseId);
      })
      .catch(
        (e) =>
          (msg.textContent =
            "error: " +
            e.message +
            " — restart the companion server if this 404s"),
      )
      .finally(() => {
        go.disabled = false;
      });
  }

  // Import the results of a hunt/flow launched directly in the Velociraptor GUI (paste id or URL).
  function veloImportExternal() {
    const caseId = veloCaseId();
    const msg = document.getElementById("veloExtMsg");
    if (!caseId) {
      msg.textContent = "connect to a case first";
      return;
    }
    const ref = document.getElementById("veloExtRef").value.trim();
    if (!ref) {
      msg.textContent = "paste a hunt id, flow, or Velociraptor URL";
      return;
    }
    const minSeverity = document.getElementById("veloExtMinsev").value;
    const superTimelineOnly = document.getElementById("veloExtSuper").checked;
    const go = document.getElementById("veloExtGo");
    go.disabled = true;
    msg.textContent = "importing…";
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/import-external`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ref, minSeverity, superTimelineOnly }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (!ok || j.error) {
          msg.textContent = "error: " + (j.error || "failed");
          return;
        }
        const where =
          j.kind === "flow"
            ? `Flow ${esc(j.flowId)} on host ${esc(j.hostname || j.clientId)}`
            : `Hunt ${esc(j.huntId)}`;
        if (j.uploadsOnly) {
          // Uploads-only path (analyst pasted the GUI's Uploaded Files tab URL) — reports imported/
          // skipped FILE counts, not artifact counts, since rows were never fetched on this path.
          const counts = `+${j.addedEvents || 0} events, +${j.addedIocs || 0} IOCs`;
          const files =
            `imported ${(j.imported || []).length} file(s)` +
            ((j.skipped || []).length ? `, skipped ${j.skipped.length}` : "");
          msg.innerHTML =
            `${where} (uploaded files) — ${files}, ${counts}` +
            (j.note ? ` (${esc(j.note)})` : "");
          loadVeloHuntJobs(caseId);
          return;
        }
        const dest = j.superTimelineOnly ? " → super-timeline" : "";
        // Super-only imports report their super-timeline event count and never add main-list IOCs, so
        // the "+IOCs" suffix (always 0 there) is dropped to avoid the misleading "+0 IOCs".
        const counts = j.superTimelineOnly
          ? `+${j.addedEvents || 0} events`
          : `+${j.addedEvents || 0} events, +${j.addedIocs || 0} IOCs`;
        msg.innerHTML =
          `${where}${dest} — imported ${(j.artifacts || []).length} artifact(s), ${counts}` +
          (j.note ? ` (${esc(j.note)})` : "");
        loadVeloHuntJobs(caseId);
      })
      .catch(
        (e) =>
          (msg.textContent =
            "error: " +
            e.message +
            " — restart the companion server if this 404s"),
      )
      .finally(() => {
        go.disabled = false;
      });
  }

  function loadVeloHuntJobs(caseId) {
    if (!caseId) {
      renderVeloJobs([]);
      return;
    }
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/hunt-jobs`)
      .then((r) => (r.ok ? r.json() : []))
      .then((j) => renderVeloJobs(Array.isArray(j) ? j : []))
      .catch(() => {});
  }
  // Render every tracked hunt (newest first) as its own card — concurrent hunts each show their
  // status, countdown, and a Collect-now button. One shared ticker updates all running countdowns.
  function renderVeloJobs(jobs) {
    const el = document.getElementById("veloJobCard");
    if (!el) return;
    if (veloCountdownTimer) {
      clearInterval(veloCountdownTimer);
      veloCountdownTimer = null;
    }
    if (!jobs.length) {
      el.style.display = "none";
      el.innerHTML = "";
      return;
    }
    el.style.display = "block";
    const statusColors = {
      running: "#6aa9ff",
      collecting: "#ffd93b",
      imported: "#4cd964",
      error: "#ff9f43",
      deleted: "#ff6b6b",
      unreachable: "#9aa4b2",
    };
    el.innerHTML = jobs
      .map((job) => {
        const link = job.guiUrl
          ? ` · <a href="${escAttr(job.guiUrl)}" target="_blank" rel="noopener" data-safe-style="color:var(--accent)">open in Velociraptor ↗</a>`
          : "";
        const badge = `<span data-safe-style="color:${statusColors[job.status] || "#9aa4b2"};font-weight:600">${esc(job.status)}</span>`;
        let detail = "";
        if (job.status === "imported") {
          const ev = job.addedEvents || 0,
            io = job.addedIocs || 0;
          detail =
            ev || io
              ? `+${ev} event(s), +${io} IOC(s) imported`
              : job.stoppedEarly
                ? "this hunt was stopped before its scheduled expiry in Velociraptor — likely stopped or deleted; no results were collected"
                : "no new results collected yet — clients may not have checked in; collect again later";
        } else if (job.status === "error") {
          detail = "error: " + (job.error || "");
        } else if (job.status === "deleted") {
          detail =
            "this hunt was removed from Velociraptor — no results will be collected";
        } else if (job.status === "unreachable") {
          detail = "couldn't reach Velociraptor to check status — will retry";
        }
        const canCollect =
          job.status === "running" ||
          job.status === "imported" ||
          job.status === "error";
        const collectBtn = canCollect
          ? `<button class="velo-collect-btn" data-hid="${escAttr(job.huntId)}">Collect now</button>`
          : "";
        const cd =
          job.status === "running" && job.collectAt
            ? `<span class="velo-countdown" data-collect-at="${escAttr(job.collectAt)}"></span> `
            : "";
        // Per-artifact accounting (failed / nothing-found / cut short at the row cap) —
        // public/js/dashboard-velo-coverage.js.
        const coverage = veloCoverageHtml(job);
        // The COLLECTION window this hunt ran with, when it was scoped. Part of the evidence record:
        // it tells a later reader that silence outside these bounds is a collection boundary, not a
        // quiet endpoint. `degraded` means we could not verify the split — don't let it read as "0".
        // Deliberately rendered as raw ISO (with trailing Z), NOT run through .toLocaleString() like most
        // other timestamps in this file: this is evidence metadata read by someone who may be in a
        // different timezone, possibly months later — an unambiguous UTC marker matters more here than
        // local-time familiarity. Do not "fix" this to local time.
        const tsLine = job.timeScope
          ? `<div data-safe-style="font-size:12px;color:var(--text-muted);margin-top:4px" title="Collection was bounded — absence of results outside this window is a collection boundary, not an absence of activity">⏱ scoped ${esc(job.timeScope.start)}${job.timeScope.end ? " → " + esc(job.timeScope.end) : " → (open)"} · ${esc(job.timeScope.scopedArtifacts)}/${esc(job.timeScope.totalArtifacts)} artifact(s) bounded${job.timeScope.degraded ? ` · <span data-safe-style="color:var(--sev-high)">coverage unverified (server reported no parameter metadata)</span>` : ""}</div>`
          : "";
        return `<div class="synth-meta" data-safe-style="margin:0 0 8px;padding:8px 10px;border:1px solid var(--border-color);border-radius:6px">
        <div data-safe-style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <div>🎯 <strong>${esc(job.bundleName)}</strong> · ${badge} · <code>${esc(job.huntId)}</code>${link}</div>
          <div>${collectBtn}</div>
        </div>
        <div data-safe-style="font-size:12px;color:var(--text-muted);margin-top:4px">${cd}${esc(detail)}</div>
        ${coverage}
        ${tsLine}
      </div>`;
      })
      .join("");
    el.querySelectorAll(".velo-collect-btn").forEach(
      (btn) => (btn.onclick = () => veloCollectNow(btn.dataset.hid, btn)),
    );
    const tick = () => {
      const spans = el.querySelectorAll(".velo-countdown[data-collect-at]");
      if (!spans.length) {
        if (veloCountdownTimer) {
          clearInterval(veloCountdownTimer);
          veloCountdownTimer = null;
        }
        return;
      }
      spans.forEach((cd) => {
        const ms = new Date(cd.dataset.collectAt).getTime() - Date.now();
        if (ms <= 0) {
          cd.textContent = "collecting results… ·";
        } else {
          const m = Math.floor(ms / 60000),
            s = Math.floor((ms % 60000) / 1000);
          cd.textContent = `auto-collect in ${m}m ${String(s).padStart(2, "0")}s ·`;
        }
      });
    };
    if (el.querySelector(".velo-countdown[data-collect-at]")) {
      tick();
      veloCountdownTimer = setInterval(tick, 1000);
    }
  }
  function veloCollectNow(huntId, btn) {
    const caseId = veloCaseId();
    if (!caseId) return;
    if (btn) {
      btn.disabled = true;
      btn.textContent = "collecting…";
    }
    fetch(`/cases/${encodeURIComponent(caseId)}/velociraptor/collect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ huntId }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      // `queued` = a collect was already running for this hunt, so this click was folded into a
      // follow-up pass that starts when it finishes (#195). It WILL run — just not this instant.
      .then(({ ok, j }) => {
        if (!ok) console.warn("collect failed", j);
        else if (j && j.queued && btn) {
          btn.textContent = "queued…";
          btn.title =
            "a collect is already running for this hunt — this one runs right after it";
        }
        loadVeloHuntJobs(caseId);
      })
      .catch((e) => console.warn("collect error", e));
  }

  // Accessors over the four shared bindings. The writes stay here, where the loads that refresh
  // them are.
  function veloBundlesList() {
    return _veloBundles || [];
  }
  function veloClientsList() {
    return _veloClients;
  }
  function veloMonAutoBrowsed() {
    return _veloMonAutoBrowsed;
  }
  function setVeloMonAutoBrowsed(v) {
    _veloMonAutoBrowsed = v;
  }

  window.loadVeloTriage = loadVeloTriage;
  window.loadVeloBundles = loadVeloBundles;
  window.loadVeloClients = loadVeloClients;
  window.loadVeloHuntJobs = loadVeloHuntJobs;
  window.veloCaseId = veloCaseId;
  window.applyVeloEnabled = applyVeloEnabled;
  window.doRefreshVeloClients = doRefreshVeloClients;
  window.doVeloReconnect = doVeloReconnect;
  window.veloImportExternal = veloImportExternal;
  window.veloBundlesList = veloBundlesList;
  window.veloClientsList = veloClientsList;
  window.veloMonAutoBrowsed = veloMonAutoBrowsed;
  window.setVeloMonAutoBrowsed = setVeloMonAutoBrowsed;
})();
