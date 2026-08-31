// Health / Diagnostics (#118) — operator system state, Settings → Diagnostics (#415 tier 3).
//
// Disk and memory, the AI provider round-trip, clock skew against the browser, per-case sizes, and
// the support bundle the operator pastes into a bug report.
//
// IIFE-WRAPPED BECAUSE IT OWNS STATE: the copied diagnostics text and the support bundle's body and
// filename. In a CLASSIC script — which this is, so a missing sibling cannot take the page down — a
// top-level `let` joins the shared global lexical environment, so unwrapped these three would be
// reachable by name from every other script on the page.
//
// IT HAS AN INITIALIZER, and it did not start with one. Its five controls were bound in the page's
// Settings block, which meant the page held five bare references to this file's functions and
// evaluated them at load. A 404 there is a ReferenceError before the WebSocket connects — the whole
// page, not one tab. initDiagnostics() moves that binding here so the page guards one name.
//
// Reads its row/card/format helpers off window.DfirDiagnostics at CALL time, not parse time: that
// module is deferred, and every caller here runs on a data load, by which point it is populated.
(function () {
  // --- Health / Diagnostics (#118) — operator system state, Settings → Diagnostics --------------
  let diagCopyText = "";
  let diagSupportText = "";
  let diagSupportFilename = "dfir-companion-support.json";
  function renderDiagnostics(report, cost) {
    // Bound from the module namespace at CALL time, not parse time: this file is plain inline
    // script and cannot import, and the module that defines these is deferred. Every caller
    // below runs on a data load, so the namespace is always populated by then.
    const { diagRow, diagCard, diagFmtBytes, diagFmtAge } =
      window.DfirDiagnostics;
    const d = report.disk;
    const lvlColor =
      window.DfirDiagnostics.DIAG_LEVEL_COLOR[d.level] || "#cbd3df";
    const disk = diagCard(
      "Disk",
      [
        diagRow(
          "Free",
          `${diagFmtBytes(d.freeBytes)} of ${diagFmtBytes(d.totalBytes)}`,
        ),
        diagRow("Used", `${(d.usedPct || 0).toFixed(1)}%`, lvlColor),
        diagRow("Status", esc(d.level), lvlColor),
      ].join(""),
    );
    const cs = report.cases;
    const cases = diagCard(
      "Cases",
      diagRow("Total", `${cs.count} (${cs.open} open, ${cs.closed} closed)`),
    );
    const q = report.queue;
    const queue = diagCard(
      "Queue / processing",
      [
        diagRow(
          "Buffered screenshots",
          `${q.bufferedCaptures} across ${q.casesBuffering} case(s)`,
        ),
        q.oldestBufferedAgeMs != null
          ? diagRow("Oldest buffered", diagFmtAge(q.oldestBufferedAgeMs))
          : "",
        diagRow("Synthesis in flight", String(q.synthInFlight)),
        diagRow(
          "Failed-analysis cases",
          String(q.pendingAnalysisCases),
          q.pendingAnalysisCases > 0 ? "#ffb05a" : "",
        ),
      ].join(""),
    );
    const ai = report.ai;
    let aiRows;
    if (!ai.configured) {
      aiRows = diagRow("Status", "not configured", "#ffb05a");
    } else {
      const errEntries = Object.entries(ai.errorCounts || {});
      aiRows = [
        diagRow(
          "Provider",
          `${esc(ai.provider)} <span data-safe-style="color:${ai.local ? "#5ad17a" : "#ffb05a"}">(${ai.local ? "local" : "external"})</span>`,
        ),
        diagRow("Model", esc(ai.model)),
        ai.synthModel && ai.synthModel !== ai.model
          ? diagRow("Synthesis model", esc(ai.synthModel))
          : "",
        ai.secondOpinionModel
          ? diagRow("2nd-opinion model", esc(ai.secondOpinionModel))
          : "",
        ai.baseUrl
          ? diagRow("Base URL", `<code>${esc(ai.baseUrl)}</code>`)
          : "",
        diagRow("Timeout", `${ai.timeoutMs} ms`),
        diagRow("Max tokens", String(ai.maxTokens)),
        diagRow("Context window", String(ai.contextTokens)),
        diagRow("Anonymize default", ai.anonymizeDefault ? "on" : "off"),
        errEntries.length
          ? diagRow(
              "Recent AI errors",
              errEntries.map(([k, n]) => `${esc(k)}=${n}`).join(", "),
              "#ff9f9f",
            )
          : "",
      ].join("");
    }
    aiRows += `<div data-safe-style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
      <button id="diagAiTestBtn" type="button">⚡ Test AI connectivity</button>
      <span id="diagAiTestMsg" class="manual-msg"></span></div>`;
    const aiCard = diagCard("AI connectivity & config", aiRows);
    const im = report.importers;
    let impRows = [
      diagRow(
        "Evidence files imported",
        `${im.attempts.last24h} (24h) · ${im.attempts.last7d} (7d) · ${im.attempts.total} total`,
      ),
      `<div data-safe-style="font-size:11px;color:#7e8aa0;margin:1px 0 5px">files imported across all cases (from each case's imports.jsonl audit log) in the last 24h / 7d / all-time</div>`,
      diagRow("Custom importers loaded", String(im.customImporters)),
    ].join("");
    if (im.recentFailures && im.recentFailures.length) {
      impRows += `<div data-safe-style="margin-top:6px;color:#9aa4b2">Recent failures (${im.recentFailures.length}):</div>`;
      impRows +=
        `<div data-safe-style="max-height:160px;overflow:auto;margin-top:3px">` +
        im.recentFailures
          .map(
            (f) =>
              `<div data-safe-style="border-left:2px solid #5a2a2a;padding:2px 0 2px 8px;margin:3px 0;font-family:monospace;font-size:11.5px">
          <span data-safe-style="color:#7e8aa0">${esc((f.at || "").replace("T", " ").slice(0, 19))}</span>
          <span data-safe-style="color:#ff9f9f">${esc(f.kind)}</span> ${esc(f.caseId)}/${esc(f.filename)}<br>
          <span data-safe-style="color:#ffb0b0">${esc(f.error)}</span></div>`,
          )
          .join("") +
        `</div>`;
    } else {
      impRows += diagRow("Recent failures", "none", "#5ad17a");
    }
    impRows += window.DfirDiagnostics.renderPerImporterHealth(im);
    const importers = diagCard("Importer health", impRows);
    const bk = report.backups || {};
    let backupsCard = "";
    if (bk.enabled) {
      backupsCard = diagCard(
        "State backups",
        [
          diagRow("Total backups", `${bk.totalCount} across all cases`),
          diagRow("Disk usage", diagFmtBytes(bk.totalBytes)),
          diagRow("Retain per case", String(bk.retain)),
          diagRow(
            "Byte budget per case",
            bk.maxBytes > 0 ? diagFmtBytes(bk.maxBytes) : "no byte cap",
          ),
          // Only non-zero when pruning has already deleted everything it may: what is left is the
          // newest backup and the newest pre-synthesis one, and those are never evicted (#295).
          bk.overBudgetCases > 0
            ? diagRow(
                "Over budget",
                `⚠ ${bk.overBudgetCases} case(s) — nothing left to prune`,
              )
            : "",
          `<div data-safe-style="font-size:11px;color:#7e8aa0;margin-top:4px">Created automatically before each synthesis. Use "Load case backups" below to browse and restore per-case snapshots.</div>`,
        ].join(""),
      );
    }
    const footer = `<div data-safe-style="font-size:11px;color:#7e8aa0;margin-top:4px">generated ${esc((report.generatedAt || "").replace("T", " ").slice(0, 19))} · uptime ${diagFmtAge(report.uptimeMs)}</div>`;
    return (
      disk +
      cases +
      queue +
      window.DfirDiagnostics.renderOperationalDiagnostics(report.operational) +
      aiCard +
      window.DfirDiagnostics.renderAiCostCard(cost) +
      importers +
      backupsCard +
      `<div id="diagSizes"></div>` +
      footer
    );
  }
  // Pre-flight status panel inside Settings → Diagnostics (#179).
  function renderPreflightStatus(report) {
    const el = document.getElementById("preflightStatus");
    const btn = document.getElementById("preflightToggleBtn");
    if (!el || !report) return;
    if (report.disabled) {
      el.innerHTML =
        '<span data-safe-style="color:#7e8aa0">⊘ Checks disabled — no probes run on startup.</span>';
      if (btn) btn.textContent = "Enable checks";
      return;
    }
    if (btn) btn.textContent = "Disable checks";
    const status = report.anyCriticalFailed
      ? '<span data-safe-style="color:#ff5c5c">✗ CRITICAL</span>'
      : report.anyFailed
        ? '<span data-safe-style="color:#ffb05a">⚠ WARN</span>'
        : '<span data-safe-style="color:#5ad17a">✓ OK</span>';
    const rows = (report.items || [])
      .map((i) => {
        const icon = i.ok
          ? '<span data-safe-style="color:#5ad17a">✓</span>'
          : i.critical
            ? '<span data-safe-style="color:#ff5c5c">✗</span>'
            : '<span data-safe-style="color:#ffb05a">⚠</span>';
        return `<div data-safe-style="margin:2px 0">${icon} <strong>${esc(i.name)}</strong>: ${esc(i.detail)}</div>`;
      })
      .join("");
    el.innerHTML = `<div data-safe-style="margin-bottom:4px">Status: ${status} &nbsp;<span data-safe-style="color:#7e8aa0;font-size:11px">${esc(report.ranAt || "")} (${report.durationMs || 0}ms)</span></div>${rows}`;
  }
  function loadPreflightStatus() {
    const el = document.getElementById("preflightStatus");
    if (el) el.textContent = "Loading…";
    fetch("/diagnostics/preflight")
      .then((r) =>
        r.ok ? r.json() : Promise.reject(new Error(String(r.status))),
      )
      .then((d) => renderPreflightStatus(d.report))
      .catch((e) => {
        if (el) el.textContent = "Could not load pre-flight: " + e.message;
      });
  }
  function loadDiagnostics() {
    const body = document.getElementById("diagBody");
    const msg = document.getElementById("diagMsg");
    if (msg) msg.textContent = "";
    body.textContent = "Loading…";
    const caseIdEl = document.getElementById("caseId");
    const caseId = caseIdEl ? caseIdEl.value.trim() : "";
    const diagFetch = fetch("/diagnostics").then((r) => r.json());
    const costFetch = caseId
      ? fetch(`/cases/${encodeURIComponent(caseId)}/ai-cost`)
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null)
      : Promise.resolve(null);
    Promise.all([diagFetch, costFetch])
      .then(([j, cost]) => {
        if (!j.report) throw new Error(j.error || "no report");
        diagSupportText = j.supportPreview || "";
        diagSupportFilename =
          j.supportFilename || "dfir-companion-support.json";
        diagCopyText = diagSupportText || j.text || "";
        const preview = document.getElementById("diagSupportPreview");
        const download = document.getElementById("diagSupportDownloadBtn");
        if (preview) {
          preview.hidden = true;
          preview.textContent = "";
        }
        if (download) download.disabled = true;
        body.innerHTML = renderDiagnostics(j.report, cost);
      })
      .catch((e) => {
        body.textContent =
          "Could not load diagnostics: " +
          e.message +
          " — restart the companion server if this 404s.";
      });
  }
  function loadCaseStats() {
    const { diagRow, diagCard, diagFmtBytes, diagFmtAge } =
      window.DfirDiagnostics; // see renderDiagnostics
    const el = document.getElementById("caseStatsPanel");
    if (!el) return;
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) {
      el.innerHTML =
        '<span data-safe-style="color:#7e8aa0">Select a case first.</span>';
      return;
    }
    el.textContent = "Loading…";
    fetch(`/cases/${encodeURIComponent(caseId)}/stats`)
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        const t = j.totals || {};
        const tiles = ["events", "findings", "iocs", "assets"]
          .map(
            (k) =>
              `<div data-safe-style="text-align:center;padding:4px 8px"><div data-safe-style="font-size:18px;font-weight:600;color:#cbd3df">${(t[k] || 0).toLocaleString()}</div>
            <div data-safe-style="font-size:10.5px;color:#7e8aa0;text-transform:uppercase">${k}</div></div>`,
          )
          .join("");
        const bySource =
          (j.bySource || [])
            .map((s) => diagRow(esc(s.source), s.count.toLocaleString()))
            .join("") ||
          `<div data-safe-style="color:#7e8aa0">no events yet</div>`;
        el.innerHTML = `
          <div data-safe-style="display:flex;justify-content:space-around;flex-wrap:wrap;border-bottom:1px solid var(--border-color);padding-bottom:8px;margin-bottom:8px">${tiles}</div>
          <div data-safe-style="font-weight:600;color:#9aa4b2;margin-bottom:3px">Events by source</div>
          ${bySource}
          <div data-safe-style="font-weight:600;color:#9aa4b2;margin:8px 0 3px">Import velocity (daily)</div>
          ${caseStatsBarChart(j.importVelocity || [])}`;
      })
      .catch((e) => {
        el.innerHTML = `<span data-safe-style="color:#ff9f9f">Could not load case stats: ${esc(e.message)}</span>`;
      });
  }
  // Round a millisecond span to the coarsest unit that still reads honestly. A ~9-month clock error
  // is "268 days", not "23155200 seconds" — the analyst has to recognise the size at a glance.
  function skewSpanLabel(ms) {
    const days = Math.round(Math.abs(ms) / 86400000);
    if (days >= 2) return `${days} days`;
    const hours = Math.round(Math.abs(ms) / 3600000);
    return hours >= 2 ? `${hours} hours` : `${Math.round(Math.abs(ms) / 60000)} minutes`;
  }

  // Timeline-integrity warnings (#739, #740). Neither of these is a correction — they exist so a
  // wrong clock or a machine-adjusted year can never pass through the case in silence, which is
  // precisely how a ~9-month VM skew reached synthesis unremarked on INC-2026-020.
  function timelineIntegrityWarnings(j) {
    const out = [];
    // A host whose own events split across a huge gap. Needs no second clock, so it fires on the
    // single-source case where no offset can be measured at all.
    for (const g of j.timeGaps || []) {
      const src = (g.sources || []).length
        ? ` Reported by ${esc((g.sources || []).join(", "))}.`
        : "";
      out.push(`<div data-safe-style="color:#ffcf8f;padding:5px 0;border-bottom:1px solid var(--border-color)">
        &#9888; <strong>${esc(g.host)}</strong> — ${esc(g.minorityCount)} of ${esc(g.totalCount)} events are dated
        ${esc(skewSpanLabel(g.gapMs))} ${g.minoritySide === "before" ? "before" : "after"} the rest
        (${esc(String(g.minorityStart).slice(0, 10))} &rarr; ${esc(String(g.minorityEnd).slice(0, 10))} vs
        ${esc(String(g.majorityStart).slice(0, 10))} &rarr; ${esc(String(g.majorityEnd).slice(0, 10))}).
        Check this host for clock skew before trusting its ordering or the case's scope window.${src}</div>`);
    }
    // Years the merge re-anchored. Read off the events themselves — a clamped event keeps what it
    // was imported as, so the count needs no extra endpoint.
    const events =
      (window.DfirState && window.DfirState.lastState() && window.DfirState.lastState().forensicTimeline) || [];
    const byPair = new Map();
    for (const e of events) {
      const from = e.yearClampedFrom ? new Date(e.yearClampedFrom).getUTCFullYear() : NaN;
      const to = e.timestamp ? new Date(e.timestamp).getUTCFullYear() : NaN;
      if (isNaN(from) || isNaN(to) || from === to) continue;
      const key = `${from}>${to}`;
      byPair.set(key, (byPair.get(key) || 0) + 1);
    }
    for (const [key, count] of [...byPair.entries()].sort((a, b) => b[1] - a[1])) {
      const [from, to] = key.split(">");
      out.push(`<div data-safe-style="color:#ffcf8f;padding:5px 0;border-bottom:1px solid var(--border-color)">
        &#9888; ${esc(count)} event${count === 1 ? "" : "s"} had the year adjusted from ${esc(from)} to ${esc(to)}.
        Those sources carry no year of their own, so the import guessed one and the merge re-anchored it onto the
        case's dominant year. Each row shows the time it was imported as.</div>`);
    }
    return out.join("");
  }

  function renderClockSkew(j) {
    const el = document.getElementById("clockSkewPanel");
    if (!el) return;
    const results = j.results || [];
    const overrides = j.overrides || {};
    const alertMs = (j.thresholds && j.thresholds.alertThresholdMs) || 60000;
    const align = document.getElementById("clockSkewAlign");
    if (align) align.checked = j.alignEnabled === true;
    const warnings = timelineIntegrityWarnings(j);
    // A host can carry an override with no detection behind it, so union the two key sets.
    const keys = [
      ...new Set([...results.map((r) => r.hostKey), ...Object.keys(overrides)]),
    ].sort();
    if (!keys.length) {
      el.innerHTML =
        warnings +
        `<div data-safe-style="color:#7e8aa0">No clock-skew anchors yet. Offsets are measured during
        synthesis, from events that two different tools recorded for the same artifact — a case with a
        single evidence source, or one not yet synthesized, has nothing to compare.</div>`;
      return;
    }
    const byKey = new Map(results.map((r) => [r.hostKey, r]));
    const rows = keys
      .map((key) => {
        const r = byKey.get(key);
        const ov = Object.prototype.hasOwnProperty.call(overrides, key)
          ? overrides[key]
          : null;
        const effective = ov !== null ? ov : r && r.alignable ? r.offsetMs : 0;
        const flagged = Math.abs(effective) > alertMs;
        const name = esc(r ? r.host : key);
        const measured = r
          ? `${skewOffsetLabel(r.offsetMs)} · ${r.anchorCount} anchor${r.anchorCount === 1 ? "" : "s"} · ±${skewOffsetLabel(r.dispersionMs)} · ${esc(r.confidence)}`
          : "not measured";
        // Three distinct reasons a host is not aligned, and they are not interchangeable: too little
        // evidence, evidence that disagrees, or a sound measurement too large to apply unattended
        // (#740). The last one is the only one the analyst can act on, so it says how.
        const why =
          r && !r.qualified
            ? `<div data-safe-style="color:#7e8aa0;font-size:11px">not aligned — ${r.anchorCount < 3 ? "too few anchors" : "offsets disagree across anchors (looks like propagation delay, not a clock)"}</div>`
            : r && !r.alignable
              ? `<div data-safe-style="color:#ffcf8f;font-size:11px">measured but NOT applied — an offset this large is never aligned automatically. Confirm the host's clock, then type the offset in seconds to apply it.</div>`
              : "";
        const src =
          r && r.sources.length
            ? `<div data-safe-style="color:#7e8aa0;font-size:11px">from ${esc(r.sources.join(", "))}</div>`
            : "";
        return `<div data-safe-style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid var(--border-color)">
        <div data-safe-style="min-width:0">
          <div data-safe-style="font-weight:600;color:${flagged ? "#ffcf8f" : "#cbd3df"}">${flagged ? "⚠ " : ""}${name}
            <span data-safe-style="font-weight:400;color:#7e8aa0">${esc(measured)}</span></div>
          ${why}${src}
        </div>
        <div data-safe-style="display:flex;gap:5px;align-items:center;white-space:nowrap">
          <input type="number" step="1" class="clock-skew-override" data-host="${esc(r ? r.host : key)}"
            value="${ov === null ? "" : ov / 1000}" placeholder="${r ? (r.offsetMs / 1000).toFixed(0) : "0"}"
            title="Manual offset in seconds. Overrides the measurement; 0 pins this clock as correct; empty clears it."
            data-safe-style="width:74px;text-align:right" />
          <span data-safe-style="color:#7e8aa0;font-size:11px">s</span>
        </div>
      </div>`;
      })
      .join("");
    const shifted = keys.filter((k) => {
      const ov = Object.prototype.hasOwnProperty.call(overrides, k)
        ? overrides[k]
        : null;
      const r = byKey.get(k);
      return ov !== null ? ov !== 0 : !!(r && r.alignable && r.offsetMs !== 0);
    }).length;
    el.innerHTML =
      warnings +
      rows +
      `<div data-safe-style="color:#7e8aa0;margin-top:6px">
      ${shifted} host${shifted === 1 ? "" : "s"} would shift when alignment is on${j.detectedAt ? " · measured " + esc(j.detectedAt.slice(0, 19).replace("T", " ")) + "Z" : ""}</div>`;
  }
  function loadClockSkew(caseId) {
    const el = document.getElementById("clockSkewPanel");
    if (!el) return;
    const id = (caseId || document.getElementById("caseId").value).trim();
    if (!id) {
      el.innerHTML =
        '<span data-safe-style="color:#7e8aa0">Select a case first.</span>';
      return;
    }
    fetch(`/cases/${encodeURIComponent(id)}/clock-skew`)
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then(renderClockSkew)
      .catch((e) => {
        el.innerHTML = `<span data-safe-style="color:#ff9f9f">Could not load clock skew: ${esc(e.message)}</span>`;
      });
  }
  // Every mutation re-renders the panel AND re-fetches the case state: alignment changes the
  // timestamp on every row the analyst is looking at, so the timeline must be redrawn with it.
  function clockSkewMutate(path, body, note) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    const msg = document.getElementById("clockSkewMsg");
    if (msg) msg.textContent = note || "Saving…";
    fetch(`/cases/${encodeURIComponent(caseId)}/clock-skew/${path}`, {
      method: path === "override" ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            (await r.json().catch(() => ({}))).error || "HTTP " + r.status,
          );
        return r.json();
      })
      .then((j) => {
        renderClockSkew(j);
        if (msg) msg.textContent = "";
        fetch(`/cases/${caseId}/state`)
          .then((r) => r.json())
          .then(render)
          .catch(() => {});
      })
      .catch((e) => {
        if (msg) msg.textContent = "Failed: " + e.message;
      });
  }
  function diagAiTest() {
    const btn = document.getElementById("diagAiTestBtn");
    const msg = document.getElementById("diagAiTestMsg");
    if (!msg) return;
    if (btn) btn.disabled = true;
    msg.style.color = "#9aa4b2";
    msg.textContent = "testing…";
    fetch("/diagnostics/ai-test", { method: "POST" })
      .then(async (r) => ({
        status: r.status,
        body: await r.json().catch(() => ({})),
      }))
      .then(({ status, body }) => {
        if (status === 501) {
          msg.style.color = "#ffb05a";
          msg.textContent = body.error || "AI not configured";
          return;
        }
        if (body.ok) {
          msg.style.color = "#5ad17a";
          msg.textContent = `✓ ${esc(body.provider)} responded in ${body.latencyMs} ms`;
        } else {
          msg.style.color = "#ff9f9f";
          msg.textContent = `✗ ${esc(body.kind || "error")}: ${esc(body.error || "failed")}`;
        }
      })
      .catch((e) => {
        msg.style.color = "#ff9f9f";
        msg.textContent = "request failed: " + e.message;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function diagComputeSizes() {
    const { diagRow, diagCard, diagFmtBytes, diagFmtAge } =
      window.DfirDiagnostics; // see renderDiagnostics
    const btn = document.getElementById("diagSizesBtn");
    const target = document.getElementById("diagSizes");
    if (!target) {
      loadDiagnostics();
      return;
    }
    if (btn) btn.disabled = true;
    target.innerHTML = `<div data-safe-style="color:#9aa4b2;padding:6px 0">Scanning case files…</div>`;
    fetch("/diagnostics/sizes?top=10")
      .then((r) => r.json())
      .then((j) => {
        if (j.error) throw new Error(j.error);
        const cases =
          (j.cases || [])
            .map((c) => diagRow(esc(c.caseId), diagFmtBytes(c.bytes)))
            .join("") || `<div data-safe-style="color:#9aa4b2">no cases</div>`;
        const files =
          (j.largestFiles || [])
            .map(
              (f) =>
                `<div data-safe-style="display:flex;justify-content:space-between;gap:12px;font-family:monospace;font-size:11.5px;padding:1px 0">
          <span data-safe-style="color:#9aa4b2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.caseId)}/${esc(f.path)}</span>
          <span>${diagFmtBytes(f.bytes)}</span></div>`,
            )
            .join("") || `<div data-safe-style="color:#9aa4b2">none</div>`;
        const trunc = j.truncated
          ? ` <span data-safe-style="color:#ffb05a">(scan truncated at ${j.scannedFiles} files)</span>`
          : "";
        // Locked cases still count toward the byte totals but withhold their filenames, so say so —
        // otherwise a short "Largest files" list on a passworded install just looks broken.
        const locked = j.lockedCases
          ? ` <span data-safe-style="font-weight:400">— hidden for ${j.lockedCases} locked case(s)</span>`
          : "";
        target.innerHTML = diagCard(
          "Case sizes — total " + diagFmtBytes(j.totalBytes) + trunc,
          `<div data-safe-style="font-weight:600;color:#9aa4b2;margin:2px 0">By case</div>${cases}
         <div data-safe-style="font-weight:600;color:#9aa4b2;margin:8px 0 2px">Largest files${locked}</div>${files}`,
        );
      })
      .catch((e) => {
        target.innerHTML = `<div data-safe-style="color:#ff9f9f">Size scan failed: ${esc(e.message)}</div>`;
      })
      .finally(() => {
        if (btn) btn.disabled = false;
      });
  }
  function diagCopy() {
    const msg = document.getElementById("diagMsg");
    const preview = document.getElementById("diagSupportPreview");
    if (diagSupportText && (!preview || preview.hidden)) {
      diagPreviewSupport();
      if (msg)
        msg.textContent =
          "review the support preview, then click Copy diagnostics again";
      return;
    }
    const text = diagCopyText || "(load diagnostics first)";
    const done = () => {
      if (msg) {
        msg.style.color = "#5ad17a";
        msg.textContent = "copied to clipboard";
      }
    };
    const fail = () => {
      if (msg) {
        msg.style.color = "#ff9f9f";
        msg.textContent = "copy failed — select & copy manually";
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(fail);
    } else {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        done();
      } catch {
        fail();
      }
    }
  }
  function diagPreviewSupport() {
    const preview = document.getElementById("diagSupportPreview");
    const download = document.getElementById("diagSupportDownloadBtn");
    const msg = document.getElementById("diagMsg");
    if (!preview || !diagSupportText) {
      if (msg) msg.textContent = "load diagnostics first";
      return;
    }
    preview.textContent = diagSupportText;
    preview.hidden = false;
    if (download) download.disabled = false;
    if (msg)
      msg.textContent =
        "preview contains aggregate metrics only; evidence and identifiers are excluded";
  }
  function diagDownloadSupport() {
    const preview = document.getElementById("diagSupportPreview");
    if (!diagSupportText || !preview || preview.hidden) return;
    const blob = new Blob([diagSupportText], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = diagSupportFilename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // The five Settings → Diagnostics controls. These were bound in the page's Settings block; they
  // move here because the handlers are this module's own functions, and binding them from the page
  // meant five bare names evaluated at load time — a 404 here would have taken the page down before
  // the WebSocket connected, rather than just greying out one tab.
  function initDiagnostics() {
    document
      .getElementById("diagRefreshBtn")
      .addEventListener("click", loadDiagnostics);
    document.getElementById("diagCopyBtn").addEventListener("click", diagCopy);
    document
      .getElementById("diagSupportPreviewBtn")
      .addEventListener("click", diagPreviewSupport);
    document
      .getElementById("diagSupportDownloadBtn")
      .addEventListener("click", diagDownloadSupport);
    document
      .getElementById("diagSizesBtn")
      .addEventListener("click", diagComputeSizes);
  }

  window.initDiagnostics = initDiagnostics;
  window.loadDiagnostics = loadDiagnostics;
  window.renderPreflightStatus = renderPreflightStatus;
  window.loadPreflightStatus = loadPreflightStatus;
  window.loadCaseStats = loadCaseStats;
  window.loadClockSkew = loadClockSkew;
  window.clockSkewMutate = clockSkewMutate;
  window.diagAiTest = diagAiTest;
  window.diagComputeSizes = diagComputeSizes;
  window.diagCopy = diagCopy;
  window.diagDownloadSupport = diagDownloadSupport;
  window.diagPreviewSupport = diagPreviewSupport;
})();
