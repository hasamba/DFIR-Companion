// Last-import change tracking — what the most recent import actually added — extracted from
// dashboard.html (issue #415, tier 3).
//
// Three escapes, all of them READS from the page's two render paths: newEventKeys.has(evKey(e))
// in the event list and newIocKeys.has(i.value) in the IOC table. Both renderers are page core
// machinery and stay there, so what crosses the boundary is a question, not a variable:
// isNewEvent() and isNewIoc(). That also makes the missing-module answer the safe one — a stub
// returns falsy, so the NEW badge simply does not appear. It drops a decoration, never an event.
//
// Nothing here runs at load, so there is no initializer: the panel is drawn by loadImportMeta(),
// which the refresh fan-out already calls.
(function () {
  "use strict";

  // The import analog of the synthesis what-changed view above: banners (above the Forensic
  // Timeline and above the IOCs) showing when the last import ran and how many events / IOCs it
  // added, plus per-row "new" highlights keyed the SAME way the server computed each diff (events
  // by normalized time+description — see timelineDiff.ts; IOCs by exact value — see iocsDiff.ts).
  // The key sets are rebuilt whenever import-meta loads, then both lists are re-rendered.
  const CAP_IMPORT_LIST = 50; // how many added items to list in a banner detail
  let newEventKeys = new Set();
  let newIocKeys = new Set();
  const evNorm = (s) =>
    String(s == null ? "" : s)
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
  const evKey = (e) => `${evNorm(e.timestamp)}|${evNorm(e.description)}`;
  function loadImportMeta(caseId) {
    fetch(`/cases/${caseId}/import-meta`)
      .then((r) => r.json())
      .then(renderImportMeta)
      .catch(() => {});
  }
  // Evidence drop folder (#auto-import inbox): show where to drop + the last sweep's result, and
  // list any files that failed (they sit in drop/_failed/). Backed by GET /cases/:id/drop-status.
  function loadDropStatus(caseId) {
    fetch(`/cases/${caseId}/drop-status`)
      .then((r) => (r.ok ? r.json() : null))
      .then(renderDropStatus)
      .catch(() => {});
  }
  // The drop-folder auto-import feature stays fully enabled (the server poller keeps ingesting
  // cases/<id>/drop/); we deliberately do NOT surface its inbox/sweep banner in the dashboard —
  // EXCEPT the actionable "raw EVTX/PCAP awaiting an external tool" case (#211), which needs an
  // analyst decision (run a tool / configure one), so it's surfaced as a banner.
  // Drop-folder raw files awaiting a tool (#211): ONE batch prompt for the whole set — "N raw files
  // dropped, run tools on them? [Run all] [Dismiss]". A single POST runs every pending file through
  // its matching tool server-side. Files with no configured tool are noted (link to Settings).
  function renderDropStatus(d) {
    const el = document.getElementById("dropStatus");
    if (!el) return;
    // GET /cases/:id/drop-status wraps the record as { enabled, pollSeconds, dropPath, status }.
    const st = (d && d.status) || d || {};
    const pending = st.pendingRawInputs || [];
    if (!pending.length) {
      el.style.display = "none";
      el.innerHTML = "";
      return;
    }
    const caseId = (document.getElementById("caseId").value || "").trim();
    const n = pending.length;
    const anyConfigured = pending.some((p) => p.configured && p.suggestedTool);
    const files = pending
      .map((p) => `<code>${esc(p.relpath)}</code>`)
      .join(", ");
    el.style.display = "block";
    const head = `<div class="rb-head">📥 ${n} raw file${n !== 1 ? "s" : ""} dropped — run a tool on ${n !== 1 ? "them" : "it"}?</div>`;
    const body = `<div class="rb-files">${files}</div>`;
    const actions = anyConfigured
      ? `<button class="rb-yes" id="dropRunAll">Run tools on ${n !== 1 ? "these " + n + " files" : "this file"}</button><button class="rb-no" id="dropDismiss">Dismiss</button>`
      : `<div class="rb-files">No external tool is configured for ${n !== 1 ? "these file types" : "this file type"}.</div><button class="rb-yes" id="dropConfigure">Configure tools</button><button class="rb-no" id="dropDismiss">Dismiss</button>`;
    el.innerHTML = head + body + actions;
    const dis = document.getElementById("dropDismiss");
    if (dis)
      dis.onclick = () => {
        el.style.display = "none";
      };
    const cfg = document.getElementById("dropConfigure");
    if (cfg) cfg.onclick = openToolsSettings;
    const runAll = document.getElementById("dropRunAll");
    if (runAll)
      runAll.onclick = () => {
        runAll.disabled = true;
        runAll.textContent = "Running…";
        fetch(`/cases/${caseId}/drop/run-pending`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        })
          .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
          .then(({ ok, j }) => {
            if (!ok) {
              runAll.disabled = false;
              runAll.textContent = "Retry";
              document.getElementById("status").textContent =
                (j && j.error ? j.error : "run failed") +
                " — restart the companion server if this 404s";
              return;
            }
            document.getElementById("status").textContent =
              `Ran ${j.ran || 0} tool run(s)` +
              (j.failed ? `, ${j.failed} failed` : "") +
              (j.skipped ? `, ${j.skipped} skipped (no tool)` : "");
            loadDropStatus(caseId);
            loadImportMeta(caseId);
          })
          .catch((e) => {
            runAll.disabled = false;
            runAll.textContent = "Retry";
            document.getElementById("status").textContent =
              "run failed: " + e.message;
          });
      };
  }
  // Display names for the external tools (kept in sync with TOOL_DEFS labels server-side).
  const TOOL_LABELS = {
    hayabusa: "Hayabusa",
    velociraptor_cli: "Velociraptor CLI",
    suricata: "Suricata",
    snort: "Snort",
    yara: "YARA",
  };
  // Deep-link the Settings modal straight to the Tools tab (mirrors the velo badge link).
  function openToolsSettings() {
    openSettingsTab("tools");
  }
  // Display label for a tool id (built-in label or custom name), from /tools/status; falls back to the id.
  function toolLabel(id, status) {
    const t = ((status && status.tools) || []).find((x) => x.id === id);
    return (t && t.label) || TOOL_LABELS[id] || id || "a tool";
  }
  // Every file extension any tool (built-in or custom) handles → used to detect raw-tool inputs in the
  // Import dialog. From /tools/status so custom-tool extensions are included. Returns a Set or empty.
  function fetchRawToolExts() {
    return fetch("/tools/status")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        const set = new Set();
        for (const t of (j && j.tools) || [])
          for (const e of t.extensions || []) set.add(String(e).toLowerCase());
        return set;
      })
      .catch(() => new Set());
  }
  // Raw evidence picked in the Import dialog → one banner listing each file with the tools that
  // can analyze it. Zips also get a password box, defaulting to "infected". #211
  function askRunToolsOnImport(caseId, rawFiles) {
    const el = document.getElementById("rawToolBanner");
    if (!el) return;
    fetch("/tools/status")
      .then((r) => (r.ok ? r.json() : null))
      .then((status) => {
        const items = rawFiles.map((f, i) => {
          const ext = "." + (f.name.split(".").pop() || "").toLowerCase();
          return {
            idx: i,
            file: f,
            ext,
            tools: toolsForExt(ext, status),
            isZip: /\.(zip|7z|rar)$/i.test(f.name),
          };
        });
        const runnable = items.filter((it) => it.tools.length);
        const notCfg = items.filter((it) => !it.tools.length);
        el.style.display = "block";

        if (!runnable.length) {
          const sug = [
            ...new Set(
              items.map((it) =>
                toolLabel(suggestToolForExt(it.ext, status), status),
              ),
            ),
          ].join(", ");
          const many = rawFiles.length !== 1;
          el.innerHTML =
            '<div class="rb-head">⚠️ Raw evidence not directly supported</div>' +
            '<div class="rb-files">The Companion analyzes tool <em>output</em>, not raw binaries. Configure <strong>' +
            esc(sug) +
            "</strong> (Settings → Tools) to analyze " +
            (many ? "these" : "this") +
            ", then re-import — or copy into the case <strong>drop folder</strong> " +
            "(EVTX can also be exported to XML via <code>wevtutil qe /f:xml</code>).</div>" +
            '<button class="rb-yes" id="rawCfgBtn">Settings → Tools</button><button class="rb-no" id="rawRunNo">Dismiss</button>';
        } else {
          let rows = "";
          for (const it of runnable) {
            const boxes = it.tools
              .map(
                (t) =>
                  '<label class="rb-tool"><input type="checkbox" data-file="' +
                  it.idx +
                  '" value="' +
                  esc(t.id) +
                  '" checked> ' +
                  esc(t.label) +
                  "</label>",
              )
              .join(" ");
            const pw = it.isZip
              ? '<input class="rb-pw" type="password" data-pw="' +
                it.idx +
                '" placeholder="infected" autocomplete="off">'
              : "";
            rows +=
              '<div class="rb-row"><code>' +
              esc(it.file.name) +
              "</code> " +
              boxes +
              " " +
              pw +
              "</div>";
          }
          const many = rawFiles.length !== 1;
          let head =
            '<div class="rb-head">⚠️ ' +
            rawFiles.length +
            " raw " +
            (many ? "files" : "file") +
            " — the Companion can't read " +
            (many ? "them" : "it") +
            " directly. Choose what to run:</div>";
          if (notCfg.length) {
            rows +=
              '<div class="rb-files">' +
              notCfg.length +
              " file(s) have no configured tool and will be skipped — " +
              '<a href="#" id="rawCfgLink">configure in Settings → Tools</a>.</div>';
          }
          el.innerHTML =
            head +
            rows +
            '<button class="rb-yes" id="rawRunYes">Run selected</button><button class="rb-no" id="rawRunNo">No</button>';
        }

        const no = document.getElementById("rawRunNo");
        if (no)
          no.onclick = () => {
            el.style.display = "none";
          };
        const cfgBtn = document.getElementById("rawCfgBtn");
        if (cfgBtn) cfgBtn.onclick = openToolsSettings;
        const cfgLink = document.getElementById("rawCfgLink");
        if (cfgLink)
          cfgLink.onclick = (ev) => {
            ev.preventDefault();
            openToolsSettings();
          };
        const yes = document.getElementById("rawRunYes");
        if (yes)
          yes.onclick = () => {
            // Expand the checkbox grid into one (file, tool, password) run per ticked box.
            const runs = [];
            el.querySelectorAll(
              'input[type="checkbox"][data-file]:checked',
            ).forEach((cb) => {
              const it = runnable.find(
                (x) => String(x.idx) === cb.getAttribute("data-file"),
              );
              if (!it) return;
              const pwEl = el.querySelector('input[data-pw="' + it.idx + '"]');
              runs.push({
                file: it.file,
                toolId: cb.value,
                zipPassword: pwEl ? pwEl.value : "",
              });
            });
            if (!runs.length) {
              el.style.display = "none";
              return;
            }
            runUploadRawFiles(caseId, runs, el, yes);
          };
      })
      .catch(() => {
        el.style.display = "none";
      });
  }
  // Upload each selected file's bytes and run its tool. Spawn tools return counts synchronously;
  // SO-CRATES returns job ids because its analysis is asynchronous, so those are polled after.
  // Files too big for the JSON body cap are skipped with a hint to use the drop folder. #211
  function runUploadRawFiles(caseId, runs, el, btn) {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Running…";
    }
    const statusEl = document.getElementById("status");
    const LARGE_MB = 180; // base64 body must fit DFIR_MAX_BODY_MB (default 256 MB → ~190 MB raw)
    (async () => {
      let ran = 0,
        failed = 0,
        ev = 0,
        ioc = 0;
      const jobIds = [];
      for (const it of runs) {
        statusEl.textContent =
          "running " + it.toolId + " on " + it.file.name + "…";
        try {
          if (it.file.size > LARGE_MB * 1024 * 1024) {
            failed++;
            statusEl.textContent =
              it.file.name +
              " is too large to upload — copy it into the case drop folder instead";
            continue;
          }
          const b64 = await fileToBase64(it.file);
          if (!b64) {
            failed++;
            continue;
          }
          const body = { filename: it.file.name, dataBase64: b64 };
          if (it.zipPassword) body.zipPassword = it.zipPassword;
          const r = await fetch(
            "/cases/" + caseId + "/tools/" + it.toolId + "/run-upload",
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            },
          );
          const j = await r.json().catch(() => ({}));
          if (!r.ok) {
            failed++;
            // Surface the reason (wrong zip password, unreachable service) instead of a silent skip.
            statusEl.textContent = it.file.name + ": " + (j.error || "failed");
            console.warn("tool run failed", it.file.name, j.error);
            continue;
          }
          ran++;
          ev += j.addedEvents || 0;
          ioc += j.addedIocs || 0;
          if (Array.isArray(j.jobIds)) jobIds.push.apply(jobIds, j.jobIds);
          if (j.truncated)
            statusEl.textContent =
              it.file.name +
              ": only the first 25 archive entries were submitted";
        } catch (e) {
          failed++;
          console.warn("tool run error", it.file.name, e && e.message);
        }
      }
      if (el) el.style.display = "none";
      statusEl.textContent =
        "Ran " +
        ran +
        " run(s): +" +
        ev +
        " event(s), +" +
        ioc +
        " IOC(s)" +
        (failed ? ", " + failed + " failed/skipped" : "") +
        (jobIds.length
          ? " — " + jobIds.length + " SO-CRATES analysis/es running…"
          : "");
      if (jobIds.length) pollSocratesJobs(caseId, jobIds);
      loadImportMeta(caseId);
    })();
  }
  // SO-CRATES analysis is asynchronous, so follow the jobs until every one is terminal. Polls at
  // 5s and gives up after 20 minutes, matching the server-side attempt ceiling.
  function pollSocratesJobs(caseId, jobIds) {
    const statusEl = document.getElementById("status");
    const wanted = new Set(jobIds);
    let ticks = 0;
    const timer = setInterval(async () => {
      ticks++;
      try {
        const r = await fetch("/cases/" + caseId + "/socrates/jobs");
        if (!r.ok) return;
        const jobs = ((await r.json()).jobs || []).filter((j) =>
          wanted.has(j.jobId),
        );
        const done = jobs.filter(
          (j) => j.status === "imported" || j.status === "error",
        );
        const running = jobs.filter(
          (j) => j.status !== "imported" && j.status !== "error",
        );
        if (running.length) {
          const phase = running[0].phase ? " (" + running[0].phase + ")" : "";
          statusEl.textContent =
            "SO-CRATES: analyzing" +
            phase +
            " — " +
            running.length +
            " remaining…";
        }
        if (jobs.length && done.length === jobs.length) {
          clearInterval(timer);
          const ev = done.reduce((n, j) => n + (j.addedEvents || 0), 0);
          const errs = done.filter((j) => j.status === "error");
          statusEl.textContent =
            "SO-CRATES finished: +" +
            ev +
            " event(s)" +
            (errs.length
              ? ", " + errs.length + " failed — " + (errs[0].error || "")
              : "");
          loadImportMeta(caseId);
        }
      } catch (e) {
        /* transient; keep polling */
      }
      if (ticks > 240) clearInterval(timer);
    }, 5000);
  }
  function renderImportMeta(m) {
    paintTimelineImportMeta(m);
    paintIocImportMeta(m);
  }
  function paintTimelineImportMeta(m) {
    const el = document.getElementById("importMeta");
    if (!el) return;
    const d = (m && m.lastDiff) || { added: [], removed: [] };
    // Rebuild the "new event" set used to highlight timeline rows, then re-render the timeline.
    newEventKeys = new Set((d.added || []).map(evKey));
    if (DfirState.lastFt()) renderTimelineEvents(DfirState.lastFt());
    if (!m || !m.lastImportedAt) {
      el.innerHTML = "";
      el.style.display = "none";
      return;
    }
    el.style.display = "block";
    const added = m.addedCount || 0,
      removed = m.removedCount || 0;
    const counts = [];
    if (added)
      counts.push(
        `<span class="sm-added">+${added} new event${added !== 1 ? "s" : ""}</span>`,
      );
    if (removed)
      counts.push(`<span class="sm-removed">⊖ ${removed} merged</span>`);
    const summary = counts.length ? counts.join(" · ") : "no new events";
    const src = m.lastImportFile
      ? ` from <strong>${esc(m.lastImportFile)}</strong>`
      : "";
    const kind = m.lastImportKind
      ? ` <span data-safe-style="color:var(--accent)">(${esc(m.lastImportKind)})</span>`
      : "";
    let detail = "";
    const list = d.added || [];
    if (list.length) {
      const items = list
        .slice(0, CAP_IMPORT_LIST)
        .map(
          (x) =>
            `<span class="sm-item sm-added">+ <span class="sev-${esc(x.severity)}">${esc(x.timestamp || "(undated)")}</span> ${esc(x.description)}</span>`,
        )
        .join("");
      const remaining = added - Math.min(CAP_IMPORT_LIST, list.length);
      const more =
        remaining > 0
          ? `<span class="sm-item" data-safe-style="color:var(--text-muted)">…and ${remaining} more</span>`
          : "";
      detail = `<details><summary>what this import added to the timeline</summary>${items}${more}</details>`;
    }
    // Source-yield warning (investigation-guidance #10): a large file run through the AI-triage path
    // that produced ZERO events is a blind spot, not a clean source — say so with a directive action,
    // instead of a bland "no new events". Mirrors the server classifyImportYield (path ai / +0 / >=500).
    let yieldWarn = "";
    if (
      m.path === "ai" &&
      (m.addedCount || 0) === 0 &&
      (m.linesIn || 0) >= 500
    ) {
      const label = m.lastImportFile || m.lastImportKind || "this file";
      yieldWarn = `<div class="sm-line" data-safe-style="color:var(--badge-danger-text);font-weight:600">⚠️ ${esc(label)}: ${m.linesIn.toLocaleString()} lines → 0 events via AI triage — re-run triage or grep the raw file for the case's IOCs/hosts before treating this source as clean.</div>`;
    }
    // Cap-hit truncation (#10 trigger b): the log-aggregation cap dropped distinct patterns the AI never
    // saw — a rare one-off attack line can hide there. Mirrors the server classifyImportYield cap_hit.
    const tr = m.truncation;
    if (tr && (tr.distinctTemplates || 0) > (tr.keptTemplates || 0)) {
      const label = m.lastImportFile || m.lastImportKind || "this file";
      const dropped = tr.distinctTemplates - tr.keptTemplates;
      yieldWarn += `<div class="sm-line" data-safe-style="color:var(--badge-warning-text);font-weight:600">⚠️ ${esc(label)}: ${dropped.toLocaleString()} of ${tr.distinctTemplates.toLocaleString()} distinct log patterns weren't triaged (cap ${tr.keptTemplates.toLocaleString()}) — a one-off attack line can hide in the dropped rare patterns; raise DFIR_LOG_MAX_TEMPLATES or split the file and re-import.</div>`;
    }
    // Proactive FP-pattern propagation (#15b): new events reproduce a known false-positive pattern —
    // offer a one-click bulk-mark (SUGGESTED, never auto-applied). data-evids drives the batch call.
    let fpProp = "";
    const props = Array.isArray(m.fpPropagation)
      ? m.fpPropagation.filter((p) => p && (p.count || 0) > 0)
      : [];
    if (props.length) {
      fpProp = props
        .map((p) => {
          const what = esc(
            (p.note || p.ref || "a marked-FP pattern").slice(0, 80),
          );
          return (
            `<div class="sm-line" data-safe-style="color:var(--badge-warning-text);font-weight:600" title="These new events match the pattern of a finding/event you previously marked false positive. Review, then bulk-mark — never auto-applied.">` +
            `🔁 ${p.count} new event${p.count === 1 ? "" : "s"} match FP pattern “${what}” ` +
            `<a href="#" class="fp-propagate" data-evids="${escAttr((p.matchedEventIds || []).join(","))}" data-label="${escAttr(p.note || p.ref || "FP pattern")}" data-safe-style="color:var(--accent);margin-left:6px">review &amp; bulk-mark →</a>` +
            `</div>`
          );
        })
        .join("");
    }
    el.innerHTML = `<div class="sm-line"><span>📥 Last import <strong>${esc(relTime(m.lastImportedAt))}</strong>${src}${kind}</span><span>${summary}</span></div>${yieldWarn}${fpProp}${detail}`;
  }
  // #15b: bulk-mark every new event matching a propagated FP pattern (one confirm → batch endpoint).
  function propagateFalsePositive(ids, label) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !ids.length) return;
    if (
      !confirm(
        `Mark all ${ids.length} new event(s) matching the “${label}” pattern as false positive?`,
      )
    )
      return;
    const items = ids.map((id) => ({
      kind: "event",
      ref: id,
      reason: "duplicate",
    }));
    fetch(`/cases/${caseId}/false-positive/batch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        items,
        reason: "duplicate",
        note: `matches previously-marked FP pattern (${label})`,
      }),
    })
      .then(() => {
        const c = document.getElementById("caseId").value.trim();
        if (c)
          fetch(`/cases/${c}/import-meta`)
            .then((r) => r.json())
            .then(renderImportMeta)
            .catch(() => {});
      })
      .catch(() => {});
  }
  function paintIocImportMeta(m) {
    const el = document.getElementById("iocImportMeta");
    if (!el) return;
    const d = (m && m.iocsDiff) || { added: [], removed: [] };
    // Rebuild the "new IOC" set (keyed by exact value), then re-render the IOC list.
    newIocKeys = new Set((d.added || []).map((x) => x.value));
    if (DfirState.lastState()) renderIocs(DfirState.lastState().iocs || []);
    if (!m || !m.lastImportedAt) {
      el.innerHTML = "";
      el.style.display = "none";
      return;
    }
    el.style.display = "block";
    const added = m.iocsAddedCount || 0,
      removed = m.iocsRemovedCount || 0;
    const counts = [];
    if (added)
      counts.push(
        `<span class="sm-added">+${added} new IOC${added !== 1 ? "s" : ""}</span>`,
      );
    if (removed)
      counts.push(`<span class="sm-removed">⊖ ${removed} removed</span>`);
    const summary = counts.length ? counts.join(" · ") : "no new IOCs";
    let detail = "";
    const list = d.added || [];
    if (list.length) {
      const items = list
        .slice(0, CAP_IMPORT_LIST)
        .map(
          (x) =>
            `<span class="sm-item sm-added">+ <span data-safe-style="color:var(--text-muted)">${esc(x.type)}:</span> ${esc(x.value)}</span>`,
        )
        .join("");
      const remaining = added - Math.min(CAP_IMPORT_LIST, list.length);
      const more =
        remaining > 0
          ? `<span class="sm-item" data-safe-style="color:var(--text-muted)">…and ${remaining} more</span>`
          : "";
      detail = `<details><summary>what this import added to the IOCs</summary>${items}${more}</details>`;
    }
    el.innerHTML = `<div class="sm-line"><span>📥 Last import <strong>${esc(relTime(m.lastImportedAt))}</strong></span><span>${summary}</span></div>${detail}`;
  }

  // Import undo / redo (#76) moved to js/dashboard-import-undo.js (#415 tier 3). doAsk, which
  // sat under the same banner, is the AI Ask box and stayed — it follows immediately below.

  function doAsk() {
    const caseId = document.getElementById("caseId").value.trim();
    const q = document.getElementById("askInput").value.trim();
    if (!caseId) {
      document.getElementById("askAnswer").innerHTML =
        "<div data-safe-style='color:var(--text-muted)'>connect to a case first</div>";
      return;
    }
    if (!q) return;
    const box = document.getElementById("askAnswer");
    box.innerHTML =
      "<div data-safe-style='color:var(--text-muted)'>thinking…</div>";
    fetch(`/cases/${caseId}/ask`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ question: q }),
    })
      .then(async (r) => {
        if (r.status === 409) {
          const body = await r.json().catch(() => ({}));
          if (body.error === "presidio_approval_required") {
            if (typeof setPresidioPending === "function")
              setPresidioPending(body.findings);
            box.innerHTML =
              "<div data-safe-style='color:var(--tag-orange-text)'>Presidio found new value(s) awaiting approval — resolve them in Anonymization, then ask again.</div>";
            return null;
          }
        }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then((a) => {
        if (!a) return; // handled above (409 presidio hold)
        const events = citeEvents(a.relatedEventIds);
        box.innerHTML =
          `<div class="info-card">` +
          `<div>${askStatusBadge(a.status)} <strong>${esc(q)}</strong></div>` +
          `<div data-safe-style="margin:6px 0">${esc(a.answer || "(no answer)")}</div>` +
          (a.pointer
            ? `<div data-safe-style="color:var(--accent)"><small>→ where to look: ${esc(a.pointer)}</small></div>`
            : "") +
          (events
            ? `<div data-safe-style="color:var(--text-muted)"><small>cited events: ${events}</small></div>`
            : "") +
          `<div data-safe-style="margin-top:8px"><button id="askAddBtn" title="Add this to the case's open Key Investigative Questions (with the collection pointer); synthesis will answer it once the evidence supports it">Add to open questions</button> <span id="askAddStatus" data-safe-style="color:var(--text-muted);font-size:12px"></span></div>` +
          `</div>`;
        document.getElementById("askAddBtn").onclick = () => {
          const st = document.getElementById("askAddStatus");
          st.textContent = "adding…";
          fetch(`/cases/${caseId}/questions`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              question: q,
              answer: a.answer || "",
              status: a.status || "unknown",
              pointer: a.pointer || "",
            }),
          })
            .then((r) => {
              if (!r.ok) throw new Error("HTTP " + r.status);
              return r.json();
            })
            .then(() => {
              st.textContent = "added to Key Investigative Questions ✓";
              document.getElementById("askAddBtn").disabled = true;
            })
            .catch((e) => (st.textContent = "failed: " + e.message));
        };
      })
      .catch(
        (e) =>
          (box.innerHTML = `<div data-safe-style="color:var(--sev-high)">ask failed: ${esc(e.message)} — restart the companion server if this 404s</div>`),
      );
  }

  // Explain Event (#141) moved to js/dashboard-explain-event.js (#415 tier 3). No initializer.
  // Query Translator, the scope-apply function and the AI toggle shared one banner and are
  // three separate modules now: js/dashboard-query-translator.js, js/dashboard-scope-apply.js
  // and js/dashboard-ai-toggle.js (#415 tier 3). None has load-time work.

  // The two questions the page's renderers ask. Keeping evKey's shape private means the key
  // format can change without a second copy of it drifting in the page.
  function isNewEvent(e) {
    return newEventKeys.has(evKey(e));
  }
  function isNewIoc(value) {
    return newIocKeys.has(value);
  }

  window.loadImportMeta = loadImportMeta;
  window.loadDropStatus = loadDropStatus;
  window.fetchRawToolExts = fetchRawToolExts;
  window.askRunToolsOnImport = askRunToolsOnImport;
  window.propagateFalsePositive = propagateFalsePositive;
  window.paintIocImportMeta = paintIocImportMeta;
  window.doAsk = doAsk;
  window.isNewEvent = isNewEvent;
  window.isNewIoc = isNewIoc;
})();
