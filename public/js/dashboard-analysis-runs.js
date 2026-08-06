// Reproducible analysis runs (#377) — the run history for a case, and the diff between any two
// of them (#415 tier 3).
//
// NO STATE OF ITS OWN. The modal reads what it needs on open, so there is nothing here that could
// escape — it is still IIFE-wrapped, because in a CLASSIC script every top-level binding this file
// might grow later would join the shared global lexical environment.
//
// ITS WIRING IS AN INITIALIZER, and the block itself runs nothing at load: the three controls
// (Compare, Cancel and the overlay backdrop) were bound in the page's shared modal-wiring block,
// nearly a thousand lines away. Left there, the page would read two of this file's functions as
// values while it parses, and a 404 would be a ReferenceError before the WebSocket connects rather
// than one dead modal.
//
// The backdrop handler calls jumpToEvent, which is the page's, not this module's — the same
// direction of dependency eleven other extracted modules already have.
(function () {
  // ── Reproducible analysis runs (#377) ────────────────────────────────────
  function openAnalysisRuns() {
    document.getElementById("arMsg").textContent = "";
    document.getElementById("arCompareResult").innerHTML = "";
    document.getElementById("arDetail").style.display = "none";
    document.getElementById("analysisRunsOverlay").classList.add("open");
    loadAnalysisRuns();
  }
  function closeAnalysisRuns() {
    document.getElementById("analysisRunsOverlay").classList.remove("open");
  }

  async function loadAnalysisRuns() {
    const caseId = document.getElementById("caseId").value.trim();
    const list = document.getElementById("arList");
    const integrity = document.getElementById("arIntegrity");
    if (!caseId) {
      list.textContent = "no case loaded";
      return;
    }
    list.textContent = "loading…";
    integrity.textContent = "checking integrity…";
    try {
      const c = encodeURIComponent(caseId);
      const [runsRes, integrityRes] = await Promise.all([
        fetch(`/cases/${c}/analysis-runs`),
        fetch(`/cases/${c}/analysis-runs/integrity`),
      ]);
      const runs = await runsRes.json();
      const check = await integrityRes.json();
      if (!runsRes.ok) throw new Error(runs.error || "HTTP " + runsRes.status);
      integrity.textContent = check.ok
        ? `✓ Ledger intact — ${check.manifests} manifest(s), hash chain verified`
        : `⚠ Ledger integrity FAILED — ${(check.problems || []).join("; ")}`;
      integrity.style.color = check.ok
        ? "var(--sev-low)"
        : "var(--badge-danger-text)";
      if (!runs.length) {
        list.textContent =
          "no runs yet — import evidence, run analysis, enrich, or generate a report";
        document.getElementById("arFrom").innerHTML = "";
        document.getElementById("arTo").innerHTML = "";
        return;
      }
      list.innerHTML = runs
        .map((run) => {
          const warnings = run.execution?.warnings?.length
            ? `<div data-safe-style="color:var(--sev-medium)">⚠ ${run.execution.warnings.map(esc).join("; ")}</div>`
            : "";
          const parent = run.parentRunId
            ? `<span title="${escAttr(run.parentRunId)}"> · child of ${esc(run.parentRunId.slice(0, 12))}…</span>`
            : "";
          const artifacts = run.input?.artifacts?.length
            ? ` · ${run.input.artifacts.length} artifact(s)`
            : "";
          return `<div data-safe-style="display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px solid var(--border-color)">
          <div><strong>${esc(run.kind)}</strong>${parent} · ${esc(new Date(run.startedAt).toLocaleString())}
            · ${(run.durationMs / 1000).toFixed(1)}s${artifacts}
            · ${run.input?.eventCount || 0} evidence event(s) → ${run.output?.claimCount || 0} claim(s)
            ${run.configuration?.provider ? `<div data-safe-style="color:var(--text-muted)">${esc(run.configuration.provider)}${run.configuration.model ? "/" + esc(run.configuration.model) : ""} · app ${esc(run.versions.application)}</div>` : ""}
            ${warnings}</div>
          <div data-safe-style="display:flex;gap:5px;align-items:flex-start;flex:none">
            <button type="button" data-ar-view="${escAttr(run.id)}" data-safe-style="font-size:11px">View manifest</button>
            <button type="button" data-ar-replay="${escAttr(run.id)}" data-safe-style="font-size:11px" title="Verify pinned dependencies, then create a new child run">Replay</button>
          </div>
        </div>`;
        })
        .join("");
      list
        .querySelectorAll("[data-ar-view]")
        .forEach(
          (btn) =>
            (btn.onclick = () =>
              viewAnalysisRun(btn.getAttribute("data-ar-view"))),
        );
      list
        .querySelectorAll("[data-ar-replay]")
        .forEach(
          (btn) =>
            (btn.onclick = () =>
              replayAnalysisRun(btn.getAttribute("data-ar-replay"))),
        );
      const options = runs
        .map(
          (run) =>
            `<option value="${escAttr(run.id)}">${esc(analysisRunLabel(run))}</option>`,
        )
        .join("");
      document.getElementById("arFrom").innerHTML = options;
      document.getElementById("arTo").innerHTML = options;
      document.getElementById("arFrom").selectedIndex = Math.min(
        1,
        runs.length - 1,
      );
      document.getElementById("arTo").selectedIndex = 0;
    } catch (err) {
      list.textContent = "failed to load: " + err.message;
    }
  }

  async function viewAnalysisRun(id) {
    const caseId = document.getElementById("caseId").value.trim();
    const detail = document.getElementById("arDetail");
    if (!caseId || !id) return;
    detail.style.display = "block";
    detail.textContent = "loading manifest…";
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/analysis-runs/${encodeURIComponent(id)}`,
      );
      const run = await res.json();
      if (!res.ok) throw new Error(run.error || "HTTP " + res.status);
      const eventLinks = (ids) =>
        ids?.length
          ? ids
              .map(
                (eventId) =>
                  `<button type="button" data-ar-evid="${escAttr(eventId)}" class="ev-jump">${esc(eventId)}</button>`,
              )
              .join(" ")
          : "none";
      const artifacts = run.input.artifacts?.length
        ? run.input.artifacts
            .map(
              (item) =>
                `<div><code>${esc(item.path)}</code><br><span data-safe-style="color:var(--text-muted)">SHA-256 ${esc(item.sha256)}</span></div>`,
            )
            .join("")
        : "none";
      const claims = run.output.claims?.length
        ? run.output.claims
            .map(
              (claim) =>
                `<div data-safe-style="margin:4px 0"><strong>${esc(claim.id)}</strong> · ${esc(claim.hash)}<br>evidence: ${eventLinks(claim.evidenceEventIds)}</div>`,
            )
            .join("")
        : "none";
      detail.innerHTML = `<div data-safe-style="display:flex;justify-content:space-between;gap:8px">
        <strong>Manifest #${run.sequence} · ${esc(run.kind)} · ${esc(run.status)}</strong>
        <button type="button" data-ar-hide data-safe-style="font-size:11px">Hide</button></div>
        <div data-safe-style="color:var(--text-muted);margin:4px 0">Run ${esc(run.id)}${run.parentRunId ? ` · parent ${esc(run.parentRunId)}` : ""}<br>
        ${esc(run.startedAt)} → ${esc(run.finishedAt)} · ${run.durationMs} ms<br>
        manifest SHA-256 ${esc(run.manifestHash)}<br>previous ${run.previousManifestHash ? esc(run.previousManifestHash) : "ledger start"}</div>
        <strong>Source artifacts</strong><div>${artifacts}</div>
        <strong>Evidence events (${run.input.eventIds?.length || 0})</strong><div>${eventLinks(run.input.eventIds)}</div>
        <strong>Input entities (${run.input.entityIds?.length || 0})</strong><div>${esc((run.input.entityIds || []).join(", ") || "none")}</div>
        <strong>Pinned versions and configuration</strong>
        <pre data-safe-style="white-space:pre-wrap;margin:3px 0">${esc(JSON.stringify({ versions: run.versions, configuration: run.configuration, execution: run.execution }, null, 2))}</pre>
        <strong>Output claims (${run.output.claims?.length || 0})</strong><div>${claims}</div>`;
      detail.querySelector("[data-ar-hide]").onclick = () => {
        detail.style.display = "none";
      };
    } catch (err) {
      detail.textContent = "manifest failed to load: " + err.message;
    }
  }

  async function replayAnalysisRun(id) {
    const caseId = document.getElementById("caseId").value.trim();
    const msg = document.getElementById("arMsg");
    if (!caseId || !id) return;
    if (
      !confirm(
        "Replay this run? The Companion will verify its model, prompt, rules and source evidence first. A replay creates a new child run and may spend provider credits.",
      )
    )
      return;
    msg.textContent = "checking dependencies…";
    try {
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/analysis-runs/${encodeURIComponent(id)}/replay`,
        { method: "POST" },
      );
      const body = await res.json();
      if (!res.ok) {
        const blockers = Array.isArray(body.blockers)
          ? body.blockers.join("; ")
          : body.error;
        throw new Error(blockers || "HTTP " + res.status);
      }
      msg.textContent =
        res.status === 202
          ? "replay accepted — refresh shortly for its child run"
          : "replay completed ✓";
      setTimeout(loadAnalysisRuns, res.status === 202 ? 1500 : 100);
    } catch (err) {
      msg.textContent = "replay not started: " + err.message;
    }
  }

  async function compareAnalysisRuns() {
    const caseId = document.getElementById("caseId").value.trim();
    const from = document.getElementById("arFrom").value;
    const to = document.getElementById("arTo").value;
    const out = document.getElementById("arCompareResult");
    if (!caseId || !from || !to) return;
    out.textContent = "comparing…";
    try {
      const q = new URLSearchParams({ from, to }).toString();
      const res = await fetch(
        `/cases/${encodeURIComponent(caseId)}/analysis-runs/compare?${q}`,
      );
      const diff = await res.json();
      if (!res.ok) throw new Error(diff.error || "HTTP " + res.status);
      const evidence = (ids) =>
        ids.length
          ? ids
              .map(
                (id) =>
                  `<button type="button" data-ar-evid="${escAttr(id)}" class="ev-jump">${esc(id)}</button>`,
              )
              .join(" ")
          : "no linked events";
      const rows = [
        ...diff.added.map(
          (claim) =>
            `<div data-safe-style="margin-bottom:5px">+ <strong>${esc(claim.id)}</strong> — ${evidence(claim.evidenceEventIds)}</div>`,
        ),
        ...diff.removed.map(
          (claim) =>
            `<div data-safe-style="margin-bottom:5px">− <strong>${esc(claim.id)}</strong> — ${evidence(claim.evidenceEventIds)}</div>`,
        ),
        ...diff.changed.map(
          (claim) =>
            `<div data-safe-style="margin-bottom:5px">~ <strong>${esc(claim.id)}</strong><br>before: ${evidence(claim.beforeEvidenceEventIds)}<br>after: ${evidence(claim.afterEvidenceEventIds)}</div>`,
        ),
      ];
      out.innerHTML = rows.length
        ? rows.join("")
        : "no claim changes between these runs";
    } catch (err) {
      out.textContent = "compare failed: " + err.message;
    }
  }

  // The three controls the page's shared modal-wiring block used to bind. Order unchanged.
  function initAnalysisRuns() {
    document.getElementById("arCompare").onclick = compareAnalysisRuns;
    document.getElementById("arCancel").onclick = closeAnalysisRuns;
    document
      .getElementById("analysisRunsOverlay")
      .addEventListener("click", (e) => {
        if (e.target.id === "analysisRunsOverlay") {
          closeAnalysisRuns();
          return;
        }
        const jump = e.target.closest && e.target.closest("[data-ar-evid]");
        if (jump) {
          closeAnalysisRuns();
          jumpToEvent(jump.getAttribute("data-ar-evid"));
        }
      });
  }

  window.openAnalysisRuns = openAnalysisRuns;
  window.closeAnalysisRuns = closeAnalysisRuns;
  window.compareAnalysisRuns = compareAnalysisRuns;
  window.initAnalysisRuns = initAnalysisRuns;
})();
