// The Fleet Collection panel's run list — every saved Velociraptor bundle with a ▶ Run button, and
// the per-run form that opens under it.
//
// SETTINGS CONFIGURES THE APPLICATION; RUNNING A BUNDLE ACTS ON THE CASE. Every Settings tab is
// global — except the Velociraptor tab, where "▶ Run" sat between Edit and Delete and launched a
// hunt into whichever case was connected. The analyst's mental model broke there: a bundle looked
// like a setting, but pressing Run collected from live endpoints into one case. So the run list
// moved out to the dashboard (#sec-fleet-collection), beside the Suggested Fleet Hunts it feeds,
// and Settings → Velociraptor keeps only the shared library (build / edit / duplicate / delete).
//
// PURE, AND HOLDS NOTHING. The bundle list and the fleet snapshot live in
// js/dashboard-velo-triage.js, which owns the loads that refresh them and hands them out through
// veloBundlesList() / veloClientsList(). That module also keeps veloRunBundle() and the time-scope
// preview, because both are the same request path the job card refreshes from. This file only
// renders and wires; the triage module calls renderVeloRunList() after every bundle load.

// One card per bundle: name, what it collects, and Run — or a disabled Run that says why
// (js/dashboard-velo-case.js decides the reason). No editing controls here on purpose.
function renderVeloRunList(bundles) {
  const el = document.getElementById("veloRunList");
  if (!el) return;
  if (!bundles.length) {
    el.innerHTML =
      "<div data-safe-style='color:var(--text-muted);font-size:12px'>No bundles yet — build one under <a href='#' class='velo-open-library' data-safe-style='color:var(--accent)'>Settings → Velociraptor</a>.</div>";
    veloWireOpenLibrary(el);
    return;
  }
  const runBlocked = veloRunBlockedReason(veloEnabled, veloCaseId());
  el.innerHTML =
    bundles
      .map((b) => {
        const runBtn = runBlocked
          ? `<button disabled title="${escAttr(runBlocked)}">▶ Run</button>`
          : `<button class="velo-run-btn" data-id="${escAttr(b.id)}" title="Run this bundle as a hunt on the configured Velociraptor server, into the connected case">▶ Run</button>`;
        const badge = b.builtIn
          ? ` <span data-safe-style='color:var(--accent);font-size:11px'>built-in${b.customized ? " · edited" : ""}</span>`
          : "";
        return `<div class="velo-bundle" data-safe-style="border:1px solid var(--border-color);border-radius:6px;padding:8px 10px;margin-bottom:8px">
        <div data-safe-style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <div><strong>${esc(b.name)}</strong>${badge} <span data-safe-style="color:var(--text-muted);font-size:11px">${esc(b.artifacts.length)} artifact(s)</span></div>
          <div data-safe-style="display:flex;gap:6px;flex-wrap:wrap">${runBtn}</div>
        </div>
        ${b.description ? `<div data-safe-style="color:var(--text-muted);font-size:12px;margin-top:4px">${esc(b.description)}</div>` : ""}
        <div data-safe-style="color:var(--text-dim);font-size:11px;margin-top:4px">${b.artifacts.map((a) => esc(a)).join(", ")}</div>
        <div class="velo-run-form" data-id="${escAttr(b.id)}" data-safe-style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid var(--border-color)"></div>
      </div>`;
      })
      .join("") +
    `<div data-safe-style="font-size:11px;color:var(--text-dim)">Build or edit bundles under <a href="#" class="velo-open-library" data-safe-style="color:var(--accent)">Settings → Velociraptor</a> — bundles are shared across cases; a run goes into this case.</div>`;
  el.querySelectorAll(".velo-run-btn").forEach(
    (btn) => (btn.onclick = () => toggleVeloRunForm(btn.dataset.id)),
  );
  veloWireOpenLibrary(el);
}

function veloWireOpenLibrary(el) {
  el.querySelectorAll(".velo-open-library").forEach(
    (a) =>
      (a.onclick = (e) => {
        e.preventDefault();
        openSettingsTab("velociraptor");
      }),
  );
}

function veloRunForm(id) {
  const forms = document.querySelectorAll(".velo-run-form");
  for (const f of forms) if (f.dataset.id === id) return f;
  return null;
}

function toggleVeloRunForm(id) {
  const bundle = veloBundlesList().find((b) => b.id === id);
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
  // Only labels the cached fleet really carries; js/dashboard-velo-labels.js says why it is a picker.
  const fleetLabels = veloFleetLabels(veloClientsList());
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
        ${veloLabelPickerHtml("inc", fleetLabels)}
        ${veloLabelPickerHtml("exc", fleetLabels)}
        <button class="velo-run-go">Run hunt</button>
        <span class="velo-run-msg" data-safe-style="font-size:12px;color:var(--text-muted)"></span>
      </div>
      <div data-safe-style="font-size:11px;color:var(--text-dim);margin-top:4px">Runs across all enrolled clients unless you set a label/OS filter. Collection timeout: <strong>${timeoutNote}</strong> — set it on the bundle (Settings → Velociraptor → <em>Edit</em>) for slow artifacts like THOR. Results (+ any uploaded JSON report) are auto-collected after the wait, then imported + synthesized — or click <em>Collect now</em> on the job card.</div>
      <div class="velo-ts-preview" data-safe-style="font-size:11px;color:var(--text-dim);margin-top:4px"></div>`;
  form.style.display = "block";
  veloWireLabelPickers(form);
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

window.renderVeloRunList = renderVeloRunList;
window.toggleVeloRunForm = toggleVeloRunForm;
