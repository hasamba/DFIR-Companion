// Per-asset event-rate spikes (#12) (#415 tier 3).
//
// A derived panel: the server computes the spikes, this draws them and offers the one-click
// false-positive cascade. Its two state cells are a cached response and a debounce timer.
//
// AN IIFE, unlike js/dashboard-tagger.js and js/dashboard-kev.js. Those hold no state, so their
// top-level declarations were harmless. This feature owns state, and a top-level `let` in a
// classic script joins the global LEXICAL environment — reachable by name from every other script
// on the page, which is the hazard js/dashboard-state.js sets out at length. Wrapping it is what
// makes "feature-local" true rather than merely intended.
//
// NOT AN ES MODULE: the inline script calls the published names below by bare name.
(function () {
  // ── Timeline Anomalies (#175) ─────────────────────────────────────────────────────────
  // Per-asset event-rate spikes: assets whose count in a time bucket exceeds spikeFactor × the
  // per-bucket median across all assets. Derived server-side (GET /cases/:id/anomalies) from the
  // in-scope timeline; re-derived (debounced) on each state change, like the phases/gaps panels.
  // Clicking an asset row scrolls the forensic-timeline filter to that asset's events.
  let anomaliesData = null;
  let anomaliesTimer = null;
  function loadAnomalies(caseId) {
    fetch(`/cases/${caseId}/anomalies`).then(r => r.json()).then(d => {
      anomaliesData = (d && typeof d === "object") ? d : null;
      renderAnomalies();
    }).catch(() => {});
  }
  function scheduleAnomaliesReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(anomaliesTimer);
    anomaliesTimer = setTimeout(() => loadAnomalies(caseId), 800);
  }
  function renderAnomalies() {
    const el = document.getElementById("anomalies");
    if (!el) return;
    const d = anomaliesData;
    if (!d) { el.innerHTML = "<span data-safe-style='color:var(--text-muted)'>—</span>"; return; }
    if (!d.anomalies || !d.anomalies.length) {
      const sf = esc(String(d.spikeFactor)), self = esc(String(d.selfFactor != null ? d.selfFactor : d.spikeFactor));
      el.innerHTML = d.assetCount < 2
        ? `<span data-safe-style='color:var(--text-muted)'>No event-rate spikes detected (only ${esc(String(d.assetCount))} asset; bucket ${esc(String(d.bucketMinutes))} min, peer ${sf}× / self ${self}×).</span>`
        : `<span data-safe-style='color:var(--text-muted)'>No event-rate spikes detected (bucket ${esc(String(d.bucketMinutes))} min, peer ${sf}× / self ${self}×).</span>`;
      return;
    }
    const TYPE_TIP = { peer: "busier than other assets in the same bucket", self: "bursting above this asset's own typical rate" };
    const rows = d.anomalies.map(a => {
      const sevColor = KC_SEV_COLOR[a.severity] || "var(--border-color)";
      const window = `${esc(a.bucketStart || "")} → ${esc(a.bucketEnd || "")}`;
      const methods = Array.isArray(a.methods) && a.methods.length ? a.methods : [a.kind || "peer"];
      const typeTip = methods.map(m => TYPE_TIP[m] || m).join("; ");
      const typeCell = methods.join(" + ");
      const baseTip = (a.kind === "self") ? "this asset's own median events per bucket" : "median events across all assets in this bucket";
      const evLink = a.eventIds && a.eventIds.length
        ? `<a href="#" class="anomaly-events" data-evids="${escAttr(a.eventIds.join(","))}" data-label="${escAttr((a.asset || "") + " · " + (a.bucketStart || ""))}" data-safe-style="font-size:11px;color:var(--accent);margin-left:6px" title="Filter the forensic timeline to exactly these ${a.eventIds.length} events">view ${a.eventIds.length} event${a.eventIds.length !== 1 ? "s" : ""}</a>`
        : "";
      // Immediate FP cascade (#12): one-click suppress the whole spike — marks every event in it false
      // positive (detection-misfire) via the batch endpoint, so a noisy/benign spike deflates at once
      // (anomalies recompute over FP-filtered events) and drops out of the baseline.
      const fpLink = a.eventIds && a.eventIds.length
        ? `<a href="#" class="anomaly-fp" data-evids="${escAttr(a.eventIds.join(","))}" data-label="${escAttr((a.asset || "") + " · " + (a.bucketStart || ""))}" data-safe-style="font-size:11px;color:var(--badge-warning-text);margin-left:8px" title="Mark all ${a.eventIds.length} events in this spike as false positive (detection-misfire) — the spike deflates and stops skewing the baseline">✗ mark spike FP</a>`
        : "";
      return `<tr>` +
        `<td><span class="sev-${esc(a.severity)}" data-safe-style="color:${sevColor};font-weight:bold">${esc(a.severity)}</span></td>` +
        `<td><strong>${esc(a.asset)}</strong>${evLink}${fpLink}</td>` +
        `<td title="${escAttr(typeTip)}">${esc(typeCell)}</td>` +
        `<td data-safe-style="color:var(--text-muted);font-size:11px">${window}</td>` +
        `<td title="events in this bucket for this asset">${esc(String(a.eventCount))}</td>` +
        `<td title="${escAttr(baseTip)}">${esc(String(a.medianCount))}</td>` +
        `<td title="eventCount ÷ baseline"><strong>${esc(String(a.ratio))}×</strong></td>` +
        `</tr>`;
    }).join("");
    const self = esc(String(d.selfFactor != null ? d.selfFactor : d.spikeFactor));
    el.innerHTML =
      `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-bottom:6px">An event-rate spike is a triage lead — a host flooding logs can be an attacker running recon, ransomware encrypting, or a noisy EDR rule. <strong>peer</strong> = busier than other assets this bucket; <strong>self</strong> = bursting above its own normal rate. Verify each against the raw timeline; suppress noise with the <em>false-positive</em> tag to drop it from the baseline. Bucket: ${esc(String(d.bucketMinutes))} min · peer ${esc(String(d.spikeFactor))}× / self ${self}×.</div>` +
      `<div class="vql-result-wrap"><table class="vql-result"><thead><tr>` +
      `<th>Severity</th><th>Asset</th><th title="peer = vs other assets this bucket; self = vs this asset's own baseline">Type</th><th>Bucket</th><th>Events</th><th>Baseline</th><th>Ratio</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  // Immediate FP cascade (#12): mark every event in an anomaly spike false positive in one batch call.
  // The anomalies panel recomputes over FP-filtered events, so the suppressed spike deflates/disappears
  // and stops skewing the baseline; the single batch re-synthesis (kicked by the route) folds it in.
  function markAnomalySpikeFalsePositive(ids, label) {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId || !ids.length) return;
    if (!confirm(`Mark all ${ids.length} event(s) in this spike (${label}) as false positive?`)) return;
    const items = ids.map(id => ({ kind: "event", ref: id, reason: "detection-misfire" }));
    fetch(`/cases/${caseId}/false-positive/batch`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ items, reason: "detection-misfire", note: `anomaly spike suppressed (${label})` }),
    }).then(() => { scheduleAnomaliesReload(); }).catch(() => {});
  }

  // The names the inline script calls by bare name. Everything else — this feature's state
  // included — stays inside the closure, which is the point of moving it.
  window.loadAnomalies = loadAnomalies;
  window.scheduleAnomaliesReload = scheduleAnomaliesReload;
  window.markAnomalySpikeFalsePositive = markAnomalySpikeFalsePositive;
})();
