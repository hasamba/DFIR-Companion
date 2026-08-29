// IOC provenance, corroboration and risk — extracted from dashboard.html (issue #415, tier 3).
//
// renderIocs is core machinery and stays in the page, so its four reads of this feature's state
// cross as questions. The direction of the safe answer INVERTS here, and it is worth being
// explicit about why, because every other crossing in #415 runs the other way.
//
// These are FILTERS. Everywhere else a stub answering falsy hides a decoration, which is the
// safe failure. Here a stub answering falsy would mean 'no filtering', so the analyst sees MORE
// rows than they asked for. That is still the safer of the two — showing un-asked-for evidence
// beats hiding asked-for evidence — but it is a lie about what is on screen unless it is said,
// so iocProvenanceFiltersActive() drives the empty-state text and the page guards each call.
//
// The sharpest edge is iocCorroborationCount(). It feeds `count >= 2` tests, and an absent
// module returning undefined makes `undefined >= 2` false — which would filter out EVERY IOC.
// Both call sites therefore default to a value that does not exclude, never to zero.
(function () {
  "use strict";

  // Split out of the "Attack Phases" banner (#415). Nothing here is Attack Phases: these are
  // the provenance chains, the per-IOC source map, the risk ranking and the three filters that
  // renderIocs applies. They shared a banner for no reason beyond where they were written, and
  // that made the block report five state escapes belonging to two unrelated features.
  //
  // renderIocs is core machinery and stays in the page, so when this is extracted the filters
  // cross as questions, not variables — and note the facade direction INVERTS here: a stub that
  // answers falsy means NO filtering, so the analyst sees more rows, not fewer. Safer than
  // hiding evidence, but it has to be said on screen rather than left silent.
  let iocSourcesById = {};
  let iocSourcesTimer = null;
  function loadIocSources(caseId) {
    fetch(`/cases/${caseId}/ioc-sources`)
      .then((r) => r.json())
      .then((m) => {
        iocSourcesById = m && typeof m === "object" ? m : {};
        if (DfirState.lastState())
          renderIocs(DfirScope.project(DfirState.lastState()).iocs || []);
      })
      .catch(() => {});
  }
  function scheduleIocSourcesReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(iocSourcesTimer);
    iocSourcesTimer = setTimeout(() => loadIocSources(caseId), 800);
  }

  // Per-IOC provenance (#): { iocId: "detection" | "telemetry" }, derived server-side. DISTINCT
  // from the threat-intel verdict badge — this is about HOW the IOC entered the case (does it appear
  // in a graded Low+ event, or only in Info telemetry), not what threat intel says about it. Powers
  // the provenance badge + the detection/telemetry filter in the IOC panel. Mirrors loadIocSources.
  let iocProvenance = {};
  let iocProvenanceTimer = null;
  // "All" (default) / "detection" / "telemetry" — client-side lens over the rendered IOC rows.
  let iocProvenanceFilter = "all";
  function loadIocProvenance(caseId) {
    fetch(`/cases/${caseId}/ioc-provenance`)
      .then((r) => r.json())
      .then((m) => {
        iocProvenance = m && typeof m === "object" ? m : {};
        if (DfirState.lastState())
          renderIocs(DfirScope.project(DfirState.lastState()).iocs || []);
      })
      .catch(() => {});
  }
  function scheduleIocProvenanceReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(iocProvenanceTimer);
    iocProvenanceTimer = setTimeout(() => loadIocProvenance(caseId), 800);
  }
  let iocProvenanceChainTimer = null;
  function scheduleIocProvenanceChainReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(iocProvenanceChainTimer);
    iocProvenanceChainTimer = setTimeout(
      () => loadIocProvenanceChains(caseId),
      800,
    );
  }
  // Provenance for an IOC — absent from the map = telemetry (safe default: recede, don't over-signal).
  function iocProvenanceOf(iocId) {
    return iocProvenance[iocId] === "detection" ? "detection" : "telemetry";
  }
  // Small provenance badge shown near the corroboration badge. detection-linked = accent (signal);
  // telemetry-only = muted grey (recedes). Kept visually separate from the verdict badge.
  function iocProvenanceBadge(iocId) {
    if (iocProvenanceOf(iocId) === "detection") {
      return ` <span class="ioc-prov-badge ioc-prov-detection" title="Detection-linked: this IOC appears in a graded (Low or higher) event — not just Info telemetry">detection-linked</span>`;
    }
    return ` <span class="ioc-prov-badge ioc-prov-telemetry" title="Telemetry-only: this IOC appears only in Info telemetry, not in any graded detection event">telemetry-only</span>`;
  }

  // Composite IOC risk (#63): { iocId: { score, factors } }, derived server-side from verdict +
  // severity + corroboration + KEV + NSRL/whitelist. Bulk-fetched per case connect like provenance.
  let iocRisk = {};
  let iocRiskTimer = null;
  // Seeded by initIocProvenance(), not here: reading localStorage at module scope runs before the
  // page is up and throws outright in a non-browser context. 0 means "no risk filter", which is
  // also the right value if the read ever fails.
  let riskIocsFilter = 0; // min risk RANK to show
  const RISK_RANK = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 };
  function loadIocRisk(caseId) {
    fetch(`/cases/${caseId}/ioc-risk`)
      .then((r) => r.json())
      .then((m) => {
        iocRisk = m && typeof m === "object" ? m : {};
        if (DfirState.lastState())
          renderIocs(DfirScope.project(DfirState.lastState()).iocs || []);
      })
      .catch(() => {});
  }
  function scheduleIocRiskReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(iocRiskTimer);
    iocRiskTimer = setTimeout(() => loadIocRisk(caseId), 800);
  }
  function iocRiskRankOf(iocId) {
    const r = iocRisk[iocId];
    return r && r.score in RISK_RANK ? RISK_RANK[r.score] : -1; // -1 = not yet scored (excluded by a tier filter)
  }
  // "indicator" (earned a signal, or a network pivot) vs "observation" (a scraped file/hash with no
  // signal), from the server's IOC-risk scoring. null until /ioc-risk has loaded for the case.
  function iocRoleOf(iocId) {
    const r = iocRisk[iocId];
    return r && r.role ? r.role : null;
  }
  // Colored risk badge with the factors as a tooltip. Benign/low recede; medium+ signal.
  function iocRiskBadge(iocId) {
    const r = iocRisk[iocId];
    if (!r || !(r.score in RISK_RANK)) return "";
    const tip = (r.factors || []).join(" · ") || r.score;
    return ` <span class="ioc-risk-badge ioc-risk-${esc(r.score)}" title="Composite risk (#63): ${escAttr(tip)}">${esc(r.score)}</span>`;
  }

  // IOC provenance CHAIN (#247): { iocId: { extraction, extractionTruncated, enrichment, findings } },
  // derived server-side. Distinct from iocProvenance above (detection-vs-telemetry classification) —
  // this is the full timestamped chain shown in the per-IOC chain panel. Loaded once per case connect
  // (same bulk-fetch shape as loadIocSources/loadIocProvenance); the panel itself only reads from it.
  let iocProvenanceChains = {};
  function loadIocProvenanceChains(caseId) {
    fetch(`/cases/${caseId}/ioc-provenance-chain`)
      .then((r) => r.json())
      .then((m) => {
        iocProvenanceChains = m && typeof m === "object" ? m : {};
      })
      .catch(() => {});
  }
  // Chip that opens the chain panel for one IOC (mirrors explainChip's button shape).
  function iocChainChip(iocId) {
    return `<button class="ioc-chain-btn" data-iocchain="${escAttr(String(iocId))}" title="Show provenance chain — extraction event(s), enrichment lookups, and citing findings">${ICON_CHAIN}</button>`;
  }
  // Renders the pre-fetched chain for one IOC into the panel. Read-only, no AI, no extra request.
  function openIocChainPanel(caseId, iocId) {
    const chain = iocProvenanceChains[iocId];
    const overlay = document.getElementById("iocChainOverlay");
    const titleEl = document.getElementById("iocChainTitle");
    const bodyEl = document.getElementById("iocChainBody");
    overlay.classList.add("open");
    overlay.dataset.iocid = iocId;
    titleEl.textContent = chain ? `${chain.type}: ${chain.value}` : iocId;
    if (!chain) {
      bodyEl.innerHTML =
        "<div data-safe-style='color:var(--text-muted)'>no provenance data for this IOC yet</div>";
      return;
    }
    // An extraction link can be real and still land on an event whose text never names the IOC
    // (#640): aggregation collapses same-shape records into ONE event and keeps the FIRST one's
    // description, and description/message are truncated before storage. Saying "linked" and then
    // showing a line that names a different address reads as a mis-attribution, so each row
    // declares what it is standing for and whether the value is actually in it.
    const mergeTag = (e) =>
      e.count > 1
        ? `<span class="iocchain-note" title="Aggregation collapsed ${escAttr(String(e.count))} same-shape records into this one timeline event and kept the first one's text. A sibling record may be the one that carried this IOC.">1 of ${esc(String(e.count))} merged records${e.endTimestamp ? " · through " + esc(e.endTimestamp) : ""}</span>`
        : "";
    const hiddenTag = (e) =>
      e.valueHidden
        ? `<span class="iocchain-warn" title="This IOC's value appears nowhere in the event record as stored — it came from a merged-away sibling record, or from text past the storage cut-off. Open the original artifact to see the record that carried it.">⚠ value not in this event's stored text</span>`
        : "";
    const extractionRows = chain.extraction.length
      ? chain.extraction
          .map(
            (e) =>
              `<div class="iocchain-row">` +
              `<span class="iocchain-time sev-${esc(e.severity)}">${esc(e.timestamp || "(undated)")}</span>` +
              `<a class="ev-jump iocchain-desc" href="${escAttr(eventDeepLink(caseId, e.eventId))}" data-evid="${escAttr(e.eventId)}" title="Jump to this event in the timeline">${esc(e.description || e.eventId)}</a>` +
              mergeTag(e) +
              hiddenTag(e) +
              (e.artifactName
                ? `<span class="iocchain-tag">${esc(e.artifactName)}</span>`
                : e.sources && e.sources.length
                  ? `<span class="iocchain-tag">${esc(e.sources.join(", "))}</span>`
                  : "") +
              `</div>`,
          )
          .join("")
      : "<div data-safe-style='color:var(--text-muted);font-size:12px'>no matching event found</div>";
    const truncNote =
      chain.extractionTruncated > 0
        ? `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-top:3px">+${esc(chain.extractionTruncated)} more matching event(s) not shown</div>`
        : "";
    const enrichRows = chain.enrichment.length
      ? chain.enrichment
          .map(
            (en) =>
              `<div class="iocchain-row"><span class="iocchain-time">${esc(en.fetchedAt)}</span>` +
              `<span class="iocchain-desc">${esc(en.source)}: ${esc(en.verdict)}${en.score ? " (" + esc(en.score) + ")" : ""}</span>` +
              (en.link
                ? `<a class="iocchain-tag" href="${escAttr(en.link)}" target="_blank" rel="noopener" data-safe-style="color:var(--accent)">↗</a>`
                : "") +
              `</div>`,
          )
          .join("")
      : "<div data-safe-style='color:var(--text-muted);font-size:12px'>no enrichment lookups recorded</div>";
    const findingRows = chain.findings.length
      ? chain.findings
          .map(
            (f) =>
              `<div class="iocchain-row"><span class="iocchain-time">${esc(f.firstSeen)}</span>` +
              `<a class="finding-jump iocchain-desc" data-fid="${escAttr(f.findingId)}" title="Jump to this finding">${esc(f.title)}</a>` +
              `<span class="iocchain-tag">${esc(f.severity)}, ${esc(f.status)}</span></div>`,
          )
          .join("")
      : "<div data-safe-style='color:var(--text-muted);font-size:12px'>no findings cite this IOC yet</div>";
    const extractionCaveat = chain.extractionAuthoritative
      ? `<small data-safe-style="color:var(--accent)">(linked — a real source-event reference, not a guess)</small>`
      : `<small data-safe-style="color:var(--text-muted)">(approximate — matched by value, not a stored link)</small>`;
    // Shown once under the rows when any of them carries a caveat, so the analyst reads WHY before
    // concluding the tool attributed the value to the wrong record.
    const gapNote = chain.extraction.some((e) => e.valueHidden || e.count > 1)
      ? `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-top:3px">A timeline event can stand for many collapsed records and shows the first one's text; long records are also cut short when stored. Open the source artifact for the exact record.</div>`
      : "";
    bodyEl.innerHTML =
      `<div class="explain-section"><strong>Extraction — event(s) this IOC was seen in ${extractionCaveat}</strong>${extractionRows}${truncNote}${gapNote}</div>` +
      `<div class="explain-section"><strong>Enrichment — threat-intel lookups</strong>${enrichRows}</div>` +
      `<div class="explain-section"><strong>Findings citing this IOC</strong>${findingRows}</div>` +
      `<div data-safe-style="color:var(--text-muted);font-size:11px;margin-top:6px">Playbook references aren't tracked yet — playbook tasks don't carry IOC links.</div>`;
  }

  // Collapsible "Evidence" disclosure under a finding (derived client-side, no extra request):
  // evidence (screenshot artifacts), Supporting events (the forensic events that back it — built in
  // render() from each event's relatedFindingIds, click to jump to the timeline row), and Supporting
  // IOCs (the finding's own related IOCs plus any IOC value referenced by a backing event). Returns
  // "" when there's nothing to show, so a bare finding gets no empty toggle.
  // Numbered, clickable citation footnotes for the forensic events an AI response names as its
  // supporting evidence (issue #222). Reused by Findings, Ask-the-case, and Explain Event so every
  // AI-cited response looks and behaves the same way; clicking a number jumps to that timeline row
  // (reuses the existing .ev-jump / jumpToEvent delegated-click mechanism — no new wiring needed).
  function citeEvents(ids) {
    const list = Array.from(new Set((ids || []).map(String).filter(Boolean)));
    if (!list.length) return "";
    const caseId = document.getElementById("caseId").value.trim();
    return list
      .map(
        (id, i) =>
          `<a class="ev-jump cite-badge" href="${escAttr(eventDeepLink(caseId, id))}" data-evid="${escAttr(id)}" title="Jump to event ${escAttr(id)} in the timeline">[${i + 1}]</a>`,
      )
      .join(" ");
  }
  // Builds the inner rows for a finding's evidence panel: confidence reasoning, supporting
  // IOCs, evidence files, and the cited-event timeline (each cited event's own timestamp +
  // description, not just a bare "[1][2][3]" footnote list — the footnote still appears, but
  // as a jump link at the end of that event's own line). citeIds is the finding's own list of
  // cited event ids (may reference events outside suppEventsByFinding's back-link set, so this
  // looks each one up in DfirState.lastFt() directly rather than only the passed-in `events`).
  function findingEvidenceDetails(
    f,
    caseId,
    screenshots,
    events,
    iocs,
    citeIds,
  ) {
    const rows = [];
    if (f.confidenceReason) {
      rows.push(
        `<div class="fev-row"><span class="fev-k">Confidence</span><span class="fev-v">${f.confidence !== undefined ? esc(String(f.confidence)) + "% — " : ""}${esc(f.confidenceReason)}</span></div>`,
      );
    }
    // Grounding/corroboration (investigation-guidance #6): flag an ungrounded finding prominently, else
    // show the tools/hosts/intel rollup so a single-source claim is visibly distinguishable from a
    // multi-tool one.
    if (f.ungrounded) {
      rows.push(
        `<div class="fev-row"><span class="fev-k">Grounding</span><span class="fev-v" data-safe-style="color:var(--badge-danger-text);font-weight:600">⚠️ no cited evidence — treat as a hypothesis, not a fact (confidence capped)</span></div>`,
      );
    } else if (f.corroboration) {
      const c = f.corroboration;
      const parts = [
        `${c.distinctTools} tool${c.distinctTools === 1 ? "" : "s"}`,
        `${c.distinctHosts} host${c.distinctHosts === 1 ? "" : "s"}`,
      ];
      if (c.intelSources > 0) parts.push("intel ✓");
      if (c.graphLinked) parts.push("graph-linked");
      // Issue #61 provenance signals, shown as badges with plain-English tooltips: KEV-linked
      // (actively exploited) and tool-confirmed (a tool adjudicated it) are positive; unconfirmed-lead
      // (raw collection, no verdict) is a caution. Titles are static, safe HTML — not user data.
      const corroborated =
        c.distinctTools >= 2 ||
        c.intelSources > 0 ||
        c.graphLinked ||
        c.kevLinked;
      const huntCaution =
        c.huntArtifactOnly && c.intelSources === 0 && !c.kevLinked;
      const badges = [];
      if (c.kevLinked)
        badges.push(
          `<span title="A CVE in this finding is on CISA's Known Exploited Vulnerabilities (KEV) list — confirmed exploited in the wild. Counts as independent corroboration.">🎯 KEV</span>`,
        );
      if (c.verdictFirst)
        badges.push(
          `<span title="Backed by at least one tool-adjudicated detection (a graded alert), not just raw collected data.">⚑ tool-confirmed</span>`,
        );
      if (huntCaution)
        badges.push(
          `<span title="Rests only on raw collected artifacts that no tool flagged — an unconfirmed lead to triage, not a confirmed detection. Confidence capped at 55.">🐇 unconfirmed lead</span>`,
        );
      const suffix = !huntCaution && !corroborated ? " — uncorroborated" : "";
      const warn = huntCaution || !corroborated;
      const badgeHtml = badges.length ? " / " + badges.join(" / ") : "";
      rows.push(
        `<div class="fev-row"><span class="fev-k">Corroboration</span><span class="fev-v"${warn ? ' data-safe-style="color:var(--badge-warning-text)"' : ""}>${esc(parts.join(" / "))}${badgeHtml}${esc(suffix)}</span></div>`,
      );
    }
    const byVal = new Map(
      (iocs || []).map((i) => [String(i.value).trim().toLowerCase(), i.value]),
    );
    const vals = new Set();
    for (const id of f.relatedIocs || []) {
      const ioc = (iocs || []).find((x) => x.id === id);
      if (ioc) vals.add(ioc.value);
    }
    for (const e of events)
      for (const v of [e.sha256, e.md5, e.srcIp, e.dstIp, e.path]) {
        if (!v) continue;
        const hit = byVal.get(String(v).trim().toLowerCase());
        if (hit) vals.add(hit);
      }
    if (vals.size)
      rows.push(
        `<div class="fev-row"><span class="fev-k">Supporting IOCs</span><span class="fev-v fev-iocs">${[...vals].map((v) => esc(v)).join(", ")}</span></div>`,
      );
    const evFiles = Array.from(new Set((screenshots || []).filter(Boolean)));
    if (caseId && evFiles.length) {
      const links = evFiles
        .map(
          (fn) =>
            `<a href="/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(fn)}" target="_blank" rel="noopener" class="ev-jump" title="Open evidence: ${escAttr(fn)}">${esc(fn)}</a>`,
        )
        .join(" · ");
      rows.push(
        `<div class="fev-row"><span class="fev-k">Evidence files</span><span class="fev-v">${links}</span></div>`,
      );
    }
    const ids = Array.from(
      new Set((citeIds || []).map(String).filter(Boolean)),
    );
    if (ids.length) {
      const byId = new Map(
        (DfirState.lastFt() || []).map((e) => [String(e.id), e]),
      );
      const items = ids
        .map((id, i) => {
          const e = byId.get(id);
          const ts = e
            ? esc(e.timestamp || "(undated)")
            : "(not in current scope)";
          const desc = e
            ? esc(
                String(e.description || "")
                  .replace(
                    /\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i,
                    "",
                  )
                  .replace(/\s*\[more\]$/, ""),
              )
            : esc(id);
          return (
            `<div class="fev-tl-item"><span class="fev-tl-time">${ts}</span><span class="fev-tl-desc">${desc}</span>` +
            `<a class="ev-jump fev-tl-cite" href="${escAttr(eventDeepLink(caseId, id))}" data-evid="${escAttr(id)}" title="Jump to this event in the timeline">[${i + 1}]</a></div>`
          );
        })
        .join("");
      rows.push(
        `<div class="fev-row"><span class="fev-k">Cited events</span><span class="fev-v"><div class="fev-timeline">${items}</div></span></div>`,
      );
    }
    return rows.join("");
  }
  // "⊕ N" corroboration badge for an IOC seen by 2+ tools (mirrors the forensic-timeline badge).
  function iocCorroBadge(iocId) {
    const src = iocSourcesById[iocId];
    if (!src || src.length < 2) return "";
    return ` <span title="Corroborated by ${src.length} sources: ${escAttr(src.join(", "))}" data-safe-style="background:var(--success-bg);color:var(--sev-low);border:1px solid var(--success-border);border-radius:4px;padding:0 5px;font-size:10px;font-weight:bold">⊕ ${esc(src.length)}</span>`;
  }

  // Beacons, evidence gaps, playbook match and ATT&CK mitigations moved to
  // js/dashboard-derived-panels.js (#415 tier 3). No initializer to guard, so without this the
  // file going missing would be SILENT: the facade stubs their names to no-ops — which is what
  // keeps the refresh fan-out alive — and a no-op panel looks exactly like a panel with nothing
  // to show. DfirFacade.stubbed records which names the facade had to fill in, so asking it is
  // how a module with no entry point of its own still gets to say it is gone.

  // Timeline Gaps (#83) moved to js/dashboard-timeline-gaps.js (#415 tier 3). No initializer.
  // Memory Next Steps (#101) moved to js/dashboard-memory-next-steps.js (#415 tier 3).

  // ---- what renderIocs asks ----
  function iocCorroborationCount(iocId) {
    return (iocSourcesById[iocId] || []).length;
  }
  // Provenance + risk, applied together. Returns the list unchanged when neither is engaged.
  function applyIocProvenanceFilters(list) {
    let out = list;
    if (iocProvenanceFilter !== "all")
      out = out.filter((i) => iocProvenanceOf(i.id) === iocProvenanceFilter);
    if (riskIocsFilter > 0)
      out = out.filter((i) => iocRiskRankOf(i.id) >= riskIocsFilter);
    return out;
  }
  function iocProvenanceFiltersActive() {
    return iocProvenanceFilter !== "all" || riskIocsFilter > 0;
  }
  function iocChainFor(iocId) {
    return iocProvenanceChains[iocId];
  }

  // The persisted risk-filter choice, and the facade probe below.
  function initIocProvenance() {
    try {
      riskIocsFilter =
        parseInt(localStorage.getItem("dfir.risk.iocs") || "0", 10) || 0;
    } catch {}
    // THE PROBE HAS TO RUN HERE, not at module load, which is where it used to sit. The facade is
    // ten module tags further down the page, so `window.DfirFacade` was always undefined then, the
    // guard was always false, and the notice could never appear -- a feature reporting its own
    // absence, silently absent itself. The page calls this initializer after every module, which is
    // the first moment the answer exists. Found by the load-order gate, #482.
    if (window.DfirFacade && window.DfirFacade.filled.includes("loadBeacons")) {
      dfirFeatureUnavailable(
        "Beacons, evidence gaps, playbook match and mitigations",
      );
    }
  }

  // ---- what the controls set ----
  // The provenance buttons live in the page's delegated click block and the risk <select> in
  // dashboard-search-scope.js. Both are dispatch plumbing; the state is this feature's.
  function setIocProvenanceFilter(value) {
    iocProvenanceFilter = value || "all";
  }
  function setRiskIocsFilter(value) {
    const v = Number(value);
    riskIocsFilter = v >= 2 && v <= 4 ? v : 0;
    try {
      localStorage.setItem("dfir.risk.iocs", String(riskIocsFilter));
    } catch {}
    return riskIocsFilter;
  }
  function riskIocsFilterValue() {
    return riskIocsFilter;
  }

  window.initIocProvenance = initIocProvenance;
  window.iocCorroborationCount = iocCorroborationCount;
  window.applyIocProvenanceFilters = applyIocProvenanceFilters;
  window.iocProvenanceFiltersActive = iocProvenanceFiltersActive;
  window.iocChainFor = iocChainFor;
  window.setIocProvenanceFilter = setIocProvenanceFilter;
  window.setRiskIocsFilter = setRiskIocsFilter;
  window.riskIocsFilterValue = riskIocsFilterValue;
  window.loadIocSources = loadIocSources;
  window.scheduleIocSourcesReload = scheduleIocSourcesReload;
  window.loadIocProvenance = loadIocProvenance;
  window.scheduleIocProvenanceReload = scheduleIocProvenanceReload;
  window.loadIocProvenanceChains = loadIocProvenanceChains;
  window.scheduleIocProvenanceChainReload = scheduleIocProvenanceChainReload;
  window.loadIocRisk = loadIocRisk;
  window.scheduleIocRiskReload = scheduleIocRiskReload;
  window.iocProvenanceOf = iocProvenanceOf;
  window.iocProvenanceBadge = iocProvenanceBadge;
  window.iocRiskRankOf = iocRiskRankOf;
  window.iocRoleOf = iocRoleOf;
  window.iocRiskBadge = iocRiskBadge;
  window.iocCorroBadge = iocCorroBadge;
  window.iocChainChip = iocChainChip;
  window.openIocChainPanel = openIocChainPanel;
  window.findingEvidenceDetails = findingEvidenceDetails;
  window.citeEvents = citeEvents;
})();
