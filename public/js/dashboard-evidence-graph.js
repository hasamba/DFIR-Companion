// Evidence Chain graph (causal: process → network → file, plus reconstructed lateral paths) —
// extracted from dashboard.html (issue #415, tier 3).
//
// Two ranges, not one. Everything the seven ev* escapes were read from — the type toggles, the
// min-severity select, the node-colour radios, the section-expand relayout and both #evPathsList
// handlers — sat in the page's big load-time block, 4,000 lines from the code it belongs to.
// Ownership follows use: those six statements are this feature's own wiring, so they are its
// initializer. The boundary is exact — the very next statement wires saveReportMeta, which is a
// different feature, and sweeping it in is how a neighbour gets silently broken.
//
// What genuinely stays in the page is one line of the refresh fan-out: `if (evGraphData)
// loadEvidenceGraph(caseId)`. It asks a question about this feature's state, so it asks through
// hasEvidenceGraph() rather than reaching for the variable.
(function () {
  "use strict";

  let evGraphData = null; // { nodes, edges }
  let evPathsData = null; // ordered lateral-movement chains (#92)
  let evGraphTimer = null;
  // Seeded by initEvidenceGraph(), NOT here. This was `new Set([...document.querySelectorAll(
  // ".ev-type-toggle")].filter(cb => cb.checked)...)` in the inline script, where it ran after the
  // markup. In a <head> module it runs before, so the query matches nothing and every node type is
  // silently off — a graph that draws an empty canvas and reports no error.
  const evTypesEnabled = new Set();
  const evMinSevRank = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  let evMinSev = "Info"; // show nodes at this severity or above; "Info" = show all

  // Kill-chain overlay (#93): recolour nodes by their ATT&CK tactic (the phase the server tagged
  // each node with) instead of by severity. Ordered as the kill chain; the palette runs cool
  // (initial access) → hot (impact) so the graph reads as a progression. A node with no tactic
  // degrades to the neutral colour.
  let evColorMode = "severity"; // "severity" | "killchain"
  const EV_KC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
  ];
  const EV_KC_COLOR = {
    "Initial Access": "#6aa9ff",
    Execution: "#38bdf8",
    Persistence: "#2dd4bf",
    "Privilege Escalation": "#4ade80",
    "Defense Evasion": "#a3e635",
    "Credential Access": "#facc15",
    Discovery: "#fbbf24",
    "Lateral Movement": "#fb923c",
    Collection: "#f472b6",
    "Command and Control": "#f87171",
    Exfiltration: "#ef4444",
    Impact: "#b91c1c",
  };
  const EV_KC_NO_TACTIC = "#6b7585"; // node with no mapped tactic — degrade cleanly
  const evTacticColor = (tac) => (tac && EV_KC_COLOR[tac]) || EV_KC_NO_TACTIC;

  function loadEvidenceGraph(caseId) {
    const gv = evEnsureGV();
    if (gv) gv.loadView(); // restore this case's persisted view state (layout/dim/edge-style)
    fetch(`/cases/${caseId}/evidence-graph${DfirTimelineView.timeQuery()}`)
      .then((r) => r.json())
      .then((g) => {
        evGraphData = g;
        renderEvidenceGraph();
      })
      .catch(() => {});
    loadLateralPaths(caseId);
  }
  // Lateral chains, optionally including the ones the analyst dismissed (review/undo view).
  function loadLateralPaths(caseId) {
    const q = DfirTimelineView.timeQuery();
    const url = `/cases/${caseId}/lateral-paths${q}${evPathsShowDismissed ? (q ? "&" : "?") + "includeDismissed=1" : ""}`;
    return fetch(url)
      .then((r) => r.json())
      .then((paths) => {
        evPathsData = paths;
        renderEvidencePaths();
      })
      .catch(() => {});
  }
  // State changes (imports / synthesis) re-derive the graph — debounced.
  function scheduleEvidenceGraphReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(evGraphTimer);
    evGraphTimer = setTimeout(() => loadEvidenceGraph(caseId), 800);
  }

  // The colour a node is drawn in under the current mode: by severity (default) or by kill-chain tactic.
  function evNodeColor(n) {
    return evColorMode === "killchain"
      ? evTacticColor(n.tactic)
      : evSevColor(n.maxSeverity);
  }
  let evGV = null;

  function evBuildElements(view) {
    // ran_on rides with the Process-trees toggle — it hangs each tree off its host.
    const edges0 = evGraphData.edges.filter(
      (e) =>
        evTypesEnabled.has(e.type) ||
        (e.type === "ran_on" && evTypesEnabled.has("spawned")),
    );
    const keep = new Set(edges0.flatMap((e) => [e.source, e.target]));
    const minRank = evMinSevRank[evMinSev] ?? 4;
    const nodes = evGraphData.nodes.filter(
      (n) => keep.has(n.id) && (evMinSevRank[n.maxSeverity] ?? 4) <= minRank,
    );
    const visibleIds = new Set(nodes.map((n) => n.id));
    const edges = edges0.filter(
      (e) => visibleIds.has(e.source) && visibleIds.has(e.target),
    );
    const els = [];
    for (const n of nodes) {
      const titleSuffix = n.asset
        ? " on " + n.asset
        : n.ip
          ? " (" + n.ip + ")"
          : "";
      els.push({
        data: {
          id: n.id,
          name: truncate(n.label, 22),
          full: n.label + titleSuffix,
          kind: n.kind,
          sev: n.maxSeverity,
          tactic: n.tactic || null,
          glyph: glyphDataUri(evNodeGlyph(n, 11, 11, evNodeColor(n))),
        },
      });
    }
    for (const e of edges) {
      els.push({
        data: {
          id: `ev:${e.source}|${e.target}|${e.type}`,
          source: e.source,
          target: e.target,
          etype: e.type,
          conf: e.confidence,
          basis: e.basis,
        },
      });
    }
    return els;
  }

  const EV_STYLE = [
    {
      selector: "node",
      style: {
        "background-image": "data(glyph)",
        "background-color": "#0f1115",
        "background-opacity": 0,
        "background-fit": "none",
        "background-clip": "none",
        width: 26,
        height: 26,
        label: "data(name)",
        color: "#cbd3df",
        "font-size": "10px",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 3,
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.6,
        "line-color": "#7f8aa0",
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "target-arrow-color": "#7f8aa0",
        "arrow-scale": 0.9,
        "line-style": "dashed",
      },
    },
    // causal high-confidence: solid orange
    {
      selector: 'edge[etype = "causal"][conf = "high"]',
      style: {
        "line-style": "solid",
        "line-color": "#ff8a5c",
        "target-arrow-color": "#ff8a5c",
      },
    },
    {
      selector: 'edge[etype = "ran_on"]',
      style: {
        "line-style": "solid",
        "line-color": "#52617a",
        "target-arrow-color": "#52617a",
        width: 1.1,
        opacity: 0.7,
      },
    },
    {
      selector: 'edge[etype = "file_lineage"]',
      style: {
        "line-style": "solid",
        "line-color": "#4ade80",
        "target-arrow-color": "#4ade80",
      },
    },
    {
      selector: 'edge[etype = "network_flow"]',
      style: {
        "line-style": "solid",
        "line-color": "#38bdf8",
        "target-arrow-color": "#38bdf8",
      },
    },
    { selector: ".gv-dim", style: { opacity: 0.1 } },
  ];

  function evShowNodePanel(node) {
    const p = document.getElementById("evSidePanel");
    p.replaceChildren();
    const title = lgEl("div");
    title.append(
      lgEl("b", null, node.data("full")),
      lgEl("span", "ev-sub", " " + node.data("sev")),
    );
    p.append(title);
    const tactic = node.data("tactic");
    if (tactic) {
      const tacRow = lgEl("div", "ev-sub");
      const sw = lgEl("span");
      sw.style.cssText = `display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle;background:${evTacticColor(tactic)}`;
      tacRow.append(sw, document.createTextNode("kill-chain phase: " + tactic));
      p.append(tacRow);
    }
    const close = lgEl("button", "lg-close", "✕ Close");
    close.type = "button";
    close.onclick = () => {
      p.style.display = "none";
      if (evGV) evGV.dimExcept(null);
    };
    p.append(close);
    p.style.display = "block";
  }
  function evShowEdgePanel(edge) {
    const p = document.getElementById("evSidePanel");
    const d = edge.data();
    p.replaceChildren();
    const title = lgEl("div");
    title.append(lgEl("b", null, d.etype));
    const sub = lgEl(
      "div",
      "ev-sub",
      d.basis + (d.etype === "ran_on" ? "" : " — " + d.conf + " confidence"),
    );
    const close = lgEl("button", "lg-close", "✕ Close");
    close.type = "button";
    close.onclick = () => {
      p.style.display = "none";
      if (evGV) evGV.dimExcept(null);
    };
    p.append(title, sub, close);
    p.style.display = "block";
  }

  function evEnsureGV() {
    if (evGV) return evGV;
    if (!window.DfirGraphView) return null;
    evGV = window.DfirGraphView.createGraphView({
      graphId: "evidence",
      container: document.getElementById("evGraph"),
      wrap: document.getElementById("evGraphWrap"),
      caseIdEl: document.getElementById("caseId"),
      exportName: "evidence-graph.png",
      defaults: { layout: "dagre", edgeStyle: "bezier", dim: 85 },
      style: EV_STYLE,
      buildElements: evBuildElements,
      onNodeTap: (node) => evShowNodePanel(node),
      onEdgeTap: (edge) => evShowEdgePanel(edge),
      onBackgroundTap: () => {
        document.getElementById("evSidePanel").style.display = "none";
      },
      onRefresh: () => {
        const cId = document.getElementById("caseId").value.trim();
        if (cId) loadEvidenceGraph(cId);
      },
      controls: {
        layoutRadios: document.querySelectorAll('input[name="evLayoutRadio"]'),
        edgeStyleRadios: document.querySelectorAll('input[name="evEdgeStyle"]'),
        dimSlider: document.getElementById("evDim"),
        filterInput: document.getElementById("evFilter"),
        fitBtn: document.getElementById("evFit"),
        fullscreenBtn: document.getElementById("evFullscreenBtn"),
        exportBtn: document.getElementById("evExport"),
        refreshBtn: document.getElementById("evRefresh"),
        optionsBtn: document.getElementById("evOptions"),
        optionsPanel: document.getElementById("evOptionsPanel"),
        toggles: [], // ev-type toggles + min-sev are wired separately (Set / select, not a view flag)
      },
    });
    return evGV;
  }

  function renderEvidenceGraph() {
    const el = document.getElementById("evGraph");
    if (!evGraphData || !evGraphData.edges || !evGraphData.edges.length) {
      el.innerHTML =
        "<div data-safe-style='padding:16px;color:var(--text-muted)'>No causal chains yet — import process-creation events (Sysmon EID 1, THOR, Velociraptor, Cyber Triage, Volatility/Rekall memory) or evidence spanning multiple hosts, then Synthesize.</div>";
      if (evGV) evGV.destroy();
      return;
    }
    const gv = evEnsureGV();
    if (!gv) {
      el.textContent =
        "Graph library not loaded — restart the companion server.";
      return;
    }
    const els = evBuildElements(gv.view);
    if (!els.some((x) => x.data.source)) {
      el.innerHTML =
        "<div data-safe-style='padding:16px;color:var(--text-muted)'>No links match the current type / severity filters.</div>";
      if (evGV) evGV.destroy();
      return;
    }
    renderEvKcLegend();
    gv.render();
  }

  // Lateral-movement PATHS (#92): the ordered entry→pivot→target chains the server reconstructs
  // from lateral_move + ran_on evidence by real timestamp (buildLateralPaths), listed alongside
  // the pairwise evidence graph. "Highlight" turns on the lateral_move layer (off by default,
  // since it's usually the noisiest) and dims everything except this chain's hosts.
  // Show analyst-dismissed chains too (the review/undo view). Off by default: a dismissed chain
  // is one the analyst has already rejected, so it stays out of the way until asked for.
  let evPathsShowDismissed = false;
  const evPathBtnStyle =
    "background:none;border:1px solid var(--text-faint);border-radius:3px;cursor:pointer;padding:0 5px;color:var(--text-primary);font-size:10px";

  function renderEvidencePaths() {
    const el = document.getElementById("evPathsList");
    const toggle = evPathsShowDismissed
      ? `<button type="button" id="evPathsHideDismissed" data-safe-style="${evPathBtnStyle}">Hide dismissed</button>`
      : `<button type="button" id="evPathsShowDismissed" data-safe-style="${evPathBtnStyle}">Show dismissed</button>`;
    if (!evPathsData || !evPathsData.length) {
      el.innerHTML =
        "<div data-safe-style='padding:8px 0;color:var(--text-muted)'>No multi-hop lateral chains reconstructed yet. " +
        toggle +
        "</div>";
      return;
    }
    const confClass = (c) =>
      c === "high"
        ? "ev-leg-high"
        : c === "medium"
          ? "ev-leg-med"
          : "ev-leg-ran";
    el.innerHTML =
      evPathsData
        .map((p, i) => {
          const route = p.hostIds
            .map((id) =>
              esc(
                (evGraphData?.nodes || []).find((n) => n.id === id)?.label ||
                  id,
              ),
            )
            .join(" → ");
          // WHO/WHAT actually moved — the route alone doesn't say. Read from the hop's structured
          // `actor` field (never parsed out of `basis`), de-duplicated across the chain.
          const actors = [
            ...new Set((p.hops || []).map((h) => h.actor).filter(Boolean)),
          ];
          const via = actors.length
            ? ` <span class="ev-sub">via <b>${actors.map(esc).join("</b>, <b>")}</b></span>`
            : "";
          // A dismissed row is shown struck-through and dimmed, with Restore in place of Dismiss.
          const action = p.dismissed
            ? `<button type="button" class="ev-path-restore" data-path-idx="${i}" data-safe-style="${evPathBtnStyle}">Restore</button>`
            : `<button type="button" class="ev-path-dismiss" data-path-idx="${i}" data-safe-style="${evPathBtnStyle}" title="Reject this chain as a wrong conclusion. The underlying evidence stays in the case.">Dismiss</button>`;
          return (
            `<div class="ev-path-row" data-safe-style="margin-bottom:4px${p.dismissed ? ";opacity:.55" : ""}">` +
            `<span class="ev-leg-line ${confClass(p.confidence)}"></span>` +
            `<b${p.dismissed ? " data-safe-style='text-decoration:line-through'" : ""}>${route}</b>${via} <span class="ev-sub">${esc(p.confidence)} confidence, ${p.hops.length} hop(s)` +
            (p.startTime ? `, ${esc(p.startTime)} → ${esc(p.endTime)}` : "") +
            (p.dismissed
              ? ` — dismissed${p.dismissalNote ? ": " + esc(p.dismissalNote) : ""}`
              : "") +
            `</span> ` +
            `<button type="button" class="ev-path-highlight" data-path-idx="${i}" data-safe-style="${evPathBtnStyle}">Highlight</button> ` +
            action +
            `</div>`
          );
        })
        .join("") + `<div data-safe-style="margin-top:6px">${toggle}</div>`;
  }

  // Kill-chain legend (#93): swatches for the tactics that actually appear in the current graph,
  // in kill-chain order, plus a "no phase" entry when some node maps to no tactic. Shown only in
  // kill-chain colour mode. Built from the raw graph so it reflects every derived phase.
  function renderEvKcLegend() {
    const group = document.getElementById("evKcLegendGroup");
    const legend = document.getElementById("evKcLegend");
    if (!group || !legend) return;
    if (evColorMode !== "killchain") {
      group.style.display = "none";
      return;
    }
    const present = new Set(
      (evGraphData?.nodes || []).map((n) => n.tactic).filter(Boolean),
    );
    const anyMissing = (evGraphData?.nodes || []).some((n) => !n.tactic);
    const items = EV_KC_ORDER.filter((t) => present.has(t)).map((t) => ({
      label: t,
      color: EV_KC_COLOR[t],
    }));
    if (anyMissing) items.push({ label: "no phase", color: EV_KC_NO_TACTIC });
    legend.replaceChildren();
    for (const it of items) {
      const wrap = lgEl("span", "ev-leg-item");
      const sw = lgEl("span", "ev-leg-dot");
      sw.style.background = it.color;
      wrap.append(sw, document.createTextNode(it.label));
      legend.append(wrap);
    }
    group.style.display = items.length ? "" : "none";
  }

  // True once a graph has been loaded for the current case — the refresh fan-out's question.
  function hasEvidenceGraph() {
    return !!evGraphData;
  }

  // The controls. These bind to markup, so they run at load, not on module evaluation.
  function initEvidenceGraph() {
    // Which layers start on is a property of the markup's checked state, so read it here.
    for (const cb of document.querySelectorAll(".ev-type-toggle")) {
      if (cb.checked) evTypesEnabled.add(cb.value);
    }
    // Evidence Chain graph controls (mirror the asset-graph chrome).
    document.querySelectorAll(".ev-type-toggle").forEach((cb) =>
      cb.addEventListener("change", () => {
        if (cb.checked) evTypesEnabled.add(cb.value);
        else evTypesEnabled.delete(cb.value);
        renderEvidenceGraph();
      }),
    );
    document.getElementById("evMinSev").addEventListener("change", (e) => {
      evMinSev = e.target.value;
      renderEvidenceGraph();
    });
    document.querySelectorAll('input[name="evColorMode"]').forEach((r) =>
      r.addEventListener("change", (e) => {
        if (!e.target.checked) return;
        evColorMode = e.target.value;
        renderEvidenceGraph();
      }),
    );
    document.querySelector("#sec-evidence h2").addEventListener("click", () => {
      setTimeout(() => {
        if (evGV) evGV.onExpand();
      }, 0);
    });
    // Dismiss / restore a reconstructed chain. Dismissing rejects the CONCLUSION ("the attacker did
    // not pivot A → B → C"); it does NOT mark the underlying events as false positives, so the
    // evidence stays in the timeline and every other view.
    document
      .getElementById("evPathsList")
      .addEventListener("click", async (e) => {
        const caseId = document.getElementById("caseId").value.trim();
        if (
          e.target.id === "evPathsShowDismissed" ||
          e.target.id === "evPathsHideDismissed"
        ) {
          evPathsShowDismissed = e.target.id === "evPathsShowDismissed";
          if (caseId) await loadLateralPaths(caseId);
          return;
        }
        const dismissBtn = e.target.closest(".ev-path-dismiss");
        if (dismissBtn && evPathsData && caseId) {
          const path = evPathsData[Number(dismissBtn.dataset.pathIdx)];
          if (!path) return;
          const note = prompt("Why is this chain wrong? (optional)") ?? "";
          const res = await fetch(`/cases/${caseId}/lateral-path-dismissals`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostIds: path.hostIds, note }),
          }).catch(() => null);
          if (res && res.ok) await loadLateralPaths(caseId);
          return;
        }
        const restoreBtn = e.target.closest(".ev-path-restore");
        if (restoreBtn && evPathsData && caseId) {
          const path = evPathsData[Number(restoreBtn.dataset.pathIdx)];
          if (!path) return;
          const key = path.hostIds
            .map((h) => String(h).trim().toLowerCase())
            .join(">");
          const res = await fetch(
            `/cases/${caseId}/lateral-path-dismissals/${encodeURIComponent(key)}`,
            { method: "DELETE" },
          ).catch(() => null);
          if (res && res.ok) await loadLateralPaths(caseId);
          return;
        }
      });
    // Highlight a reconstructed lateral-movement path (#92) in the evidence graph: switch on the
    // lateral_move layer (off by default) if needed, re-render, then dim everything except this
    // chain's hosts and their immediate neighborhood.
    document.getElementById("evPathsList").addEventListener("click", (e) => {
      const btn = e.target.closest(".ev-path-highlight");
      if (!btn || !evPathsData) return;
      const path = evPathsData[Number(btn.dataset.pathIdx)];
      if (!path) return;
      if (!evTypesEnabled.has("lateral_move")) {
        evTypesEnabled.add("lateral_move");
        const cb = document.querySelector(
          '.ev-type-toggle[value="lateral_move"]',
        );
        if (cb) cb.checked = true;
        renderEvidenceGraph();
      }
      const gv = evEnsureGV();
      if (!gv || !gv.cy) return;
      let coll = gv.cy.collection();
      for (const id of path.hostIds)
        coll = coll.union(gv.cy.getElementById(id));
      gv.dimExcept(coll);
    });
  }

  window.loadEvidenceGraph = loadEvidenceGraph;
  window.scheduleEvidenceGraphReload = scheduleEvidenceGraphReload;
  window.hasEvidenceGraph = hasEvidenceGraph;
  window.initEvidenceGraph = initEvidenceGraph;
})();
