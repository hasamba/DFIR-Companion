// Login Graph (cytoscape) — who authenticated where — extracted from dashboard.html
// (issue #415, tier 3).
//
// The banner was split first. It held TWO graph features: this one and the asset↔IoC graph, whose
// renderAssetList/assetEnsureGV are used by the separate "Compromised assets" section that
// follows. Moving the banner wholesale would have taken one feature's state away from another,
// which is why the split is its own step — same as the Kill Chain and Attack Phases splits.
//
// lgGV, the one escape, was read by a single statement in the page's wiring block: the
// #sec-login-graph h2 expand handler that relayouts a graph rendered into a zero-size container.
// That is this feature's own control, so it is the initializer. Thirteenth time in this PR that a
// handler sat in a delegated block far from the state it touches.
//
// lgEl is published because the asset graph next door uses it — a shared DOM helper, not state.
(function () {
  "use strict";

  let lgData = null; // last /login-graph payload
  let lgTimer = null; // debounced reload
  function loadLoginGraph(caseId) {
    const gv = lgEnsureGV();
    if (gv) gv.loadView();
    fetch(`/cases/${encodeURIComponent(caseId)}/login-graph`)
      .then((r) => r.json())
      .then((g) => {
        lgData = g;
        renderLoginGraph();
      })
      .catch(() => {});
  }
  function scheduleLoginGraphReload(caseId) {
    clearTimeout(lgTimer);
    lgTimer = setTimeout(() => loadLoginGraph(caseId), 800);
  }

  // The shared-module instance for the Login Graph (created once, lazily, after DOM is ready).
  let lgGV = null;

  // Build cytoscape elements from lgData + the module's view (data toggles live in view).
  function lgBuildElements(view) {
    const edges = (lgData.edges || []).filter(
      (e) => view.showFailed || e.outcome !== "failed",
    );
    const nodeById = new Map((lgData.nodes || []).map((n) => [n.id, n]));
    const keptEdges = view.hideNoise
      ? edges.filter(
          (e) =>
            !(nodeById.get(e.source) || {}).isNoise &&
            !(nodeById.get(e.target) || {}).isNoise,
        )
      : edges;
    const refd = new Set(keptEdges.flatMap((e) => [e.source, e.target]));
    const nodes = (lgData.nodes || []).filter((n) => refd.has(n.id));
    return [
      ...nodes.map((n) => ({ data: { id: n.id, name: n.name, type: n.type } })),
      ...keptEdges.map((e) => ({
        data: {
          id: `lge:${e.source}|${e.target}|${e.logonType}|${e.outcome}`,
          source: e.source,
          target: e.target,
          label: `${e.logonType} (${e.count})`,
          outcome: e.outcome,
          risk: e.risk,
          logonType: e.logonType,
          count: e.count,
          firstSeen: e.firstSeen,
          lastSeen: e.lastSeen,
          sourceName: (nodeById.get(e.source) || {}).name,
          targetName: (nodeById.get(e.target) || {}).name,
          sourceFull: e.source.replace(/^account:/, ""),
          targetFull: e.target.replace(/^host:/, ""),
        },
      })),
    ];
  }

  const LG_STYLE = [
    {
      selector: "node",
      style: {
        "background-color": "#e05c5c",
        label: "data(name)",
        color: "#fff",
        "font-size": "10px",
        "text-valign": "center",
        "text-halign": "center",
        shape: "round-rectangle",
        width: "label",
        height: "label",
        padding: "6px",
      },
    },
    {
      selector: 'node[type = "host"]',
      style: { "background-color": "#3a7bd5" },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#8899aa",
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "target-arrow-color": "#8899aa",
        "arrow-scale": 1,
        label: "data(label)",
        "font-size": "9px",
        color: "#ccc",
        "text-rotation": "autorotate",
        "text-background-color": "#0b0e14",
        "text-background-opacity": 0.7,
      },
    },
    {
      selector: 'edge[outcome = "failed"]',
      style: {
        "line-style": "dashed",
        "line-color": "#e05c5c",
        "target-arrow-color": "#e05c5c",
      },
    },
    {
      selector: 'edge[risk = "medium"]',
      style: {
        "line-color": "#e0a15c",
        "target-arrow-color": "#e0a15c",
        width: 2,
      },
    },
    { selector: ".gv-dim", style: { opacity: 0.15 } },
  ];

  function lgEnsureGV() {
    if (lgGV) return lgGV;
    if (!window.DfirGraphView) return null; // module not loaded yet (should not happen post-load)
    lgGV = window.DfirGraphView.createGraphView({
      graphId: "login",
      container: document.getElementById("loginGraph"),
      wrap: document.getElementById("loginGraphWrap"),
      caseIdEl: document.getElementById("caseId"),
      exportName: "login-graph.png",
      defaults: {
        layout: "spread",
        edgeStyle: "bezier",
        dim: 85,
        showFailed: true,
        hideNoise: false,
      },
      style: LG_STYLE,
      buildElements: lgBuildElements,
      onNodeTap: (node) => lgShowNodePanel(node),
      onEdgeTap: (edge) => lgShowEdgePanel(edge),
      onBackgroundTap: () => lgHideSidePanel(),
      onRefresh: () => {
        const cId = document.getElementById("caseId").value.trim();
        if (cId) {
          clearTimeout(lgTimer);
          loadLoginGraph(cId);
        }
      },
      controls: {
        layoutRadios: document.querySelectorAll('input[name="lgLayout"]'),
        edgeStyleRadios: document.querySelectorAll('input[name="lgEdgeStyle"]'),
        dimSlider: document.getElementById("lgDim"),
        filterInput: document.getElementById("lgFilter"),
        fitBtn: document.getElementById("lgFit"),
        fullscreenBtn: document.getElementById("lgFullscreen"),
        exportBtn: document.getElementById("lgExport"),
        refreshBtn: document.getElementById("lgRefresh"),
        optionsBtn: document.getElementById("lgOptions"),
        optionsPanel: document.getElementById("lgOptionsPanel"),
        toggles: [
          { input: document.getElementById("lgShowFailed"), key: "showFailed" },
          { input: document.getElementById("lgHideNoise"), key: "hideNoise" },
        ],
      },
    });
    return lgGV;
  }

  function renderLoginGraph() {
    const stats = document.getElementById("loginGraphStats");
    if (!lgData) {
      stats.textContent = "—";
      return;
    }
    if (lgData.error) {
      stats.textContent = "Login graph unavailable: " + lgData.error;
      if (lgGV) lgGV.destroy();
      return;
    }
    if (!lgData.edges || !lgData.edges.length) {
      stats.textContent =
        "No Windows logon events (4624/4625) found in this case's super-timeline.";
      if (lgGV) lgGV.destroy();
      return;
    }
    const gv = lgEnsureGV();
    if (!gv) {
      stats.textContent =
        "Graph library not loaded — restart the companion server.";
      return;
    }
    const elements = lgBuildElements(gv.view);
    const shown = elements.filter((x) => x.data.source).length;
    stats.innerHTML =
      `${elements.length - shown} nodes and ${shown} edges · generated ${lgAgo(lgData.generatedAt)}` +
      (lgData.truncated
        ? ` · <span class="lg-truncated">showing busiest ${lgData.edges.length} of ${lgData.totalEdges} relationships — refine with the filter</span>`
        : "");
    gv.render();
  }

  function lgHideSidePanel() {
    const p = document.getElementById("lgSidePanel");
    p.style.display = "none";
    p.replaceChildren();
  }

  function lgPivotToTimeline(name) {
    const gs = document.getElementById("globalSearch");
    gs.value = name;
    setSearchBarOpen(true, false); // reveal the filter bar so the active term is visible (no focus steal)
    // superPage(0) semantics without a racing double fetch: applySearch() itself reloads the
    // super-timeline when it has been loaded before, so pre-reset the pagination cursor and only
    // load explicitly when the section has never been opened.
    resetSuperPagination(); // js/dashboard-super-timeline.js owns the cursor
    applySearch(); // commits the search term + rescopes the whole dashboard (window-exposed by the search IIFE)
    if (!DfirState.lastSuperData()) loadSuperTimeline();
    const sec = document.getElementById("sec-super-timeline");
    if (sec) {
      sec.classList.remove("collapsed");
      sec.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // DOM-construction helpers — side-panel content is attacker-influenced log data (account/host
  // names, source IPs parsed from descriptions), so everything is built with createElement/
  // textContent, never innerHTML.
  function lgEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }
  function lgPanelButtons(name) {
    const wrap = lgEl("div", "lg-panel-btns");
    const open = lgEl("button", "lg-open-tl", "Open in Timeline");
    open.type = "button";
    open.onclick = () => lgPivotToTimeline(name);
    const close = lgEl("button", "lg-close", "✕ Close");
    close.type = "button";
    close.onclick = () => {
      lgHideSidePanel();
      if (lgGV) lgGV.dimExcept(null);
    };
    wrap.append(open, close);
    return wrap;
  }

  function lgShowNodePanel(node) {
    const p = document.getElementById("lgSidePanel");
    p.replaceChildren();
    const title = lgEl("div");
    title.append(
      lgEl("b", null, node.data("name")),
      lgEl("span", "ev-sub", " " + node.data("type")),
    );
    // Pivot on the FULL account/host name (node id minus prefix), not the shortened display
    // name — "SYSTEM" alone would match far more than "NT AUTHORITY\SYSTEM" (search is case-insensitive).
    p.append(
      title,
      lgPanelButtons(node.id().replace(/^(?:account|host):/, "")),
    );
    p.style.display = "block";
  }

  function lgShowEdgePanel(edge) {
    const p = document.getElementById("lgSidePanel");
    const d = edge.data();
    p.replaceChildren();
    const title = lgEl("div");
    title.append(lgEl("b", null, `${d.sourceName} → ${d.targetName}`));
    const sub = lgEl(
      "div",
      "ev-sub",
      `${d.label}${d.outcome === "failed" ? " · FAILED" : ""} · ${String(d.firstSeen || "").slice(0, 16)} → ${String(d.lastSeen || "").slice(0, 16)}`,
    );
    const list = lgEl("div", null, "Loading events…");
    list.id = "lgEdgeEvents";
    p.append(title, sub, list, lgPanelButtons(d.sourceFull)); // full account name, not shortened display
    p.style.display = "block";
    const caseId = document.getElementById("caseId").value.trim();
    const qs = new URLSearchParams({
      account: d.sourceFull,
      host: d.targetFull,
      type: d.logonType,
      outcome: d.outcome,
      limit: "50",
    });
    fetch(`/cases/${encodeURIComponent(caseId)}/login-graph/edge-events?${qs}`)
      .then((r) =>
        r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)),
      )
      .then((r) => {
        if (!list.isConnected) return; // panel was closed/replaced meanwhile
        list.replaceChildren();
        for (const e of r.events) {
          const row = lgEl(
            "div",
            "lg-ev-row",
            `${String(e.timestamp || "")
              .replace("T", " ")
              .slice(0, 19)}` +
              `${e.sourceIp ? ` · from ${e.sourceIp}` : ""}${e.workstation ? ` (${e.workstation})` : ""}` +
              `${e.count > 1 ? ` · ×${e.count}` : ""}`,
          );
          list.append(row);
        }
        if (r.total > r.events.length)
          list.append(
            lgEl(
              "div",
              "ev-sub",
              `…and ${r.total - r.events.length} more — Open in Timeline for all`,
            ),
          );
        if (!r.events.length)
          list.append(lgEl("div", "ev-sub", "No matching events."));
      })
      .catch(() => {
        if (list.isConnected) {
          list.replaceChildren();
          list.append(lgEl("div", "ev-sub", "Could not load events."));
        }
      });
  }

  // Deferred relayout: a graph drawn into a collapsed section has no size until the section opens.
  function initLoginGraph() {
    document
      .querySelector("#sec-login-graph h2")
      .addEventListener("click", () => {
        setTimeout(() => {
          if (lgGV) lgGV.onExpand();
        }, 0);
      });
  }

  window.initLoginGraph = initLoginGraph;
  window.loadLoginGraph = loadLoginGraph;
  window.scheduleLoginGraphReload = scheduleLoginGraphReload;
  window.renderLoginGraph = renderLoginGraph;
  window.lgEl = lgEl;
})();
