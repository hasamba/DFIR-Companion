// Asset↔IoC graph (compromised assets) — extracted from dashboard.html (issue #415, tier 3).
//
// Split out of the Login Graph banner in the previous commit: the two graph features shared one,
// and this half is what the "Compromised assets" section above calls.
//
// assetGV, the one escape, was read by the #sec-assets expand handler in the page's wiring block —
// a relayout for a graph drawn into a collapsed, zero-size container. Its own control, so it is
// the initializer.
//
// The .asset-type-toggle handlers were left behind on the first pass, on the reading that they
// mutate the "Compromised assets" section's state. Wrong: assetTypesEnabled is the layer filter
// THIS graph renders through, read in two places here and nowhere else. The handler and the Set
// have come home together, which is the point — a control and the state it touches belong in one
// place, and splitting them is what left this feature reading a page global for two commits.
(function () {
  "use strict";

  // Moved here from dashboard.html (#415). The graph's own payload, its overrides, the two loaders
  // that fill them and the debounce that drives both. The page held all of it while this module did
  // every read — the fifth time in this PR an extraction stopped at the code and left the state.
  // --- Compromised assets + asset↔IoC graph -------------------------------------
  let assetGraphData = null; // { assets, iocs, edges }
  let assetOverridesData = null; // { renames, added, removed, addedLinks, removedLinks }
  let assetGraphTimer = null;
  // The active time-window query string for the graph reads (#83). Mirrors the global timeline
  // brush (filterFrom/filterTo) so the asset/evidence graphs scope to the same range as the
  // swimlane brush, search-bar dates and applied dwell-windows. Empty when no time filter is set.
  function _graphTimeQuery() {
    const p = new URLSearchParams();
    if (DfirTimelineView.from()) p.set("from", DfirTimelineView.from());
    if (DfirTimelineView.to()) p.set("until", DfirTimelineView.to());
    const q = p.toString();
    return q ? `?${q}` : "";
  }
  function loadAssetGraph(caseId) {
    const gv = assetEnsureGV();
    if (gv) gv.loadView(); // restore this case's persisted view state (layout/dim/edge-style/positions)
    fetch(`/cases/${caseId}/asset-graph${_graphTimeQuery()}`)
      .then((r) => r.json())
      .then((g) => {
        assetGraphData = g;
        renderAssetGraph();
      })
      .catch(() => {});
  }
  function loadAssetOverrides(caseId) {
    fetch(`/cases/${caseId}/asset-overrides`)
      .then((r) => (r.ok ? r.json() : null))
      .then((ov) => {
        assetOverridesData = ov;
        renderAssetList();
      })
      .catch(() => {});
  }
  // State changes (imports / synthesis) re-derive the graph — debounced.
  function scheduleAssetGraphReload() {
    const caseId = document.getElementById("caseId").value.trim();
    if (!caseId) return;
    clearTimeout(assetGraphTimer);
    assetGraphTimer = setTimeout(() => loadAssetGraph(caseId), 800);
  }

  // The layer filter this graph renders through.
  const assetTypesEnabled = new Set(["host", "account", "service"]);

  // "Known compromised assets" — with rename/remove controls when overrides are available.
  function renderAssetList() {
    const el = document.getElementById("assetList");
    if (!assetGraphData) {
      el.textContent = "—";
      return;
    }
    const comp = assetGraphData.assets.filter(
      (a) =>
        a.compromised &&
        (a.type === "host" || a.type === "account") &&
        assetTypesEnabled.has(a.type),
    );
    const editBtns = (a) =>
      `<button class="asset-rename-btn" data-assetid="${escAttr(a.id)}" data-name="${escAttr(a.name)}" title="Rename asset" type="button" data-safe-style="background:none;border:none;cursor:pointer;padding:1px 2px;color:var(--text-faint);font-size:10px">✏</button>` +
      `<button class="asset-merge-btn" data-assetid="${escAttr(a.id)}" data-name="${escAttr(a.name)}" data-assettype="${escAttr(a.type)}" title="Merge into another asset (duplicate entity)" type="button" data-safe-style="background:none;border:none;cursor:pointer;padding:1px 2px;color:var(--text-faint);font-size:10px">⇄</button>` +
      `<button class="asset-del-btn" data-assetid="${escAttr(a.id)}" title="Suppress asset from graph" type="button" data-safe-style="background:none;border:none;cursor:pointer;padding:1px 2px;color:var(--text-faint);font-size:10px">×</button>`;
    const chip = (a) =>
      `<span class="asset-chip" data-safe-style="padding-right:2px">${esc(a.name)}${editBtns(a)}</span>`;
    const group = (label, assets) =>
      assets.length
        ? `<div data-safe-style="margin-bottom:8px"><div class="asset-subhead" data-safe-style="margin:0 0 4px">${label}</div>${assets.map(chip).join(" ")}</div>`
        : "";
    let html = "";
    if (!comp.length)
      html =
        "<em data-safe-style='color:var(--text-muted)'>No compromised hosts or users identified.</em>";
    else
      html =
        group(
          "Hosts",
          comp.filter((a) => a.type === "host"),
        ) +
        group(
          "Users",
          comp.filter((a) => a.type === "account"),
        );
    // Manual additions (not necessarily compromised — show them so analysts can confirm/remove).
    const manual = (assetGraphData.assets || []).filter((a) =>
      a.id.startsWith("manual:"),
    );
    if (manual.length) html += group("Manual additions", manual);
    // Merged (duplicate) assets (#82) — shown with what they were folded into, click ↺ to unmerge.
    if (
      assetOverridesData &&
      Object.keys(assetOverridesData.merges || {}).length
    ) {
      html +=
        `<div data-safe-style="margin-top:8px"><div class="asset-subhead" data-safe-style="margin:0 0 4px">Merged (click ↺ to un-merge)</div>` +
        Object.entries(assetOverridesData.merges)
          .map(
            ([fromId, intoId]) =>
              `<span class="asset-chip" data-safe-style="opacity:0.5">${esc(fromId)} → ${esc(intoId)}` +
              ` <button class="asset-unmerge-btn" data-assetid="${escAttr(fromId)}" title="Un-merge asset" type="button" data-safe-style="background:none;border:none;cursor:pointer;padding:1px 2px;color:var(--text-faint);font-size:10px">↺</button></span>`,
          )
          .join(" ") +
        `</div>`;
    }
    // Suppressed assets (from overrides) — shown for easy restoration.
    if (assetOverridesData && (assetOverridesData.removed || []).length) {
      html +=
        `<div data-safe-style="margin-top:8px"><div class="asset-subhead" data-safe-style="margin:0 0 4px">Suppressed (click ↺ to restore)</div>` +
        assetOverridesData.removed
          .map(
            (id) =>
              `<span class="asset-chip" data-safe-style="opacity:0.5">${esc(id)}` +
              ` <button class="asset-restore-btn" data-assetid="${escAttr(id)}" title="Restore asset" type="button" data-safe-style="background:none;border:none;cursor:pointer;padding:1px 2px;color:var(--text-faint);font-size:10px">↺</button></span>`,
          )
          .join(" ") +
        `</div>`;
    }
    el.innerHTML = html;
  }

  let assetGV = null;

  function assetBuildElements(view) {
    const assets = assetGraphData.assets.filter((a) =>
      assetTypesEnabled.has(a.type),
    );
    const assetIds = new Set(assets.map((a) => a.id));
    const iocs = assetGraphData.iocs.filter((i) =>
      i.assetIds.some((id) => assetIds.has(id)),
    );
    const iocIds = new Set(iocs.map((i) => i.id));
    const edges = assetGraphData.edges.filter(
      (e) => assetIds.has(e.asset) && iocIds.has(e.ioc),
    );
    const iocColor = (v) =>
      v === "malicious"
        ? "#ff5c5c"
        : v === "suspicious"
          ? "#ff9f43"
          : "#6aa9ff";
    const els = [];
    for (const a of assets) {
      els.push({
        data: {
          id: a.id,
          name: truncate(a.name, 40),
          full: a.name,
          kind: "asset",
          glyph: glyphDataUri(
            assetIcon(a.type, 11, 11, a.compromised ? "#ff5c5c" : "#6aa9ff"),
          ),
        },
      });
    }
    for (const i of iocs) {
      els.push({
        data: {
          id: i.id,
          name: truncate(i.value, 40),
          full: `${i.value} (${i.type})`,
          kind: "ioc",
          glyph: glyphDataUri(
            `<circle cx="11" cy="11" r="6" fill="${iocColor(i.verdict)}" stroke="#0f1115" stroke-width="1.5"/>`,
          ),
        },
      });
    }
    for (const e of edges)
      els.push({
        data: { id: `ae:${e.asset}|${e.ioc}`, source: e.asset, target: e.ioc },
      });
    return els;
  }

  const ASSET_STYLE = [
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
        width: 1,
        "line-color": "#3a4456",
        "curve-style": "bezier",
        "target-arrow-shape": "none",
      },
    },
    { selector: ".gv-dim", style: { opacity: 0.1 } },
  ];

  function assetShowNodePanel(node) {
    const p = document.getElementById("assetSidePanel");
    p.replaceChildren();
    const title = lgEl("div");
    title.append(
      lgEl("b", null, node.data("full")),
      lgEl("span", "ev-sub", " " + node.data("kind")),
    );
    const close = lgEl("button", "lg-close", "✕ Close");
    close.type = "button";
    close.onclick = () => {
      p.style.display = "none";
      if (assetGV) assetGV.dimExcept(null);
    };
    p.append(title, close);
    p.style.display = "block";
  }

  function assetEnsureGV() {
    if (assetGV) return assetGV;
    if (!window.DfirGraphView) return null;
    assetGV = window.DfirGraphView.createGraphView({
      graphId: "assets",
      container: document.getElementById("assetGraph"),
      wrap: document.getElementById("assetGraphWrap"),
      caseIdEl: document.getElementById("caseId"),
      exportName: "asset-graph.png",
      defaults: { layout: "spread", edgeStyle: "bezier", dim: 85 },
      style: ASSET_STYLE,
      buildElements: assetBuildElements,
      onNodeTap: (node) => assetShowNodePanel(node),
      onBackgroundTap: () => {
        document.getElementById("assetSidePanel").style.display = "none";
      },
      onRefresh: () => {
        const cId = document.getElementById("caseId").value.trim();
        if (cId) loadAssetGraph(cId);
      },
      controls: {
        layoutRadios: document.querySelectorAll(
          'input[name="assetLayoutRadio"]',
        ),
        edgeStyleRadios: document.querySelectorAll(
          'input[name="assetEdgeStyle"]',
        ),
        dimSlider: document.getElementById("assetDim"),
        filterInput: document.getElementById("assetFilter"),
        fitBtn: document.getElementById("assetFit"),
        fullscreenBtn: document.getElementById("assetFullscreenBtn"),
        exportBtn: document.getElementById("assetExport"),
        refreshBtn: document.getElementById("assetRefresh"),
        optionsBtn: document.getElementById("assetOptions"),
        optionsPanel: document.getElementById("assetOptionsPanel"),
        toggles: [], // asset-type toggles are wired separately below (they mutate a Set, not a view flag)
      },
    });
    return assetGV;
  }

  function renderAssetGraph() {
    renderAssetList();
    const el = document.getElementById("assetGraph");
    if (!assetGraphData || !assetGraphData.assets.length) {
      el.innerHTML =
        "<div data-safe-style='padding:16px;color:var(--text-muted)'>No assets yet — import evidence (THOR / CSV / SIEM-EDR JSON) or run Synthesize. Hosts come from each event's affected asset.</div>";
      if (assetGV) assetGV.destroy();
      return;
    }
    const assets = assetGraphData.assets.filter((a) =>
      assetTypesEnabled.has(a.type),
    );
    if (!assets.length) {
      el.innerHTML =
        "<div data-safe-style='padding:16px;color:var(--text-muted)'>No assets of the selected type(s).</div>";
      if (assetGV) assetGV.destroy();
      return;
    }
    const gv = assetEnsureGV();
    if (!gv) {
      el.textContent =
        "Graph library not loaded — restart the companion server.";
      return;
    }
    gv.render();
  }

  // Evidence Chain graph lives in public/js/dashboard-evidence-graph.js.

  function initAssetGraph() {
    // Asset-type toggles mutate the enabled Set, then rebuild through the module.
    document.querySelectorAll(".asset-type-toggle").forEach((cb) =>
      cb.addEventListener("change", () => {
        if (cb.checked) assetTypesEnabled.add(cb.value);
        else assetTypesEnabled.delete(cb.value);
        renderAssetGraph();
      }),
    );

    // Paint the legend glyph into each Show-toggle (doubles as the graph's icon key). This ran at
    // MODULE scope in the inline script, where the markup already existed. In a <head> module it
    // would match nothing and the legend would come up blank, with no error — the same trap the
    // evidence graph's evTypesEnabled seeding hit in extraction 80. I skipped the split on the body
    // range again; the lifecycle gate caught it again.
    document.querySelectorAll(".legend-slot").forEach((s) => {
      s.innerHTML = legendIcon(s.dataset.ltype);
    });
    // Deferred render when the collapsed section expands.
    document.querySelector("#sec-assets h2").addEventListener("click", () => {
      setTimeout(() => {
        if (assetGV) assetGV.onExpand();
      }, 0);
    });
  }

  // The refresh fan-out's question: is there a graph to reload?
  function hasAssetGraph() {
    return !!assetGraphData;
  }
  // js/dashboard-asset-overrides.js reads the asset list to match rename candidates against.
  function assetGraphAssets() {
    return (assetGraphData && assetGraphData.assets) || [];
  }

  window.hasAssetGraph = hasAssetGraph;
  window.assetGraphAssets = assetGraphAssets;
  window.loadAssetGraph = loadAssetGraph;
  window.loadAssetOverrides = loadAssetOverrides;
  window.scheduleAssetGraphReload = scheduleAssetGraphReload;
  window.initAssetGraph = initAssetGraph;
  window.assetEnsureGV = assetEnsureGV;
  window.renderAssetGraph = renderAssetGraph;
  window.renderAssetList = renderAssetList;
})();
