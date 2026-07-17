// Shared Cytoscape graph-view module. Loaded in the browser as an ES module
// (<script type="module" src="/js/graph-view.js">) which sets window.DfirGraphView;
// its pure helpers are also named exports so Vitest (node env) can unit-test them.
//
// LOAD ORDER: module scripts run after classic inline scripts, so window.DfirGraphView is
// NOT set while the inline dashboard script's top level executes. That is fine — the inline
// code only *calls* DfirGraphView inside fetch handlers / event listeners / DOMContentLoaded,
// all of which fire after this module has run.

// Build cytoscape layout options from a view. 'spread' is our label for the cose force layout.
// animate:false — animated layouts advance on requestAnimationFrame, which browsers pause in
// background/occluded tabs, stalling the layout forever; synchronous positioning always applies.
export function layoutOptions(view) {
  const name = view.layout === "spread" ? "cose" : view.layout;
  const base = { name, animate: false, fit: true, padding: 30 };
  if (name === "concentric") return { ...base, concentric: (n) => n.degree(), levelWidth: () => 1 };
  if (name === "breadthfirst") return { ...base, directed: true };
  return base;
}

// Dim slider 0..90 → unselected-element opacity 1..0.1 (higher = more transparent), 0.05 floor.
export function dimOpacity(dim) {
  return Math.max(0.05, 1 - dim / 100);
}

// Search predicate: does a node's name (or, failing that, an edge's label) contain the query?
// `query` is expected already trimmed + lowercased by the caller.
export function filterMatch(name, label, query) {
  return String(name || label || "").toLowerCase().includes(query);
}

// Factory for one Cytoscape graph instance + its shared chrome. The adapter supplies data,
// style, and click behavior; this owns everything generic.
//
// opts:
//   graphId       string   — persistence namespace + logical id ("login"|"assets"|"evidence")
//   container     Element  — the graph canvas div
//   wrap          Element  — the element that goes fullscreen (may equal container's parent)
//   caseIdEl      Element  — the #caseId input, for per-case persistence keys
//   exportName    string   — PNG download filename
//   defaults      object   — { layout, edgeStyle, dim, ...toggleKeys }
//   style         array    — cytoscape stylesheet (MUST include a ".gv-dim" selector rule)
//   buildElements (view)=>array — build cytoscape elements from live data + view/toggle state
//   onNodeTap     (node, api)=>void   — adapter side-panel for a node (optional)
//   onEdgeTap     (edge, api)=>void   — adapter side-panel for an edge (optional)
//   onBackgroundTap (api)=>void       — background click, e.g. hide side panel (optional)
//   onRefresh     ()=>void            — refetch data (optional; wired to the refresh button)
//   controls      object   — DOM handles: { layoutRadios(NodeList), edgeStyleRadios(NodeList),
//                              dimSlider, filterInput, fitBtn, fullscreenBtn, exportBtn,
//                              refreshBtn, optionsBtn, optionsPanel, toggles:[{input,key}] }
// returns api: { cy, view, render, fit, resize, exportPng, dimExcept, applyFilter, onExpand, destroy }
export function createGraphView(opts) {
  const {
    graphId, container, wrap, caseIdEl, exportName,
    defaults, style, buildElements,
    onNodeTap, onEdgeTap, onBackgroundTap, onRefresh,
    controls = {},
  } = opts;

  const DIM_CLASS = "gv-dim";
  let cy = null;
  let pendingRender = false;      // container was zero-size (collapsed) at render time
  let view = { ...defaults };

  const viewKey = () => `dfir.graphView.${graphId}.` + ((caseIdEl && caseIdEl.value.trim()) || "");
  function loadView() {
    try { view = { ...defaults, ...JSON.parse(localStorage.getItem(viewKey()) || "{}") }; }
    catch (e) { view = { ...defaults }; }
  }
  function saveView() { try { localStorage.setItem(viewKey(), JSON.stringify(view)); } catch (e) { /* quota — non-fatal */ } }

  function applyEdgeStyle() {
    if (!cy) return;
    cy.style().selector("edge").style("curve-style", view.edgeStyle === "taxi" ? "taxi" : "bezier").update();
  }
  function applyDim() {
    if (!cy) return;
    cy.style().selector("." + DIM_CLASS).style("opacity", dimOpacity(view.dim)).update();
  }
  // Dim everything except `eles` and their neighborhood; null/empty → undim all.
  function dimExcept(eles) {
    if (!cy) return;
    cy.elements().removeClass(DIM_CLASS);
    if (!eles || eles.empty()) return;
    const keep = eles.union(eles.neighborhood());
    cy.elements().difference(keep).addClass(DIM_CLASS);
  }
  function wireInstanceEvents() {
    // Instance-scoped — cy is recreated per render and destroy() unbinds these.
    cy.on("tap", "node", (evt) => { dimExcept(evt.target); if (onNodeTap) onNodeTap(evt.target, api); });
    cy.on("tap", "edge", (evt) => { dimExcept(evt.target); if (onEdgeTap) onEdgeTap(evt.target, api); });
    cy.on("tap", (evt) => { if (evt.target === cy) { dimExcept(null); if (onBackgroundTap) onBackgroundTap(api); } });
  }

  function render() {
    // Collapsed section → zero-size container → cytoscape can't lay out. Defer; onExpand() re-renders.
    if (!container.offsetWidth) { pendingRender = true; return; }
    pendingRender = false;
    if (typeof cytoscape === "undefined") return;   // vendor script failed to load
    const elements = buildElements(view);
    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({ container, elements, style, wheelSensitivity: 0.2 });
    applyEdgeStyle();
    applyDim();
    cy.layout(layoutOptions(view)).run();
    wireInstanceEvents();
  }

  function fit() { if (cy) cy.fit(undefined, 30); }
  function resize() { if (cy) cy.resize(); }
  function exportPng() {
    if (!cy) return;
    const a = document.createElement("a");
    a.href = cy.png({ full: true, scale: 2, bg: "#0f1115" });
    a.download = exportName;
    a.click();
  }
  function applyFilter(raw) {
    if (!cy) return;
    const q = String(raw || "").trim().toLowerCase();
    if (!q) { dimExcept(null); return; }
    const hits = cy.elements().filter((el) => filterMatch(el.data("name"), el.data("label"), q));
    // Zero matches must read as "nothing matches" (dim ALL) — dimExcept(empty) would UNdim all.
    if (hits.empty()) { cy.elements().addClass(DIM_CLASS); return; }
    dimExcept(hits);
  }

  // ---- one-time control wiring (document/element listeners; instance events are in wireInstanceEvents) ----
  const c = controls;
  if (c.fitBtn) c.fitBtn.addEventListener("click", fit);
  if (c.exportBtn) c.exportBtn.addEventListener("click", exportPng);
  if (c.refreshBtn && onRefresh) c.refreshBtn.addEventListener("click", () => onRefresh());
  if (c.filterInput) c.filterInput.addEventListener("input", (e) => applyFilter(e.target.value));
  if (c.dimSlider) c.dimSlider.addEventListener("input", () => { view.dim = Number(c.dimSlider.value); saveView(); applyDim(); });
  if (c.layoutRadios) c.layoutRadios.forEach((r) => r.addEventListener("change", () => {
    if (!r.checked) return;
    view.layout = r.value; saveView();
    if (cy) cy.layout(layoutOptions(view)).run();   // re-layout live
  }));
  if (c.edgeStyleRadios) c.edgeStyleRadios.forEach((r) => r.addEventListener("change", () => {
    if (!r.checked) return;
    view.edgeStyle = r.value; saveView(); applyEdgeStyle();
  }));
  (c.toggles || []).forEach((t) => t.input.addEventListener("change", () => {
    view[t.key] = t.input.checked; saveView(); render();   // element-set change → rebuild
  }));
  if (c.optionsBtn && c.optionsPanel) c.optionsBtn.addEventListener("click", () => {
    const p = c.optionsPanel;
    // The panel starts hidden via inline style="display:none". Toggle purely on that: clicking
    // View while it's open ("") must CLOSE it. (An `|| !p.style.display` fallback would read the
    // open "" state as "hidden" and re-open instead of closing.)
    const show = p.style.display === "none";
    if (show) {   // sync controls from view before showing
      if (c.layoutRadios) c.layoutRadios.forEach((r) => { r.checked = r.value === view.layout; });
      if (c.edgeStyleRadios) c.edgeStyleRadios.forEach((r) => { r.checked = r.value === view.edgeStyle; });
      if (c.dimSlider) c.dimSlider.value = view.dim;
      (c.toggles || []).forEach((t) => { t.input.checked = !!view[t.key]; });
    }
    p.style.display = show ? "" : "none";
  });
  if (c.fullscreenBtn && wrap) {
    c.fullscreenBtn.addEventListener("click", () => {
      if (document.fullscreenElement === wrap) document.exitFullscreen();
      else if (wrap.requestFullscreen) wrap.requestFullscreen();
    });
    // Resize + refit when OUR wrap enters/exits fullscreen. fsWas distinguishes our exit from
    // another section's fullscreenchange (on exit fullscreenElement is null for everyone).
    let fsWas = false;
    document.addEventListener("fullscreenchange", () => {
      const isNow = document.fullscreenElement === wrap;
      if (!isNow && !fsWas) return;
      fsWas = isNow;
      if (cy) setTimeout(() => { if (cy) { cy.resize(); cy.fit(undefined, 30); } }, 60);
    });
  }

  const api = {
    get cy() { return cy; },
    get view() { return view; },
    loadView, saveView, render, fit, resize, exportPng, dimExcept, applyFilter,
    // Called by the section's h2 click hook after setupCollapsible toggles .collapsed.
    onExpand() { if (pendingRender) render(); else if (cy) cy.resize(); },
    destroy() { if (cy) { cy.destroy(); cy = null; } },
  };
  return api;
}

if (typeof window !== "undefined") {
  window.DfirGraphView = { createGraphView, layoutOptions, dimOpacity, filterMatch };
}
