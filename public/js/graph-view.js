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

// createGraphView is implemented in Phase 2. Stub keeps the module importable meanwhile.
export function createGraphView() {
  throw new Error("createGraphView not implemented yet");
}

if (typeof window !== "undefined") {
  window.DfirGraphView = { createGraphView, layoutOptions, dimOpacity, filterMatch };
}
