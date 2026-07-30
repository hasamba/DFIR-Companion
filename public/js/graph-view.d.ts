// Types for the pure helpers of graph-view.js, for the same reason as command-palette.d.ts:
// companion/tests/analysis/graphView.test.ts imports them and runs them in node, and without a
// declaration the import is TS7016 and the test cannot be type-checked at all (#385).
//
// Only the three pure helpers are declared. `createGraphView` is browser-only — it takes live
// Cytoscape and DOM handles — and nothing outside the browser imports it, so hand-typing it here
// would be an unverifiable second copy of its contract.
//
// KEEP IN SYNC with graph-view.js: TypeScript trusts this file over the .js beside it.

/** The view state a layout is built from. Extra keys (edgeStyle, dim, toggles) are ignored here. */
export interface GraphViewState {
  layout: string;
  [key: string]: unknown;
}

/**
 * Cytoscape layout options. `concentric`/`levelWidth` are present only for the concentric layout
 * and `directed` only for breadthfirst, so both are optional — a caller reading them off an
 * arbitrary layout has to account for their absence, which is exactly what the .js does.
 */
export interface GraphLayoutOptions {
  name: string;
  animate: boolean;
  fit: boolean;
  padding: number;
  concentric?: (node: { degree: () => number }) => number;
  levelWidth?: () => number;
  directed?: boolean;
}

/** Build cytoscape layout options from a view. "spread" is our label for the cose force layout. */
export declare function layoutOptions(view: GraphViewState): GraphLayoutOptions;

/** Dim slider 0..90 to unselected-element opacity 1..0.1, with a 0.05 floor. */
export declare function dimOpacity(dim: number): number;

/** Does a node's name (or, failing that, an edge's label) contain the already-lowercased query? */
export declare function filterMatch(
  name: string | null | undefined,
  label: string | null | undefined,
  query: string,
): boolean;
