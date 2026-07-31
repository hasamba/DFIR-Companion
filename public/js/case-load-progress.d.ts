// Types for the pure half of case-load-progress.js — the part above its "browser glue" banner.
//
// This file exists for the same reason command-palette.d.ts does: companion/tests/analysis/
// caseLoadProgress.test.ts imports those named exports and runs them in node, the test tree is
// type-checked (tsconfig.test.json), and a plain .js import gives TypeScript nothing (TS7016).
//
// It deliberately covers only the exports the test drives. The browser glue below the banner in the
// .js (the overlay wiring, the panel strip, the fetch-attributing runner) is untyped on purpose:
// nothing outside the browser imports it, and declaring it here would mean maintaining a second
// copy of DOM plumbing that no checker would ever compare against the real thing.
//
// KEEP IN SYNC. TypeScript trusts this file over the .js next to it — a signature that drifts here
// makes the test compile against a contract the runtime does not honour. When you change a
// signature in case-load-progress.js, change it here in the same commit.

/** The phases the overlay is up for, in order. */
export declare const LOAD_STAGES: readonly string[];

/** Opaque per-generation tracker for the overlay's staged bar. */
export interface LoadState {
  done: Set<string>;
  loaded: number;
  total: number;
  eventCount: number | null;
  high: number;
}

/** Opaque tally over the panel loaders that outlive the overlay. */
export interface PanelTally {
  total: number;
  settled: Set<string>;
  failed: Set<string>;
}

/** What the bar should show right now. */
export interface LoadProgress {
  /** 0..1, monotonic by construction. */
  fraction: number;
  /** `fraction` as a rounded percentage. */
  percent: number;
  /** The stage now RUNNING, not the one just finished. */
  label: string;
  /** True when the running stage has no signal behind it and must not show a number. */
  shimmer: boolean;
}

/** How much of the panel fan-out has finished. */
export interface PanelProgress {
  fraction: number;
  settled: number;
  total: number;
  failed: number;
}

/** Fresh tracker for one case-load generation. */
export declare function createLoadState(): LoadState;

/** Mark a stage complete. Unknown, duplicate and out-of-order ids are no-ops. */
export declare function advanceStage(state: LoadState, stageId: string): void;

/** Record download progress; a non-positive or non-finite `total` switches the stage to shimmer. */
export declare function setDownloadBytes(state: LoadState, loaded: number, total: number): void;

/** The parsed payload's event count — the real figure behind the render stage's label. */
export declare function setEventCount(state: LoadState, n: number): void;

/** Current fraction, percent, label and shimmer flag. */
export declare function progressOf(state: LoadState): LoadProgress;

/** Fresh tally over a denominator fixed before any loader runs. */
export declare function createPanelTally(total: number): PanelTally;

/** Record a panel as finished. Idempotent per name. */
export declare function settlePanel(tally: PanelTally, name: string): void;

/** Record a panel as finished unsuccessfully. Still counts as settled. */
export declare function failPanel(tally: PanelTally, name: string): void;

/** Tally state. Empty tallies read as complete rather than dividing by zero. */
export declare function panelProgressOf(tally: PanelTally): PanelProgress;

/**
 * Read a response body to text while reporting real byte progress into `state`.
 *
 * Typed here despite living near the browser glue because the streaming path and its two fallbacks
 * (no Content-Length, no readable body) are exactly where this would break silently, so the test
 * drives them directly.
 */
export declare function readBodyWithProgress(
  state: LoadState,
  response: Response,
  onProgress?: () => void,
): Promise<string>;

/**
 * Run every `[name, thunk]` panel loader, tallying each as its requests settle.
 *
 * Typed for the same reason: it swaps `globalThis.fetch` for the duration of its synchronous loop,
 * and the test asserts that the swap is undone even when a loader throws.
 */
export declare function runPanelLoaders(
  entries: readonly (readonly [string, () => void])[],
  onProgress?: (tally: PanelTally) => void,
): PanelTally;

/**
 * Resolves after the browser has painted, or after `timeoutMs`, whichever comes first.
 *
 * Typed because the timeout is a correctness property, not a nicety: this await sits mid-load, and
 * a backgrounded tab runs no rAF callbacks at all, so without a way out it hangs the case load
 * rather than just the bar. The test drives exactly that case.
 */
export declare function afterPaint(timeoutMs?: number): Promise<void>;
