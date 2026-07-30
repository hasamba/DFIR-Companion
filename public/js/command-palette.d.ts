// Types for the pure half of command-palette.js — the part above its "browser glue" banner.
//
// This file exists because companion/tests/analysis/commandPalette.test.ts imports those named
// exports and runs them in node, and a plain .js import gives TypeScript nothing to check (TS7016,
// then an implicit `any` on every callback parameter derived from it). That is what kept the test
// out of the typecheck (#385).
//
// It deliberately covers only the exports the test drives. The browser glue below the banner in the
// .js (wire(), the overlay, the DOM listeners) is untyped on purpose: nothing outside the browser
// imports it, and declaring it here would mean maintaining a second copy of DOM plumbing that no
// checker would ever compare against the real thing.
//
// KEEP IN SYNC. TypeScript trusts this file over the .js next to it — a signature that drifts here
// makes the test compile against a contract the runtime does not honour. When you change a
// signature in command-palette.js, change it here in the same commit.

/** The fixed category set, in the order the palette lists them. */
export declare const CATEGORY_ORDER: readonly string[];

/** One entry in the action registry the inline dashboard script publishes. */
export interface PaletteAction {
  id: string;
  label: string;
  category: string;
  keywords?: string[];
  run?: () => void;
  /** Optional gate. Absent ⇒ always offered; a predicate that throws hides just this action. */
  available?: (state: unknown) => boolean;
}

/** One ranked hit from `searchActions`. */
export interface PaletteHit {
  action: PaletteAction;
  score: number;
}

/** A `>category term` query split into its parts; `category` is null when none was recognised. */
export interface ParsedQuery {
  category: string | null;
  term: string;
}

/** Ranked match of `query` against one string; 0 means no match. */
export declare function fuzzyScore(query: string, text: string): number;

/** Split `">exp csv"` into a category filter plus the remaining search term. */
export declare function parseQuery(raw: string): ParsedQuery;

/** Best of the action's label score and 0.9x its best keyword score. */
export declare function scoreAction(term: string, action: PaletteAction): number;

/** Whether the action's `available` predicate (if any) vouches for it under `state`. */
export declare function isAvailable(action: PaletteAction, state: unknown): boolean;

/**
 * Filter + rank the registry for one query. Recency is a tie-breaker, never a score bonus.
 *
 * `actions` and `recents` accept null/undefined because the implementation guards for both
 * (`actions || []`, `Array.isArray(recents) ? recents : []`) — the inline dashboard script can
 * call this before its registry has been built.
 */
export declare function searchActions(
  raw: string,
  actions: readonly PaletteAction[] | null | undefined,
  state: unknown,
  recents: readonly string[] | null | undefined,
): PaletteHit[];

/** Most-recent-first, de-duplicated, capped. Returns a new array; never mutates the input. */
export declare function bumpRecent(recents: readonly string[] | null | undefined, id: string): string[];
