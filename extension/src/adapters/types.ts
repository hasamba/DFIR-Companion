// Tool-specific "site adapters" (issue #102). The extension does NOT try to understand every
// website — it carries a small registry of adapters for known DFIR consoles (Splunk, Velociraptor,
// Elastic/Kibana, CrowdStrike Falcon). An adapter answers three questions, all PURE so they can be
// unit-tested without a browser:
//   1. is THIS tab one of my tools?            → matchUrl
//   2. which of the page's API responses carry result rows?  → apiPatterns
//   3. given one of those response bodies, what are the clean rows?  → extractRows
// The browser-only glue (hooking fetch/XHR, injecting the push button) lives in pageHook.ts /
// artifactCapture.ts and consumes these pure adapters.

export interface Adapter {
  /** Stable id — used in the pushed evidence filename + log lines. */
  readonly id: string;
  /** Human label shown in the injected page button. */
  readonly label: string;
  /** True when this adapter recognizes the page (host / path / port signature). */
  matchUrl(url: URL): boolean;
  /**
   * Regex sources (matched case-insensitively against a response URL) for the tool's data API.
   * The MAIN-world hook only forwards bodies whose URL matches one of these — so we never copy
   * unrelated traffic. Strings (not RegExp) so they survive the postMessage bridge to the page.
   */
  readonly apiPatterns: readonly string[];
  /**
   * Pull the clean result rows out of one captured API response body. Returns `null` when the
   * body isn't a recognized result envelope (the hook may forward several API shapes — only the
   * results-bearing one yields rows). Tolerant by design: tool API shapes drift across versions.
   */
  extractRows(url: string, body: unknown): unknown[] | null;
  /**
   * Optional CSS selector narrowing the DOM-scrape fallback to the results table. When absent the
   * scraper picks the largest visible <table> on the page.
   */
  readonly tableSelector?: string;
  /**
   * Optional: derive a human "source label" (the artifact / notebook the rows came from) so each
   * pushed row can record where to navigate back to. Given the intercepted API URL, the page URL,
   * the page's <input> values (for combo-box selectors), and the rows. Pure. Returns "" when unknown.
   */
  sourceLabel?(opts: { apiUrl: string; pageUrl: string; domInputs: readonly string[]; domHeadings: readonly string[]; rows: readonly unknown[] }): string;
}

/** A captured set of rows ready to push to the companion. */
export interface CapturedArtifact {
  adapterId: string;
  rows: unknown[];
  sourceUrl: string;
  /** "intercept" (clean API JSON) or "scrape" (parsed from the visible table). */
  via: "intercept" | "scrape";
  /** The artifact / notebook the rows came from (also stamped onto each row's `_Source`). */
  label?: string;
}
