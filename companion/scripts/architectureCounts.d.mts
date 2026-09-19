// Types for architectureCounts.mjs. It has to be .mjs — check-boundaries.mjs imports it and runs
// under plain `node` in CI, with no TypeScript loader — and tsconfig has no allowJs, so a test that
// imports it needs this bridge. Nothing generates the file, so it can drift from the module; the
// test asserts the runtime result's exact key set against what is declared here, which turns that
// drift into a failure rather than a lie that type-checks.
export interface BoundaryCounts {
  /** Still accepted (the scan produces the pair) but no longer written into prose — #1368. */
  complying: number;
  crossDomain: number;
  violations: number;
}

export interface ArchitectureRewrite {
  /** The document with every derived figure replaced. Unchanged if it states none of them. */
  text: string;
  /** Whether anything actually moved — the caller skips the write when nothing did. */
  changed: boolean;
  /** How many "N violations" claims were rewritten. */
  violationClaims: number;
}

export function architectureWithCounts(doc: string, counts: BoundaryCounts): ArchitectureRewrite;
