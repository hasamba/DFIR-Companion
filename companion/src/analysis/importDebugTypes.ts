// The shape of an import's debug summary (#1736). Types only, in the shared tier, so the
// diagnostics ring (analysis/case) can carry one without importing the import layer. Built and
// sanitized by analysis/importDebug.ts — see there for the privacy rules each field obeys.

/**
 * `parsed`: the importer itself finished, but the attempt still has steps to run (settle, tag, demote).
 * It is NOT final — a later failure is recorded as `failed` without contradicting it. The other four
 * are final, and the first final outcome wins: a second one is ignored and writes no second line.
 */
export type ImportOutcome = "parsed" | "succeeded" | "failed" | "cancelled" | "refused";

export interface ImportDebugSummary {
  /** A built-in import kind, `custom` for an analyst's importer, or `unknown`. */
  kind: string;
  /** How the kind was chosen, when the resolver said so. */
  detection?: { confident: boolean; decision: string };
  counts: { total?: number; kept?: number; dropped?: number };
  /** target -> source column -> rows that used it. */
  fields: Record<string, Record<string, number>>;
  /** Rows NOT mapped at all, by reason. */
  skipped: Record<string, number>;
  /** Valid rows mapped and then removed (severity floor, event cap, aggregation), by reason. */
  omitted: Record<string, number>;
  /** Rows kept but unusual (no host, empty time), by code. */
  observations: Record<string, number>;
  /** Import- or row-level decisions (generic mapper, AI fallback), with how often. */
  fallbacks: Record<string, number>;
  /** Where a parse failed, only when the parser KNOWS it — never guessed from a message. */
  failure?: { phase: string; row?: number };
  outcome?: ImportOutcome;
  /** True when any cap above dropped entries: the detail is then partial, not exhaustive. */
  truncated: boolean;
}
