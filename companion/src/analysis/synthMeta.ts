import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { FindingsDiff } from "./findingsDiff.js";

// Lightweight per-case record of the LAST synthesis run: when it actually ran (the AI call, not a
// skipped no-op) and what changed in the findings. Kept in a side file (`state/synth-meta.json`)
// so the dashboard can show "last synthesized 3 min ago" and a what-changed diff. NOT part of
// InvestigationState (which synthesis rewrites); written by pipeline.synthesize only on a real run.

const severityChangeSchema = z.object({
  title: z.string(),
  from: z.string(),
  to: z.string(),
});

// Second-look sweep result (investigation-guidance #11): what the post-synthesis re-query of the raw
// record promoted, and which requests came back empty (each an actionable collection lead). Surfaced on
// the synth-meta card. Optional/lenient — absent on a run where the sweep didn't run or found nothing.
const secondLookSchema = z.object({
  promoted: z.number().catch(0),          // events pulled up from the raw record and re-synthesized
  requests: z.number().catch(0),          // total search requests issued this sweep
  matched: z.number().catch(0),           // requests that hit at least one event
  leads: z.array(z.string()).catch([]),   // reasons of requests that matched nothing (collection leads)
  summary: z.string().catch(""),          // one-line human summary for the card
  at: z.string().catch(""),               // when the sweep ran
});

export type SecondLookMeta = z.infer<typeof secondLookSchema>;

// Synthesis coverage audit (issue #62): how much of the case the LAST real synthesis run actually put
// in front of the model, and what it left out and why. The model can only read a bounded slice of a
// large timeline (selectSynthesisEvents caps at DFIR_AI_SYNTH_MAX_EVENTS / the token budget), so the
// analyst needs to see "considered N of M" and the reason breakdown to trust the conclusions. All
// counts are derived deterministically at the synthesis call site. Optional/lenient — absent on old
// files and on runs recorded before this existed.
const synthesisCoverageSchema = z.object({
  inWindow: z.number().catch(0),             // events inside the scope window — the denominator ("of M")
  considered: z.number().catch(0),           // events the model actually read ("N")
  omittedBudget: z.number().catch(0),        // in-window, non-legitimate events dropped by the size/token cap
  omittedLegitimate: z.number().catch(0),    // in-window events filtered out as false-positive / legitimate
  omittedScope: z.number().catch(0),         // events dropped for being OUTSIDE the scope window
  omittedHighSeverity: z.number().catch(0),  // of the budget-omitted, how many are Critical/High (the safety-net backfill still covers these)
  promptTokensEstimate: z.number().catch(0), // ~size of the assembled synthesis prompt, in tokens
});

export type SynthesisCoverage = z.infer<typeof synthesisCoverageSchema>;

/**
 * Build a coverage snapshot from the raw per-stage event counts (pure). `totalEvents` is the whole
 * forensic timeline; `inWindow` is after the scope filter; `scoped` is after the false-positive/
 * legitimate filter; `considered` is what the model actually saw. Omissions are attributed to their
 * stage and clamped to non-negative (defensive against out-of-order inputs).
 */
export function buildSynthesisCoverage(input: {
  totalEvents: number;
  inWindow: number;
  scoped: number;
  considered: number;
  omittedHighSeverity: number;
  promptTokensEstimate: number;
}): SynthesisCoverage {
  const nn = (n: number): number => (n > 0 ? n : 0);
  return {
    inWindow: nn(input.inWindow),
    considered: nn(input.considered),
    omittedScope: nn(input.totalEvents - input.inWindow),
    omittedLegitimate: nn(input.inWindow - input.scoped),
    omittedBudget: nn(input.scoped - input.considered),
    omittedHighSeverity: nn(input.omittedHighSeverity),
    promptTokensEstimate: nn(input.promptTokensEstimate),
  };
}

/**
 * One-line human summary for the dashboard card / report footnote, e.g.
 * "Analysis considered 287 of 412 in-window events (125 omitted: 120 size limit, 5 filtered) · 8
 * high-severity recovered by the safety net · ~61k prompt tokens". Omits each clause that is zero.
 */
export function coverageLabel(c: SynthesisCoverage): string {
  let s = `Analysis considered ${c.considered} of ${c.inWindow} in-window event${c.inWindow === 1 ? "" : "s"}`;
  const omitted = c.omittedBudget + c.omittedLegitimate;
  if (omitted > 0) {
    const parts: string[] = [];
    if (c.omittedBudget > 0) parts.push(`${c.omittedBudget} size limit`);
    if (c.omittedLegitimate > 0) parts.push(`${c.omittedLegitimate} filtered`);
    s += ` (${omitted} omitted: ${parts.join(", ")})`;
  }
  if (c.omittedHighSeverity > 0) s += ` · ${c.omittedHighSeverity} high-severity recovered by the safety net`;
  if (c.omittedScope > 0) s += ` · ${c.omittedScope} outside scope window`;
  if (c.promptTokensEstimate > 0) s += ` · ~${Math.round(c.promptTokensEstimate / 1000)}k prompt tokens`;
  return s;
}

export const synthMetaSchema = z.object({
  lastSynthesizedAt: z.string().catch(""),
  lastDiff: z.object({
    added: z.array(z.string()).catch([]),
    removed: z.array(z.string()).catch([]),
    severityChanged: z.array(severityChangeSchema).catch([]),
  }).nullable().catch(null),
  durationMs: z.number().optional().catch(undefined),
  eventCount: z.number().optional().catch(undefined),
  iocCount: z.number().optional().catch(undefined),
  secondLook: secondLookSchema.nullable().optional().catch(undefined),
  // Per-class selection counts (investigation-guidance #4): how many events of each selection class the
  // model actually saw this run (anchor / earliest / context / corroborated / technique / rare / spread),
  // so the analyst can see the evidence mix behind the conclusions. Optional/lenient; absent on old files.
  selectionCounts: z.record(z.string(), z.number()).optional().catch(undefined),
  // Synthesis coverage audit (#62): what the model saw vs what was left out, and why.
  coverage: synthesisCoverageSchema.nullable().optional().catch(undefined),
});

export type SynthMeta = z.infer<typeof synthMetaSchema>;

const EMPTY: SynthMeta = { lastSynthesizedAt: "", lastDiff: null };

export interface SynthPerfMetrics {
  durationMs: number;
  eventCount: number;
  iocCount: number;
  selectionCounts?: Record<string, number>;   // #4: per-class counts of the events the model saw
  coverage?: SynthesisCoverage;               // #62: included/omitted coverage audit for this run
}

export class SynthMetaStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "synth-meta.json");
  }

  async load(caseId: string): Promise<SynthMeta> {
    try {
      return synthMetaSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Record a completed synthesis run: stamp the time, store the findings diff, and
  // optionally store performance metrics (duration, event/IOC counts).
  async record(caseId: string, diff: FindingsDiff, at: string = new Date().toISOString(), perf?: SynthPerfMetrics): Promise<SynthMeta> {
    const meta: SynthMeta = { lastSynthesizedAt: at, lastDiff: diff, ...perf };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }

  // Stamp the second-look sweep result onto the CURRENT synth-meta (#11). Called AFTER the sweep and its
  // (optional) re-synthesis, so it merges onto the latest record() write instead of being clobbered by
  // it. Load-merge-save so the rest of the meta (time/diff/perf) is preserved. `null` clears it.
  async recordSecondLook(caseId: string, secondLook: SecondLookMeta | null): Promise<SynthMeta> {
    const cur = await this.load(caseId);
    const meta: SynthMeta = { ...cur, secondLook };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }
}
