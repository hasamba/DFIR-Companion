// AI Agent Forensics (#2690): the hidden "sweep case". A run started with no case open creates one
// case per run, flagged `kind: "sweep"` in case.json, so it reuses every piece of case machinery —
// evidence-first storage, the hunt jobs, the import lock, background recovery. It is shown only in
// the AI Agent Forensics panel: analyst-facing case lists (the case picker's GET /cases, cross-case
// search) filter it out with isAnalystCase; background readers (hunt timers, monitors, recovery,
// maintenance, custody, the job ledger, diagnostics counts) keep seeing it, so a sweep's hunt is never
// stranded. tests/architecture/sweepCaseListing.test.ts classifies every listCases() call site.

import { randomBytes } from "node:crypto";
import type { CaseMeta } from "../types.js";

export const SWEEP_CASE_KIND = "sweep" as const;
export const SWEEP_CASE_PREFIX = "aiagent-sweep-";
/** Sweeps kept; the oldest beyond this is removed automatically (Velociraptor data is never touched). */
export const SWEEP_RETENTION = 20;

/** False for a hidden sweep case — the one test every analyst-facing case list applies. */
export function isAnalystCase(meta: Pick<CaseMeta, "kind">): boolean {
  return meta.kind !== SWEEP_CASE_KIND;
}

export function isSweepCase(meta: Pick<CaseMeta, "kind"> | null | undefined): boolean {
  return meta?.kind === SWEEP_CASE_KIND;
}

/** A fresh sweep case id: sortable by time, valid under isValidCaseId. */
export function newSweepCaseId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\..*$/, "").replace("T", "-");
  return `${SWEEP_CASE_PREFIX}${stamp}-${randomBytes(3).toString("hex")}`;
}

/** The sweeps that fall outside the retention window, oldest last in `metas` order (newest first). */
export function sweepsBeyondRetention(metas: readonly CaseMeta[], keep = SWEEP_RETENTION): CaseMeta[] {
  return metas
    .filter(isSweepCase)
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0))
    .slice(keep);
}
