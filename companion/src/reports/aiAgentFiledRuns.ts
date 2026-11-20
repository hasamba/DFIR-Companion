// AI Agent Forensics (#2740): the report-safe copy of each sweep run filed into a case with "Add to
// case", kept in the TARGET case (state/ai-agent-filed-runs.json). Sweep cases are pruned to the newest
// SWEEP_RETENTION, so without this copy a filed run would drop out of the case report once its sweep
// was removed. Written at each filing by addSweepToCase, and replaced in place when the filed sweep's
// results are read again (refreshAiAgentRun, #2744); read only by the case report loader
// (aiAgentCaseRuns.ts). Never AI input, never part of the saved investigation state.
//
// Only the projected run is stored (aiAgentRunProjection.ts): never the raw rows with the unredacted
// matched text, never the manifest's file list. Every entry is projected again on read.
//
// Like state/ai-agent-runs.json, the file is not in SNAPSHOT_STATE_FILES: a backup restore never
// rewinds it, and it travels with a case archive (which walks the whole case folder).

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { AiAgentCaseRun } from "../analysis/aiAgentReportTypes.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "../analysis/stateLock.js";
import { isObj, projectAiAgentRun, str } from "./aiAgentRunProjection.js";

export const FILED_RUNS_FILE = "ai-agent-filed-runs.json";
/** Filed-run copies a case keeps, latest filing first. */
export const MAX_FILED_RUNS_PER_CASE = 50;

export interface FiledFrom {
  sweepCaseId: string;
  at: string;
}
type FiledRun = Required<AiAgentCaseRun>;

const lock = new StateLock();
const pathOf = (cases: CaseStore, caseId: string): string => join(cases.stateDir(caseId), FILED_RUNS_FILE);

/** One stored entry, re-validated: the file is never trusted. */
function entryOf(v: unknown): FiledRun | null {
  if (!isObj(v) || !isObj(v.filedFrom)) return null;
  const { sweepCaseId, at } = v.filedFrom;
  const run = projectAiAgentRun(v.run);
  return run && str(sweepCaseId) && str(at) ? { run, filedFrom: { sweepCaseId, at } } : null;
}

async function readRaw(cases: CaseStore, caseId: string): Promise<unknown[]> {
  try {
    const parsed = JSON.parse(await readFile(pathOf(cases, caseId), "utf8")) as unknown;
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/** The case's filed-run copies, latest filing first; throws when the file cannot be read. */
export async function listFiledRuns(cases: CaseStore, caseId: string): Promise<FiledRun[]> {
  const entries = (await readRaw(cases, caseId)).map(entryOf).filter((e): e is FiledRun => e !== null);
  return [...entries].sort((a, b) =>
    a.filedFrom.at < b.filedFrom.at ? 1 : a.filedFrom.at > b.filedFrom.at ? -1 : 0,
  );
}

/** Save (or replace, by run id) the report-safe copy of a filed run; false when the run has no usable shape. */
export function saveFiledRun(
  cases: CaseStore,
  caseId: string,
  raw: unknown,
  filedFrom: FiledFrom,
): Promise<boolean> {
  const run = projectAiAgentRun(raw);
  if (!run) return Promise.resolve(false);
  return lock.runExclusive(caseId, async () => {
    const kept = (await listFiledRuns(cases, caseId)).filter((e) => e.run.runId !== run.runId);
    const next = [{ run, filedFrom: { ...filedFrom } }, ...kept].slice(0, MAX_FILED_RUNS_PER_CASE);
    await atomicWrite(pathOf(cases, caseId), JSON.stringify(next, null, 2));
    return true;
  });
}

/** Replace the copy of an already filed run after its sweep was read again (#2744). Update only: it
 *  never creates a copy, never re-dates it (filedFrom keeps the filing time, so the report can say the
 *  results were read again after that) and never reorders or evicts. False when no copy was replaced. */
export function updateFiledRun(cases: CaseStore, caseId: string, raw: unknown): Promise<boolean> {
  const run = projectAiAgentRun(raw);
  if (!run) return Promise.resolve(false);
  return lock.runExclusive(caseId, async () => {
    const entries = await listFiledRuns(cases, caseId);
    if (!entries.some((e) => e.run.runId === run.runId)) return false;
    const next = entries.map((e) => (e.run.runId === run.runId ? { run, filedFrom: e.filedFrom } : e));
    await atomicWrite(pathOf(cases, caseId), JSON.stringify(next, null, 2));
    return true;
  });
}
