// AI Agent Forensics in the case report (#2721): which runs a case's report shows, read at report time.
//
//   - the runs launched in the case (its own state/ai-agent-runs.json, newest 20 by the run store's cap);
//   - the sweeps filed into it with "Add to case": a sweep's run stays in the sweep case and records
//     the filing in `addedTo`, so the sweeps still kept (the newest SWEEP_RETENTION) are looked up here.
//     A sweep past retention drops out of this list; the hits it filed stay in the case timeline.
//
// READ-TIME ONLY. withAiAgentRuns() is applied by ReportWriter to the state it renders report.md,
// report.html, state-export.json and the .docx from, and nowhere else: never saved, never part of
// loadFilteredState (so no dashboard panel, push, presentation or redacted export carries it), and
// never AI input — the matched text in a run report is attacker-controlled and stays out of every AI
// path (user decision for #2690). Only report-safe fields are copied (an allowlist): never the raw rows,
// which hold the unredacted matched text, and never the manifest's file list.

import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { AiAgentCaseRun, AiAgentCaseRuns, AiAgentRunView } from "../analysis/aiAgentReportTypes.js";
import { AiAgentRunStore } from "../analysis/aiAgentRunStore.js";
import { isSweepCase, SWEEP_RETENTION } from "../storage/sweepCase.js";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === "string";
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter(str) : []);
const objs = (v: unknown): Obj[] => (Array.isArray(v) ? v.filter(isObj) : []);
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

/** A stored report is kept only when its lists are lists; its nested cells are escaped at render. */
function reportOf(v: unknown): AiAgentRunView["report"] {
  if (!isObj(v) || !Array.isArray(v.endpoints) || !Array.isArray(v.hits) || !Array.isArray(v.notRun))
    return undefined;
  return v as unknown as AiAgentRunView["report"];
}

/** The report-safe fields of one stored run; null when it lacks the fields every run has. */
export function projectAiAgentRun(raw: unknown): AiAgentRunView | null {
  if (!isObj(raw) || !str(raw.runId) || !str(raw.huntId) || !str(raw.launchedAt)) return null;
  const report = reportOf(raw.report);
  const manifest = isObj(raw.manifest) ? raw.manifest : null;
  const incomplete = objs(raw.readIncomplete).map((x) => ({
    artifact: String(x.artifact ?? ""),
    rowsRead: num(x.rowsRead),
  }));
  return {
    runId: raw.runId,
    huntId: raw.huntId,
    ...(str(raw.guiUrl) ? { guiUrl: raw.guiUrl } : {}),
    launchedAt: raw.launchedAt,
    scopes: strs(raw.scopes),
    ruleSetVersion: str(raw.ruleSetVersion) ? raw.ruleSetVersion : "",
    preserved: raw.preserved === true,
    warnings: strs(raw.warnings),
    failedEndpoints: objs(raw.failedEndpoints).map((e) => ({
      clientId: String(e.clientId ?? ""),
      error: String(e.error ?? ""),
    })),
    skippedEndpoints: objs(raw.skippedEndpoints).map((e) => ({
      clientId: String(e.clientId ?? ""),
      hostname: String(e.hostname ?? ""),
      reason: String(e.reason ?? ""),
    })),
    ...(incomplete.length ? { readIncomplete: incomplete } : {}),
    ...(str(raw.reportError) ? { reportError: raw.reportError } : {}),
    ...(manifest ? { manifest: { total: num(manifest.total), totalBytes: num(manifest.totalBytes) } } : {}),
    ...(report ? { report } : {}),
  };
}

/** When this sweep run was last filed into the case; null when it never was. */
function filedAt(raw: unknown, caseId: string): string | null {
  if (!isObj(raw)) return null;
  const times = objs(raw.addedTo)
    .filter((a) => a.caseId === caseId && str(a.at))
    .map((a) => a.at as string);
  return times.length ? times.sort().at(-1)! : null;
}

async function sweepRuns(
  cases: CaseStore,
  store: AiAgentRunStore,
  caseId: string,
  unreadable: string[],
): Promise<{ raw: unknown; filed: { sweepCaseId: string; at: string } }[]> {
  let sweeps: string[];
  try {
    sweeps = (await cases.listCases())
      .filter(isSweepCase)
      .slice(0, SWEEP_RETENTION)
      .map((m) => m.caseId)
      .filter((id) => id !== caseId);
  } catch {
    unreadable.push("the list of AI Agent Forensics sweeps");
    return [];
  }
  const out: { raw: unknown; filed: { sweepCaseId: string; at: string } }[] = [];
  for (const sweepCaseId of sweeps) {
    try {
      for (const raw of await store.list(sweepCaseId)) {
        const at = filedAt(raw, caseId);
        if (at) out.push({ raw, filed: { sweepCaseId, at } });
      }
    } catch {
      unreadable.push(`the run record of sweep ${sweepCaseId}`);
    }
  }
  return out.sort((a, b) => (a.filed.at < b.filed.at ? 1 : a.filed.at > b.filed.at ? -1 : 0));
}

/** The runs a case's report shows: its own, then the sweeps filed into it (latest filing first). */
export async function loadAiAgentCaseRuns(cases: CaseStore, caseId: string): Promise<AiAgentCaseRuns> {
  const store = new AiAgentRunStore(cases);
  const unreadable: string[] = [];
  let own: unknown[] = [];
  try {
    own = await store.list(caseId);
  } catch {
    unreadable.push("this case's AI Agent Forensics run record");
  }
  const candidates = [
    ...own.map((raw) => ({ raw, filed: undefined })),
    ...(await sweepRuns(cases, store, caseId, unreadable)),
  ];
  const runs: AiAgentCaseRun[] = [];
  const seen = new Set<string>();
  let malformed = 0;
  for (const { raw, filed } of candidates) {
    const run = projectAiAgentRun(raw);
    if (!run) malformed++;
    else if (!seen.has(run.runId)) {
      seen.add(run.runId);
      runs.push(filed ? { run, filedFrom: filed } : { run });
    }
  }
  if (malformed) unreadable.push(`${malformed} run record(s) in an unexpected shape`);
  return { runs, unreadable };
}

/** The state with the case's runs added for this one report; the same state when there are none. */
export async function withAiAgentRuns(
  cases: CaseStore,
  caseId: string,
  state: InvestigationState,
): Promise<InvestigationState> {
  const aiAgentRuns = await loadAiAgentCaseRuns(cases, caseId);
  return aiAgentRuns.runs.length || aiAgentRuns.unreadable.length ? { ...state, aiAgentRuns } : state;
}
