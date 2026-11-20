// AI Agent Forensics in the case report (#2721): which runs a case's report shows, read at report time.
//
//   - the runs launched in the case (its own state/ai-agent-runs.json, newest 20 by the run store's cap);
//   - the sweeps filed into it with "Add to case": a sweep's run stays in the sweep case and records
//     the filing in `addedTo`, so the sweeps still kept (the newest SWEEP_RETENTION) are looked up here;
//   - the report-safe copies saved into the case at filing time (#2740, aiAgentFiledRuns.ts), so a
//     filed sweep stays in the report after retention removes the sweep. A live sweep wins over its copy
//     (it can show a re-read after filing). A sweep filed before #2740 has no copy and drops out with it.
//
// READ-TIME ONLY. withAiAgentRuns() is applied by ReportWriter to the state it renders report.md,
// report.html, state-export.json and the .docx from, and nowhere else: never saved with the
// investigation state, never part of loadFilteredState (so no dashboard panel, push, presentation or
// redacted export carries it), and never AI input — the matched text in a run report is
// attacker-controlled and stays out of every AI path (user decision for #2690). Only report-safe fields
// are copied (an allowlist, aiAgentRunProjection.ts): never the raw rows, which hold the unredacted
// matched text, and never the manifest's file list.

import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { AiAgentCaseRun, AiAgentCaseRuns } from "../analysis/aiAgentReportTypes.js";
import { AiAgentRunStore } from "../analysis/aiAgentRunStore.js";
import { isSweepCase, SWEEP_RETENTION } from "../storage/sweepCase.js";
import { isObj, objs, projectAiAgentRun, str } from "./aiAgentRunProjection.js";
import { listFiledRuns } from "./aiAgentFiledRuns.js";

export { projectAiAgentRun };

type Candidate = { raw: unknown; filed?: { sweepCaseId: string; at: string } };

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
): Promise<Required<Candidate>[]> {
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
  const out: Required<Candidate>[] = [];
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
  return out;
}

const byFiledAtDesc = (a: { at: string }, b: { at: string }): number =>
  a.at < b.at ? 1 : a.at > b.at ? -1 : 0;

/** The copies saved at filing time (#2740), latest filing first; after the live sweeps so those win. */
async function filedCopies(cases: CaseStore, caseId: string, unreadable: string[]): Promise<Candidate[]> {
  try {
    return (await listFiledRuns(cases, caseId)).map((e) => ({ raw: e.run, filed: e.filedFrom }));
  } catch {
    unreadable.push("this case's filed AI Agent Forensics sweep copies");
    return [];
  }
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
  const candidates: Candidate[] = [
    ...own.map((raw) => ({ raw })),
    ...(await sweepRuns(cases, store, caseId, unreadable)),
    ...(await filedCopies(cases, caseId, unreadable)),
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
  const launched = runs.filter((r) => !r.filedFrom);
  const filed = runs.filter((r) => r.filedFrom).sort((a, b) => byFiledAtDesc(a.filedFrom!, b.filedFrom!));
  return { runs: [...launched, ...filed], unreadable };
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
