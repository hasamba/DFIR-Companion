// "AI Agent Forensics" case report section (#2721): every run launched in the case, and every sweep
// filed into it with "Add to case", each with its own run report — what was looked at per endpoint,
// what matched (with the redacted matched text, both hashes and their caveat), the rule-by-endpoint
// Sigma coverage, and what was not run and why. The body is the one the per-run download renders
// (aiAgentReportExport.ts), so the two never disagree.
//
// The data is read at report time only (aiAgentCaseRuns.ts): it is never saved with the case and the
// AI never reads it. Omitted when the case has no run, so every other report is unchanged.

import type { InvestigationState } from "../analysis/stateTypes.js";
import type { AiAgentCaseRun } from "../analysis/aiAgentReportTypes.js";
import { aiAgentRunBodyMarkdown } from "./aiAgentReportExport.js";
import { codeSpanMd, oneLineMd } from "./mdText.js";

/** Hits per run in the case report; the run's own download lists every hit. */
export const AI_AGENT_SECTION_MAX_HITS = 500;

const INTRO =
  "Runs of the AI Agent Forensics endpoint check (tampered AI coding agents: instruction files, MCP " +
  "servers, hooks) for this case. Matched text appears only here, in the AI Agent Forensics panel and " +
  "in each run's own report download; the AI never reads it.";
const APPENDIX =
  "Each run below is its own record, as read from Velociraptor. The case's scope, clock-skew " +
  "alignment and false-positive marks apply to the timeline and findings above, not to this record. " +
  "A sweep filed into the case shows here while the sweep is kept (the newest 20 sweeps); the hits it " +
  "filed stay in the case timeline either way.";

function originLine(c: AiAgentCaseRun): string {
  if (!c.filedFrom) return "Launched in this case.";
  const { sweepCaseId, at } = c.filedFrom;
  const builtAt = c.run.report?.builtAt;
  const reread =
    builtAt && builtAt > at
      ? ` Its results were read again after that (${oneLineMd(builtAt)}); the case timeline holds the hits as filed.`
      : "";
  return `Filed into this case from sweep ${codeSpanMd(sweepCaseId)} on ${oneLineMd(at)}.${reread}`;
}

function runLines(c: AiAgentCaseRun): string[] {
  const head = [
    `### Run ${codeSpanMd(c.run.huntId)} — launched ${oneLineMd(c.run.launchedAt)}`,
    "",
    originLine(c),
    "",
  ];
  try {
    return [...head, ...aiAgentRunBodyMarkdown(c.run, { level: 4, maxHits: AI_AGENT_SECTION_MAX_HITS }), ""];
  } catch {
    return [...head, "This run's record could not be rendered.", ""];
  }
}

export function aiAgentSection(state: InvestigationState, lines: string[]): void {
  const a = state.aiAgentRuns;
  if (!a || (!a.runs.length && !a.unreadable.length)) return;
  lines.push("## AI Agent Forensics", "", INTRO, "", APPENDIX, "");
  if (a.unreadable.length) lines.push(...a.unreadable.map((u) => `- Could not be read: ${oneLineMd(u)}`), "");
  for (const c of a.runs) lines.push(...runLines(c));
}
