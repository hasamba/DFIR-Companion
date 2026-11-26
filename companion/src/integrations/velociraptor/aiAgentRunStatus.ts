// Is an AI Agent Forensics run still going, or done? (#2898)
//
// The run card had no status: an analyst could not tell a run still collecting from one that had
// finished. The run is a Velociraptor hunt with the picked endpoints added to it, so its progress is the
// hunt's own client counts — read live, never stored, and turned into one plain-English sentence here.
import type { HuntClientCounts } from "./huntClientCounts.js";

export type AiAgentRunState = "running" | "finished" | "stopped" | "unknown";

export interface AiAgentRunStatus {
  state: AiAgentRunState;
  /** Endpoints the run covers: the picked ones, or more if Velociraptor scheduled more. */
  total: number;
  finished: number;
  errors: number;
  summary: string;
}

/** What `VelociraptorClient.huntStatus` returns; null when Velociraptor has no record of the hunt. */
export type HuntStatusRead = { state: string; clients?: HuntClientCounts } | null;

const STOPPED_STATES = new Set(["STOPPED", "ARCHIVED"]);

/** Pure: the hunt's counts as the run card's status. `endpointCount` is how many endpoints were picked. */
export function describeAiAgentRunStatus(hunt: HuntStatusRead, endpointCount: number): AiAgentRunStatus {
  const unknown = (why: string): AiAgentRunStatus => ({
    state: "unknown",
    total: endpointCount,
    finished: 0,
    errors: 0,
    summary: `Unknown — ${why}`,
  });
  if (!hunt) return unknown("Velociraptor has no record of this run");
  if (!hunt.clients) return unknown("Velociraptor did not report this run's progress");
  const total = Math.max(hunt.clients.scheduled, endpointCount);
  const finished = Math.min(hunt.clients.completed, total);
  const errors = hunt.clients.errors;
  const errorNote = errors ? `; ${errors} reported an error` : "";
  const of = `${finished} of ${total} endpoint(s)`;
  if (total > 0 && finished >= total)
    return { state: "finished", total, finished, errors, summary: `Finished — ${of} done${errorNote}` };
  if (STOPPED_STATES.has(hunt.state.trim().toUpperCase()))
    return {
      state: "stopped",
      total,
      finished,
      errors,
      summary: `Stopped in Velociraptor — ${of} finished${errorNote}`,
    };
  return { state: "running", total, finished, errors, summary: `Running — ${of} finished${errorNote}` };
}
