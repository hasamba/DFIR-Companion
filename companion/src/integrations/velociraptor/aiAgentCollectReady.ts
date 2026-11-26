// When to import an AI Agent Forensics run (#2907).
//
// The run is a PAUSED hunt with the picked endpoints added to it, so Velociraptor never reports the
// hunt itself as done, and the hunt-state poll alone would never collect. It used to be collected by
// one timer 30 minutes after launch, which on a real run imported an early, partial result while the
// endpoint kept collecting for another 90 minutes, and nothing read the rest.
//
// Now the status poll (which survives a restart and honours case deletion) asks this on each tick:
// collect once every added endpoint's collection has ended, or once the per-endpoint time limit plus a
// grace period has passed, whichever comes first. A failed read before the deadline waits; it never
// collects early.
import { AI_AGENT_COLLECTION_TIMEOUT_SECONDS } from "./aiAgentLaunch.js";
import { aiAgentFlowsAllEnded, huntFlowsVql, parseHuntFlows } from "./aiAgentRunStatus.js";
import type { VeloHuntJob } from "../../analysis/veloHuntStore.js";

/** After the per-endpoint limit, how long to wait for a late endpoint before importing anyway. */
export const AI_AGENT_COLLECT_GRACE_SECONDS = 15 * 60;

export interface AiAgentFlowsClient {
  runProgram(program: string): Promise<{ rows: unknown[]; reason: string }>;
}

/** The moment the run is imported even if an endpoint has not finished (ms since the epoch). */
export function aiAgentCollectDeadline(launchedAt: string): number {
  const t = Date.parse(launchedAt);
  const base = Number.isFinite(t) ? t : 0;
  return base + (AI_AGENT_COLLECTION_TIMEOUT_SECONDS + AI_AGENT_COLLECT_GRACE_SECONDS) * 1000;
}

/** Is this AI-agent run ready to import? Never throws: an unreadable answer before the deadline is "not yet". */
export async function aiAgentRunReadyToCollect(
  client: AiAgentFlowsClient,
  job: VeloHuntJob,
  now: number = Date.now(),
): Promise<boolean> {
  if (now >= aiAgentCollectDeadline(job.launchedAt)) return true;
  try {
    const { rows } = await client.runProgram(huntFlowsVql(job.huntId));
    return aiAgentFlowsAllEnded(parseHuntFlows(rows), Math.max(1, job.aiAgentEndpointCount ?? 1));
  } catch {
    return false;
  }
}
