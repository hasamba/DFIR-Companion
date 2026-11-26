// Is an AI Agent Forensics run still going, or done? (#2898)
//
// The run card had no status: an analyst could not tell a run still collecting from one that had
// finished. The run is a paused Velociraptor hunt with the picked endpoints added to it, so its
// progress is each endpoint's own collection, read live from `hunt_flows()` and never stored.
//
// NOT the hunt's summary counters. On a real run the hunt's stats said 0 rows and 0 finished while the
// endpoint's collection was IN_PROGRESS with 1,172 rows: the counters lag behind the collections, and a
// status built on them could read "0 finished" long after the work was done.
import { AI_AGENT_COLLECTION_TIMEOUT_SECONDS } from "./aiAgentLaunch.js";
import { CLIENT_RE } from "./clientInventory.js";

export type AiAgentRunState = "running" | "finished" | "stopped" | "unknown";

export interface AiAgentRunStatus {
  state: AiAgentRunState;
  /** Endpoints the run covers: the picked ones, or more if the hunt holds more collections. */
  total: number;
  /** Collections that ended: FINISHED, or ended with an error. */
  finished: number;
  errors: number;
  summary: string;
}

/** One endpoint's collection in the hunt. */
export interface HuntFlowRead {
  clientId: string;
  state: string;
  rows: number;
  status: string;
  /** How long the collection ran, in seconds, from its create and last-active times; undefined when unread. */
  ranSeconds?: number;
}

const HUNT_RE = /^H\.[A-Za-z0-9]+$/;
const STOPPED_STATES = new Set(["STOPPED", "ARCHIVED"]);

/** The VQL for one hunt's collections. Throws on a hunt id that is not one, before it reaches the string. */
export function huntFlowsVql(huntId: string): string {
  if (!HUNT_RE.test(huntId)) throw new Error("invalid hunt id");
  return (
    "SELECT Flow.client_id AS ClientId, Flow.state AS State, Flow.status AS Status, " +
    "Flow.total_collected_rows AS Rows, Flow.create_time AS Created, Flow.active_time AS LastActive " +
    `FROM hunt_flows(hunt_id='${huntId}')`
  );
}

/** hunt_flows rows → collections; undefined when a row is not what this reads (never guessed). */
export function parseHuntFlows(rows: unknown): HuntFlowRead[] | undefined {
  if (!Array.isArray(rows)) return undefined;
  const out: HuntFlowRead[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const r = row as Record<string, unknown>;
    const clientId = typeof r.ClientId === "string" ? r.ClientId.trim() : "";
    if (!CLIENT_RE.test(clientId) || typeof r.State !== "string") return undefined;
    const n = Number(r.Rows ?? 0);
    out.push({
      clientId,
      state: r.State.trim().toUpperCase(),
      rows: Number.isSafeInteger(n) && n >= 0 ? n : 0,
      status: typeof r.Status === "string" ? r.Status.trim() : "",
      ranSeconds: ranSeconds(r.Created, r.LastActive),
    });
  }
  return out;
}

// Velociraptor flow times are microseconds since the epoch.
function ranSeconds(created: unknown, lastActive: unknown): number | undefined {
  const a = Number(created);
  const b = Number(lastActive);
  if (!Number.isFinite(a) || !Number.isFinite(b) || a <= 0 || b < a) return undefined;
  return Math.floor((b - a) / 1e6);
}

// A collection that ended this close to the per-endpoint limit most likely ran into it. Its last
// activity is not proof of WHY it ended, so the card hedges ("may be partial") instead of asserting.
const LIMIT_SLACK_SECONDS = 60;
const nearLimit = (f: HuntFlowRead): boolean =>
  ended(f) &&
  f.ranSeconds !== undefined &&
  f.ranSeconds >= AI_AGENT_COLLECTION_TIMEOUT_SECONDS - LIMIT_SLACK_SECONDS;

/**
 * Every collection the run expects has ended. False while one is still running, while fewer
 * collections exist than endpoints were added (one not reached yet), or when nothing was read.
 */
export function aiAgentFlowsAllEnded(
  flows: readonly HuntFlowRead[] | undefined,
  endpointCount: number,
): boolean {
  if (!flows || flows.length === 0 || flows.length < endpointCount) return false;
  return flows.every(ended);
}

const ended = (f: HuntFlowRead): boolean => f.state === "FINISHED" || f.state === "ERROR";
const failed = (f: HuntFlowRead): boolean => f.state === "ERROR" || (f.state === "FINISHED" && !!f.status);

/**
 * Pure: the run card's status. `huntState` is the hunt's own state (null: Velociraptor has no record
 * of it); `flows` its collections (undefined: they could not be read); `endpointCount` the endpoints
 * picked. A picked endpoint with no collection yet has not been reached — usually it is offline.
 */
export function describeAiAgentRunStatus(
  huntState: string | null,
  flows: readonly HuntFlowRead[] | undefined,
  endpointCount: number,
): AiAgentRunStatus {
  const unknown = (why: string): AiAgentRunStatus => ({
    state: "unknown",
    total: endpointCount,
    finished: 0,
    errors: 0,
    summary: `Unknown — ${why}`,
  });
  if (huntState === null) return unknown("Velociraptor has no record of this run");
  if (!flows) return unknown("could not read this run's collections from Velociraptor");
  const total = Math.max(endpointCount, flows.length);
  const finished = flows.filter(ended).length;
  const errors = flows.filter(failed).length;
  const notStarted = total - flows.length;
  const rows = flows.reduce((sum, f) => sum + f.rows, 0);
  const of = `${finished} of ${total} endpoint(s)`;
  const base = { total, finished, errors };
  const limitHit = flows.filter(nearLimit).length;
  const limitNote = limitHit
    ? `; ${limitHit} ran to the ${AI_AGENT_COLLECTION_TIMEOUT_SECONDS / 3600}-hour time limit, so its results may be partial`
    : "";
  if (total > 0 && finished >= total) {
    const errorNote = errors ? `; ${errors} ended with an error` : "";
    return { ...base, state: "finished", summary: `Finished — ${of} done${errorNote}${limitNote}` };
  }
  if (STOPPED_STATES.has(huntState.trim().toUpperCase()))
    return { ...base, state: "stopped", summary: `Stopped in Velociraptor — ${of} finished${limitNote}` };
  const notes = [
    ...(rows ? [`${rows.toLocaleString("en-US")} rows collected so far`] : []),
    ...(notStarted ? [`${notStarted} not started yet (offline?)`] : []),
    ...(errors ? [`${errors} ended with an error`] : []),
  ];
  return {
    ...base,
    state: "running",
    summary: `Running — ${of} finished${notes.map((n) => `; ${n}`).join("")}`,
  };
}
