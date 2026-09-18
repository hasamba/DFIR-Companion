// Joins an AWS flow's own already-computed resource attribution (#1151, a narrower slice of #931
// item 13's own "identity/execution" ask) to the attributed instance's own launch identity and
// remote-access requests, both already carried on the compute-lifecycle summary (#931 item 8,
// awsCompute.ts). Reads ONLY the sibling pass's own note text (awsFlowResourceAttribution.ts) to
// learn which instance(s) a flow was attributed to — never re-derives the attribution itself, so
// the two joins can never disagree with each other.
//
// What one note establishes, and what it never claims:
//   - "the instance's own launch record names <X> as the signing principal" and/or "a remote-
//     access request (<call>) was recorded against it at <time>, requested by <Y>" — both are
//     DISCLOSED FACTS, never a claim that <X> or <Y> caused this flow, and never a claim that a
//     remote-access request RAN anything on the instance: "whether anything ran is not in
//     CloudTrail" is this codebase's own established wording for that exact gap
//     (awsComputeRow.ts), reused verbatim here rather than the overclaiming word "execution";
//   - a remote-access request is disclosed only within +/-24h of the flow's own timestamp, and the
//     note SAYS SO — a session months removed does not corroborate a flow. The launch identity is
//     NOT time-windowed: a launch is a permanent fact about the instance, not an activity-in-
//     progress claim;
//   - both endpoints of an attributed flow are labeled independently (source/destination + IP +
//     instanceId), matching the sibling pass's own multi-endpoint shape; an endpoint the sibling
//     called ambiguous (names no instance) gets no identity fragment here either;
//   - compute-lifecycle summaries for the SAME (account, instanceId) across separate uploads are
//     unioned — launch identity from whichever upload carries one (more than one distinct value
//     across uploads is stated as ambiguous, never silently picked), remote-access entries deduped
//     by their own locator. One upload's own coverage gap is not the instance's whole story;
//   - `remoteBeyond` (requests the summary itself did not retain) is disclosed by count whenever
//     any matching block reports one — the MAXIMUM seen across unioned blocks, a conservative
//     "at least this many" floor, never summed (uploads can overlap the same underlying calls);
//   - the remote-access list is capped; an overflow says how many more fell in the window;
//   - re-runs on every merge; strips its own prior note first (bracket content never nests here,
//     confirmed against every other note this file touches, so this is safe to strip in isolation
//     — matching the sibling's own established strip-before-recompute discipline, itself a fix for
//     a logged partial-evidence bug, #1158's own review). Same self-healing shape as the pass it
//     follows, and the same limitation: a super-timeline row already settled is not retroactively
//     rewritten by a later merge.

import type { ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import { FLOW_ATTRIBUTION_MARKER } from "./awsFlowResourceAttribution.js";

export const FLOW_IDENTITY_EXECUTION_MARKER = "[flow identity/execution:";
const FLOW_IDENTITY_EXECUTION_NOTE_RE = /\s*\[flow identity\/execution:[^\]]*\]/gu;

const REMOTE_WINDOW_MS = 24 * 3_600_000;
const MAX_REMOTE_ENTRIES = 5;

const ATTRIBUTION_NOTE_RE = /\[flow resource attribution:([^\]]*)\]/u;
const ATTRIBUTION_ENTRY_RE = /^(source|destination) (\S+) = (\S+)$/u;

function ms(timestamp: string): number | null {
  const t = Date.parse(timestamp ?? "");
  return Number.isFinite(t) ? t : null;
}

function isFlowEvent(e: ForensicEvent): boolean {
  return e.canonical?.event.category === "network" && e.canonical.event.type === "flow";
}

function isComputeSummary(e: ForensicEvent): boolean {
  return e.canonical?.event.category === "cloud" && !!e.canonical.awsCompute;
}

interface RemoteEntry {
  call: string;
  by: string;
  time: string;
  timeMs: number;
  locator: string;
  document?: string;
}

interface InstanceIdentity {
  launchBy: Set<string>;
  remote: Map<string, RemoteEntry>; // keyed by locator, deduped across unioned uploads
  remoteBeyond: number; // max seen across unioned blocks, never summed
}

/** Attributed instance/endpoint entries parsed from the sibling pass's own note text. */
interface AttributedEndpoint {
  label: "source" | "destination";
  ip: string;
  instanceId: string;
}

function parseAttributionEndpoints(description: string | undefined): AttributedEndpoint[] {
  const m = ATTRIBUTION_NOTE_RE.exec(description ?? "");
  if (!m) return [];
  const out: AttributedEndpoint[] = [];
  for (const rawEntry of m[1].split(";").map((s) => s.trim())) {
    const entryMatch = ATTRIBUTION_ENTRY_RE.exec(rawEntry);
    if (!entryMatch) continue; // an "ambiguous — multiple candidate instances" entry names no instance
    const [, label, ip, instanceId] = entryMatch;
    out.push({ label: label as "source" | "destination", ip, instanceId });
  }
  return out;
}

function buildIdentityIndex(events: readonly ForensicEvent[]): Map<string, InstanceIdentity> {
  const index = new Map<string, InstanceIdentity>();
  for (const e of events) {
    if (!isComputeSummary(e)) continue;
    const c = e.canonical!;
    const accountId = c.cloud?.accountId ?? "";
    const instanceId = c.awsCompute!.instanceId ?? "";
    if (!accountId || !instanceId) continue;
    const key = `${accountId}|${instanceId}`;
    const entry = index.get(key) ?? { launchBy: new Set<string>(), remote: new Map(), remoteBeyond: 0 };
    const by = c.awsCompute!.launch?.by;
    if (by) entry.launchBy.add(by);
    for (const r of c.awsCompute!.remote ?? []) {
      const t = ms(r.time);
      if (t === null || !r.by || !r.call || !r.locator) continue;
      entry.remote.set(r.locator, { call: r.call, by: r.by, time: r.time, timeMs: t, locator: r.locator, document: r.document });
    }
    entry.remoteBeyond = Math.max(entry.remoteBeyond, c.awsCompute!.remoteBeyond ?? 0);
    index.set(key, entry);
  }
  return index;
}

function formatFragment(endpoint: AttributedEndpoint, identity: InstanceIdentity, flowMs: number): string {
  const launchPart =
    identity.launchBy.size === 0
      ? "launch record not in evidence"
      : identity.launchBy.size === 1
        ? `launched by ${[...identity.launchBy][0]}`
        : `launched by: ambiguous — multiple recorded signing principals across uploads`;

  const inWindow = [...identity.remote.values()]
    .filter((r) => Math.abs(r.timeMs - flowMs) <= REMOTE_WINDOW_MS)
    .sort((a, b) => a.timeMs - b.timeMs);
  const shown = inWindow.slice(0, MAX_REMOTE_ENTRIES);
  const overflow = inWindow.length - shown.length;

  let remotePart: string;
  if (shown.length === 0) {
    remotePart = "remote-access within ±24h of the flow: none";
  } else {
    const entries = shown
      .map((r) => `${r.call} by ${r.by} at ${r.time}${r.document ? ` (document: ${r.document})` : ""}`)
      .join(", ");
    const overflowSuffix = overflow > 0 ? `, + ${overflow} more in window` : "";
    remotePart = `remote-access within ±24h (requested; whether anything ran is not in CloudTrail): ${entries}${overflowSuffix}`;
  }

  const beyondSuffix =
    identity.remoteBeyond > 0
      ? `; ${identity.remoteBeyond} further remote-access record${identity.remoteBeyond === 1 ? "" : "s"} not retained by the summary`
      : "";

  return `${endpoint.label} ${endpoint.ip} = ${endpoint.instanceId}: ${launchPart}; ${remotePart}${beyondSuffix}`;
}

export function correlateAwsFlowIdentityExecution(events: readonly ForensicEvent[]): ForensicEvent[] {
  const index = buildIdentityIndex(events);
  if (index.size === 0) return events as ForensicEvent[];

  return events.map((e) => {
    if (!isFlowEvent(e)) return e;
    const strippedDescription = (e.description ?? "").replace(FLOW_IDENTITY_EXECUTION_NOTE_RE, "");
    const accountId = e.canonical?.cloud?.accountId ?? "";
    const flowMs = ms(e.timestamp);
    if (!accountId || flowMs === null || !(e.description ?? "").includes(FLOW_ATTRIBUTION_MARKER)) {
      return strippedDescription === e.description ? e : { ...e, description: strippedDescription };
    }

    const endpoints = parseAttributionEndpoints(e.description);
    const fragments: string[] = [];
    for (const endpoint of endpoints) {
      const identity = index.get(`${accountId}|${endpoint.instanceId}`);
      if (!identity) continue;
      fragments.push(formatFragment(endpoint, identity, flowMs));
    }

    if (fragments.length === 0) {
      return strippedDescription === e.description ? e : { ...e, description: strippedDescription };
    }
    return {
      ...e,
      description: appendDerivedNote(strippedDescription, FLOW_IDENTITY_EXECUTION_MARKER, fragments.join("; ")),
    };
  });
}
