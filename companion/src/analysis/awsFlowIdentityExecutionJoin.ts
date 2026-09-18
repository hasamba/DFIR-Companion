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
//     across uploads is stated as ambiguous, naming every disagreeing principal, never silently
//     picked), remote-access entries deduped by their own full content (never locator alone, so a
//     genuine locator collision with different content is never silently overwritten). One
//     upload's own coverage gap is not the instance's whole story;
//   - `remoteBeyond` (requests the summary itself did not retain) is disclosed by count whenever
//     any matching block reports one — the MAXIMUM seen across unioned blocks, a conservative
//     "at least this many" floor, never summed (uploads can overlap the same underlying calls);
//     the malformed remote-record count takes the same max-across-blocks floor, because a record
//     that failed to parse has no reliable content key to dedup on (#1293);
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
  remote: Map<string, RemoteEntry>; // keyed by content, so a genuine locator collision with
  // different content is never silently overwritten (Ollama code review, M4)
  remoteBeyond: number; // max seen across unioned blocks, never summed
  remoteSkipped: number; // malformed remote records dropped at parse time (M1) — disclosed, never
  // silent; max seen across unioned blocks, never summed (no content key to dedup on, #1293)
}

// Evidence-derived strings (a launch/remote "by" principal, an SSM document name) flow verbatim
// into a bracket-delimited note whose own strip/recompute lifecycle depends on bracket content
// never nesting (Ollama code review, H1). A forged or malformed CloudTrail record naming a
// principal/document containing "[" or "]" would otherwise corrupt that invariant and could make
// this pass's own strip regex, or the sibling's, mis-parse an unrelated note. Strip brackets from
// every evidence-derived string before it is ever interpolated — this is a report-integrity
// requirement (CLAUDE.md), not polish.
function sanitizeForNote(s: string): string {
  return s.replace(/[[\]]/gu, "");
}

/** Attributed instance/endpoint entries parsed from the sibling pass's own note text. */
export interface AttributedEndpoint {
  label: "source" | "destination";
  ip: string;
  instanceId: string;
}

/** Shared with awsFlowSensitiveDataJoin.ts (#1295) so both joins read the sibling note identically. */
export function parseAttributionEndpoints(description: string | undefined): AttributedEndpoint[] {
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
    const entry = index.get(key) ?? {
      launchBy: new Set<string>(),
      remote: new Map(),
      remoteBeyond: 0,
      remoteSkipped: 0,
    };
    const by = c.awsCompute!.launch?.by;
    if (by) entry.launchBy.add(sanitizeForNote(by));
    let blockSkipped = 0;
    for (const r of c.awsCompute!.remote ?? []) {
      const t = ms(r.time);
      if (t === null || !r.by || !r.call || !r.locator) {
        blockSkipped += 1;
        continue;
      }
      // Keyed on full content, not locator alone: two records that legitimately share a locator
      // string across overlapping uploads collapse to one identical key naturally; any real
      // difference produces a distinct entry instead of one silently overwriting the other.
      const contentKey = `${r.locator}|${r.call}|${r.by}|${r.time}`;
      entry.remote.set(contentKey, {
        call: sanitizeForNote(r.call),
        by: sanitizeForNote(r.by),
        time: r.time,
        timeMs: t,
        locator: r.locator,
        document: r.document ? sanitizeForNote(r.document) : undefined,
      });
    }
    entry.remoteBeyond = Math.max(entry.remoteBeyond, c.awsCompute!.remoteBeyond ?? 0);
    // Same floor as remoteBeyond: the same upload imported twice must not double its count.
    entry.remoteSkipped = Math.max(entry.remoteSkipped, blockSkipped);
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
        : `launched by: ambiguous — recorded signing principals disagree across uploads (${[...identity.launchBy].join(", ")})`;

  const inWindow = [...identity.remote.values()].filter(
    (r) => Math.abs(r.timeMs - flowMs) <= REMOTE_WINDOW_MS,
  );
  // Closest-to-the-flow entries are the probative ones when a cap is needed, not the earliest.
  inWindow.sort((a, b) => Math.abs(a.timeMs - flowMs) - Math.abs(b.timeMs - flowMs));
  const shown = inWindow.slice(0, MAX_REMOTE_ENTRIES).sort((a, b) => a.timeMs - b.timeMs);
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

  // Both suffixes below cover records the WINDOW FILTER NEVER SAW — they are stated separately
  // from remotePart's own "within ±24h" clause so neither reads as if it were window-scoped.
  const skippedSuffix =
    identity.remoteSkipped > 0
      ? `; at least ${identity.remoteSkipped} remote-access record${identity.remoteSkipped === 1 ? "" : "s"} could not be read (malformed)`
      : "";
  const beyondSuffix =
    identity.remoteBeyond > 0
      ? `; the summary itself did not retain at least ${identity.remoteBeyond} further remote-access record${identity.remoteBeyond === 1 ? "" : "s"} (any window)`
      : "";

  return `${endpoint.label} ${endpoint.ip} = ${endpoint.instanceId}: ${launchPart}; ${remotePart}${skippedSuffix}${beyondSuffix}`;
}

export function correlateAwsFlowIdentityExecution(events: readonly ForensicEvent[]): ForensicEvent[] {
  // No early return on an empty index: a case that loses every compute-summary record between
  // merges (re-scoped upload, corrected import) must still strip a now-stale note, not just skip.
  const index = buildIdentityIndex(events);

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
      description: appendDerivedNote(
        strippedDescription,
        FLOW_IDENTITY_EXECUTION_MARKER,
        fragments.join("; "),
      ),
    };
  });
}
