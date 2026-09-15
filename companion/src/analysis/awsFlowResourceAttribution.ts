// The resource-lifetime half of #931 item 13: attributing an AWS VPC flow-log event to the EC2
// instance that held its private IP at the time, using the already-landed compute-lifecycle
// tracking (#931 item 8, awsCompute.ts/awsComputeRow.ts). Lives in stateMerge.ts's cross-import
// chain — the flow log (a Storage/S3 export) and the CloudTrail-derived lifecycle summary (an
// Activity export) are always two separate uploads, so this can only ever be a post-merge join.
//
// What one attribution note establishes, and what it never claims:
//   - "this flow's `<endpoint>` matches the private IP AWS assigned to `<instanceId>` at its
//     last known launch before this flow's timestamp" — a best-available match, never a
//     guaranteed one;
//   - NO authoritative instance-termination time exists in the current data model (confirmed:
//     canonicalAwsCompute.ts only exposes a `terminated` boolean, never a queryable
//     `terminatedAt`) — so the match rule needs no termination time at all: a flow attributes to
//     whichever tracked launch on the SAME (accountId, privateAddress) is the LATEST one at or
//     before the flow's own timestamp. A later launch on that key naturally supersedes an
//     earlier one, which is exactly what address reuse means in practice;
//   - keyed on (accountId, privateAddress), not privateAddress alone — RFC1918 reuse across
//     different, unrelated AWS accounts is normal, not malformed evidence;
//   - both endpoints of one flow are checked independently — two instances in evidence talking
//     to each other get two attribution notes, not an error;
//   - a tie (two tracked launches at the exact same recorded time on one key — malformed/
//     duplicate CloudTrail data) states ambiguity and names no instance;
//   - re-runs on every merge (stateMerge's whole chain does), so once BOTH a CloudTrail upload
//     and a flow-log upload exist in a case, the NEXT merge produces correct attribution
//     regardless of which was imported first. What does NOT self-heal: the super-timeline's own
//     already-settled copy of a row is not retroactively rewritten by a later merge — a stale,
//     unattributed copy can persist there even after the forensic-timeline copy is annotated.

import type { ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";

export const FLOW_ATTRIBUTION_MARKER = "[flow resource attribution:";

function ms(timestamp: string): number | null {
  const t = Date.parse(timestamp ?? "");
  return Number.isFinite(t) ? t : null;
}

// Local, minimal RFC1918 check — internalIp.ts lives in analysis/ingest, a layer above this
// module's analysis/timeline domain; importing it would be an upward violation.
function isPrivateIpv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip ?? "");
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

interface Launch {
  instanceId: string;
  timeMs: number;
}

function isFlowEvent(e: ForensicEvent): boolean {
  return e.canonical?.event.category === "network" && e.canonical.event.type === "flow";
}

function isComputeLaunch(
  e: ForensicEvent,
): { accountId: string; privateAddress: string; instanceId: string } | null {
  const c = e.canonical;
  if (!c || c.event.category !== "cloud" || !c.awsCompute) return null;
  const accountId = c.cloud?.accountId ?? "";
  const privateAddress = c.awsCompute.launch?.privateAddress ?? "";
  const instanceId = c.awsCompute.instanceId ?? "";
  if (!accountId || !privateAddress || !instanceId) return null;
  return { accountId, privateAddress, instanceId };
}

/** The latest tracked launch at-or-before `atMs` for one (account, IP) key, or "ambiguous", or none. */
function attributeAt(
  launches: readonly Launch[],
  atMs: number,
): { instanceId: string } | { ambiguous: true } | null {
  const eligible = launches.filter((l) => l.timeMs <= atMs);
  if (eligible.length === 0) return null;
  const latest = Math.max(...eligible.map((l) => l.timeMs));
  const atLatest = eligible.filter((l) => l.timeMs === latest);
  const distinctInstances = new Set(atLatest.map((l) => l.instanceId));
  if (distinctInstances.size > 1) return { ambiguous: true };
  return { instanceId: atLatest[0].instanceId };
}

export function correlateAwsFlowResourceAttribution(events: readonly ForensicEvent[]): ForensicEvent[] {
  const index = new Map<string, Map<string, number>>(); // key -> instanceId -> earliest launch ms
  for (const e of events) {
    const launch = isComputeLaunch(e);
    if (!launch) continue;
    const t = ms(e.timestamp);
    if (t === null) continue;
    const key = `${launch.accountId}|${launch.privateAddress}`;
    const byInstance = index.get(key) ?? new Map<string, number>();
    const existing = byInstance.get(launch.instanceId);
    if (existing === undefined || t < existing) byInstance.set(launch.instanceId, t);
    index.set(key, byInstance);
  }
  if (index.size === 0) return events as ForensicEvent[];

  const launchesFor = (accountId: string, ip: string): Launch[] => {
    const byInstance = index.get(`${accountId}|${ip}`);
    if (!byInstance) return [];
    return [...byInstance.entries()].map(([instanceId, timeMs]) => ({ instanceId, timeMs }));
  };

  return events.map((e) => {
    if (!isFlowEvent(e)) return e;
    if ((e.description ?? "").includes(FLOW_ATTRIBUTION_MARKER)) return e;
    const accountId = e.canonical?.cloud?.accountId ?? "";
    if (!accountId) return e;
    const t = ms(e.timestamp);
    if (t === null) return e;

    const notes: string[] = [];
    for (const [label, ip] of [
      ["source", e.srcIp],
      ["destination", e.dstIp],
    ] as const) {
      if (!ip || !isPrivateIpv4(ip)) continue;
      const result = attributeAt(launchesFor(accountId, ip), t);
      if (!result) continue;
      if ("ambiguous" in result) notes.push(`${label} ${ip}: ambiguous — multiple candidate instances`);
      else notes.push(`${label} ${ip} = ${result.instanceId}`);
    }
    if (notes.length === 0) return e;

    return { ...e, description: appendDerivedNote(e.description, FLOW_ATTRIBUTION_MARKER, notes.join("; ")) };
  });
}
