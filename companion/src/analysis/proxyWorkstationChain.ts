// #993 (proxy -> workstation half, part of #933 item 1): "a proxy log names the proxy's client;
// an endpoint's own logs name the workstation. The chain joins them only through a shared identity
// the records establish... never by shape or by timing alone." hostBinding.ts (#1156) already
// names this issue as its own motivating case and does the identity resolution; this module is
// the join over the case's own already-merged forensic timeline.
//
// READ-TIME, ROUTE-LEVEL, NEVER A MERGE-TIME PASS — matches hostBinding.ts's own existing
// consumers (hostDuplicateGate.ts, hostScopeLoad.ts), both async route-driven loads over
// state.forensicTimeline, never wired into stateMerge.ts. Recomputed on every call, never
// persisted.
//
// ELIGIBILITY. Any event carrying `canonical.network.source.address` — not scoped to a #1032
// web-chain envelope (`canonical.web`) alone. combinedLogImport.ts's own Squid/combined-access-log
// rows independently stamp the same field from the log's own first (non-forgeable) column, the
// same trust class as a Zeek row's own `id.orig_h` — both are the log-writer's own observed TCP
// peer, never a client-supplied header. A LATER, client-asserted identity (Squid's `%un`, an HTTP
// `Authorization` username, `X-Forwarded-For`) is a genuinely different trust class and is never
// read here — see the design doc's own Non-goals.
//
// EXCLUDED: the Windows 4624 logon events hostBinding.ts's OWN index is built FROM. Every such
// event also carries `network.source.address` (the field this join reads), so without this
// exclusion every logon event in the case would trivially "resolve" against itself (a zero-time-
// diff self-match) — noise, never a real proxy/endpoint join, on every single logon in the
// timeline.
//
// AMBIGUITY. `resolveIpAtTime` returns every HostBinding inside the tolerance window with no
// dedup by host — the SAME workstation logging on more than once in the window (ordinary re-auth)
// must never misreport as ambiguous. Ambiguity is keyed on the count of DISTINCT hosts among the
// hits, never the raw hit count.
//
// WHAT A MATCH NEVER CLAIMS. "This event's own network.source.address matches a host-binding
// record's own IP at this time, within the declared tolerance" — never "this is the originating
// workstation" as an unqualified fact. Two caveats this codebase cannot resolve: (a) if the case's
// own sensor sits on the far side of a forward proxy, the resolved host could be the proxy
// server's own machine identity, not an end-user's; (b) hostBinding.ts's own documented
// limitation — no DHCP-lease evidence exists anywhere in this codebase, so the IP could have been
// reassigned to a different host between the logon sample and this event, and the tolerance
// window is a heuristic proxy for "still plausibly the same lease," never a guarantee.

import { buildHostBindingIndex, resolveIpAtTime, type HostBinding } from "./hostBinding.js";
import type { HostAliasIndex } from "./hostAlias.js";
import type { ForensicEvent } from "./stateTypes.js";

export type ProxyHostIdentityOutcome = "no-match" | "matched" | "ambiguous";

export interface ProxyHostIdentityMatch {
  eventId: string;
  address: string;
  outcome: ProxyHostIdentityOutcome;
  hosts: { host: string; evidenceEventIds: string[] }[];
  locators: string[];
  toleranceMs: number;
}

/** Every raw-record locator on an event, aggregated rows included (#1032 folds multiple hops
 * sharing one identical chain shape into one row; each keeps its own locator). */
function locatorsOf(e: ForensicEvent): string[] {
  return (e.canonical?.evidence?.rawRecords ?? []).map((r) => r.locator);
}

export function resolveProxyHostIdentity(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex,
  toleranceMs: number,
): ProxyHostIdentityMatch[] {
  const index = buildHostBindingIndex(events, aliasIndex);
  const results: ProxyHostIdentityMatch[] = [];

  for (const e of events) {
    const address = e.canonical?.network?.source?.address;
    if (!address) continue;
    if (e.canonical?.event?.category === "authentication" && e.canonical?.event?.type === "logon") continue;

    const hits = resolveIpAtTime(index, address, e.timestamp, toleranceMs);
    const byHost = new Map<string, HostBinding[]>();
    for (const hit of hits) {
      const list = byHost.get(hit.host) ?? [];
      list.push(hit);
      byHost.set(hit.host, list);
    }

    const hosts = [...byHost.entries()]
      .map(([host, bindings]) => ({
        host,
        evidenceEventIds: bindings.map((b) => b.evidenceEventId),
      }))
      .sort((a, b) => a.host.localeCompare(b.host));

    results.push({
      eventId: e.id,
      address,
      outcome: hosts.length === 0 ? "no-match" : hosts.length === 1 ? "matched" : "ambiguous",
      hosts,
      locators: locatorsOf(e),
      toleranceMs,
    });
  }

  return results;
}
