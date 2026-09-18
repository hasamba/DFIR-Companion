// #993 (proxy -> workstation half, part of #933 item 1): "a proxy log names the proxy's client;
// an endpoint's own logs name the workstation. The chain joins them only through a shared identity
// the records establish... never by shape or by timing alone." hostBinding.ts (#1156) already
// names this issue as its own motivating case and does the identity resolution; this module is
// the join over the case's own already-merged forensic timeline.
//
// TWO INDEPENDENT IDENTITY PATHS, NEVER PICKED DOWN TO ONE. The issue named two: "the same client
// address in both" and "an authenticated user present in both". Both are resolved separately
// against hostBinding.ts's own index (byIp / byAccount) and merged only by HOST NAME on the
// result — an event matching both paths to the SAME host says so (`via` on that host names both);
// an event whose two paths disagree returns BOTH hosts, never a pick. A host reached by only one
// path is exactly as real as one reached by both; this module states which, never discards either.
//
// READ-TIME, ROUTE-LEVEL, NEVER A MERGE-TIME PASS — matches hostBinding.ts's own existing
// consumers (hostDuplicateGate.ts, hostScopeLoad.ts), both async route-driven loads over
// state.forensicTimeline, never wired into stateMerge.ts. Recomputed on every call, never
// persisted.
//
// ELIGIBILITY, ADDRESS PATH. Any event carrying `canonical.network.source.address` — not scoped
// to a #1032 web-chain envelope (`canonical.web`) alone — AND (#1265) whose writer itself stamped
// `network.source.provenance === "edge-observed"`. combinedLogImport.ts's own Squid/
// combined-access-log rows independently stamp the same field from the log's own first
// (non-forgeable) column, the same trust class as a Zeek row's own `id.orig_h` — both are the
// log-writer's own observed TCP peer, never a client-supplied header. X-Forwarded-For and a bare
// HTTP `Authorization` header stay excluded: neither is verified by the log-writer itself, so
// either is a client's claim, not the log-writer's own observation. The provenance flag is
// fail-closed: absent (any writer that predates #1265, or a future one that forgets to set it) is
// read as NOT edge-observed and nulls the ADDRESS, never the account — an event that also carries
// a scoped, eligible account still resolves via the account path alone. An event whose ONLY
// eligible identity was the address (every event predating #1265, and any address-only event
// going forward) produces no entry at all once nulled, same as an event with no address to begin
// with — see TRUST BOUNDARY below.
//
// ELIGIBILITY, ACCOUNT PATH. Scoped to `canonical.web` records ONLY — never any event that merely
// carries `canonical.account.name` (a 4624 logon, an EDR process-create, a cloud sign-in all do,
// and none of them is "a proxy log naming its client"). Within that scope, combinedLogImport.ts
// writes `account.name` from the combined-log format's OWN `%u` field — the server/proxy's own
// determination of who authenticated (HTTP Basic/NTLM/Kerberos, verified before the request was
// served) — never `%l` (ident/RFC 1413, a client-asserted claim the importer already discards).
// `%u` is therefore the same trust class as the address path's source column: the log-writer's
// own verified fact, not a header the client wrote. A Zeek/Suricata web-chain row carries no
// authenticated-user field today (canonicalWeb.ts's `web.user` is declared but unpopulated by any
// importer), so only combined-log rows are eligible here in practice — stated as a scope, not
// hardcoded to one importer, so a future importer that legitimately populates it is eligible too.
//
// EXCLUDED (both paths): exactly the set `buildHostBindingIndex` itself indexes from —
// `event.type === "logon" && event.outcome === "success"` (mirrors hostBinding.ts's own predicate
// exactly, `category` is never consulted by either side). Every such event also carries
// `network.source.address` (the field the address path reads), so without this exclusion it would
// trivially "resolve" against itself (a zero-time-diff self-match) — noise, never a real
// proxy/endpoint join. A logon event never carries `canonical.web`, so the account path excludes
// it by scope alone; the explicit check stays shared for the address path. A FAILED logon
// (outcome !== "success") is never indexed, so it is real, eligible evidence here — an attacker's
// own source IP on a rejected auth attempt is not dropped.
//
// AMBIGUITY. `resolveIpAtTime`/`resolveAccountAtTime` return every HostBinding inside the
// tolerance window with no dedup by host — the SAME workstation logging on more than once in the
// window (ordinary re-auth) must never misreport as ambiguous. Ambiguity is keyed on the count of
// DISTINCT hosts among the MERGED hits from both paths, never the raw hit count.
//
// WHAT A MATCH NEVER CLAIMS. "This event's own network.source.address matches a host-binding
// record's own IP at this time, within the declared tolerance" (or, for the account path, "...own
// authenticated account matches a host-binding record's own account, present at that host, at
// this time") — never "this is the originating workstation" as an unqualified fact. Stated
// IN-BAND on every result (`caveats`), not only in this comment, so an API consumer cannot
// over-read a bare `matched`/host name: (a) if the case's own sensor sits on the far side of a
// forward proxy, an address match could name the proxy server's own machine identity, not an
// end-user's; (b) hostBinding.ts's own documented limitation — no DHCP-lease evidence exists
// anywhere in this codebase, so an address could have been reassigned to a different host between
// the logon sample and this event; (c) a shared or reused credential (service account, kiosk
// login, another user still signed in) makes an account match no more specific than the account
// itself is — sharper evidence when the SAME line stamped it than address-only, never a
// guarantee.
//
// TRUST BOUNDARY (#1184 audited, #1265 structurally represented — NOT type-enforced: the schema
// field is optional and independent of `address`, so a writer that forgets to stamp it still
// compiles cleanly; the sweep test in tests/architecture/networkSourceProvenanceSweep.test.ts
// catches it instead — every src/analysis file with a `source: { address }` literal must be
// registered there as stamped or explicitly exempted, so an undecided new writer fails the
// suite). This module trusts `canonical.account.name` on the account path exactly as before
// (scoped to `canonical.web`, the server's own verified `%u`). The address
// path additionally requires the provenance flag above — #1184's own cross-importer audit (PR
// #1267) confirmed 12 writers plus the pre-existing Zeek/Squid pair (14 total) genuinely stamp
// their own recorder edge's observed peer. A whole-src/analysis scan during this PR (the sweep
// test) found EIGHT more real writers the audit missed — it matched the dotted-string form
// `network.source.address` and not the object-literal form most importers use: siemImport.ts
// (Windows EVTX, OS kernel-level), auditdImport.ts (kernel SOCKADDR), ecarImport.ts (EDR),
// awsFlowLogImport.ts (VPC flow), exporterFlowImport.ts (NetFlow), and the Zeek/Suricata
// dns/conn/notice/ssl/smb sensor rows (dnsWireRows, networkImport, tlsSession, smbChainRows) —
// every one traced to a sensor-, exporter- or kernel-recorded field, never a client header. Real
// total: 22 writers / 28 stamped sites; canonicalEvent.ts's own legacy-upgrade path (2 sites) is
// the one deliberate exemption (provenance unknowable). #1267's own audit found ONE writer
// (emailImport.ts's `originatingIp`, a client-supplied header) that is NOT edge-observed; that
// stamp was removed rather than marked edge-observed. A category-based reader filter was
// considered and rejected: `exchangeAuditImport.ts`/`mailboxChain.ts` (genuinely edge-observed)
// and `emailImport.ts` (forgeable) all share `category: "email"`, so category cannot separate
// them — hence a schema-carried flag, not a reader-side allowlist. See RECOMMENDATION-1265.md in
// the proposal-loop designs directory for the full record.
//
// CLOCK SKEW. hostBinding.ts explicitly declines to align for skew itself ("a caller wanting
// aligned bindings passes already-aligned events"); this module reads `state.forensicTimeline` as
// stored. The declared tolerance window absorbs ordinary skew as a side effect, never a guarantee.

import {
  buildHostBindingIndex,
  isIndexableLogon,
  resolveAccountAtTime,
  resolveIpAtTime,
  type HostBinding,
} from "./hostBinding.js";
import type { HostAliasIndex } from "./hostAlias.js";
import type { ForensicEvent } from "./stateTypes.js";

export type ProxyHostIdentityOutcome = "no-match" | "matched" | "ambiguous";
export type ProxyHostIdentityVia = "address" | "account";

const SENSOR_TOPOLOGY_CAVEAT =
  "an address match names whichever host's own logon evidence shares this event's source address " +
  "at this time — if this case's own sensor captured proxy-to-internet traffic rather than " +
  "client-to-proxy traffic, that host could be the proxy server itself, not an end-user workstation";
const DHCP_LEASE_CAVEAT =
  "no DHCP-lease evidence exists in this codebase — the address could have been reassigned to a " +
  "different host between the logon sample and this event; the tolerance window is a heuristic, never a guarantee";
const ACCOUNT_SHARING_CAVEAT =
  "an account match names whichever host's own logon evidence shows this authenticated account " +
  "present at that time — a shared or reused credential (service account, kiosk login, another " +
  "user still signed in) is not distinguishable from this evidence alone";

export interface ProxyHostIdentityMatch {
  eventId: string;
  address: string;
  account: string;
  outcome: ProxyHostIdentityOutcome;
  hosts: {
    host: string;
    sampleTime: string;
    evidenceEventIds: string[];
    via: ProxyHostIdentityVia[];
  }[];
  locators: { source: string; locator: string }[];
  toleranceMs: number;
  caveats: string[];
}

/** Every raw record on an event, aggregated rows included (#1032 folds multiple hops sharing one
 * identical chain shape into one row; each keeps its own source+locator). */
function locatorsOf(e: ForensicEvent): { source: string; locator: string }[] {
  return (e.canonical?.evidence?.rawRecords ?? []).map((r) => ({ source: r.source, locator: r.locator }));
}

// isIndexableLogon (hostBinding.ts) is exactly the set `buildHostBindingIndex` itself indexes
// from — see the module header. Shared rather than re-derived (#1188) so the two can never drift.
// The predicates aren't structurally identical: this route never checks timestamp, deliberately —
// eligibility here is "would this event be indexed", and a no-timestamp logon can't self-match
// anyway, so no separate timestamp check is needed on this side.

/** Merge one identity path's hits into the per-host accumulator, tagging which path found each. */
function mergeHits(
  byHost: Map<string, { bindings: HostBinding[]; via: Set<ProxyHostIdentityVia> }>,
  hits: readonly HostBinding[],
  via: ProxyHostIdentityVia,
): void {
  for (const hit of hits) {
    const entry = byHost.get(hit.host) ?? { bindings: [], via: new Set() };
    entry.bindings.push(hit);
    entry.via.add(via);
    byHost.set(hit.host, entry);
  }
}

export function resolveProxyHostIdentity(
  events: readonly ForensicEvent[],
  aliasIndex: HostAliasIndex,
  toleranceMs: number,
): ProxyHostIdentityMatch[] {
  const index = buildHostBindingIndex(events, aliasIndex);
  const results: ProxyHostIdentityMatch[] = [];

  for (const e of events) {
    // #1265: the address path is eligible ONLY when the writer itself stamped
    // network.source.provenance === "edge-observed" — a writer whose own recorder edge directly
    // observed this peer, never a value copied from client-supplied header/body content. Fail
    // closed: absent (every writer that predates this field, and any future writer that forgets
    // to set it) reads as NOT edge-observed. This nulls only the address, never the whole event —
    // an event can still resolve via the account path below on its own trust class.
    const source = e.canonical?.network?.source;
    const address = source?.provenance === "edge-observed" ? (source.address ?? "") : "";
    // Account path scoped to canonical.web — see the module header's ELIGIBILITY, ACCOUNT PATH.
    const account = e.canonical?.web ? (e.canonical?.account?.name ?? "") : "";
    if (!address && !account) continue;
    if (isIndexableLogon(e)) continue;

    const byHost = new Map<string, { bindings: HostBinding[]; via: Set<ProxyHostIdentityVia> }>();
    if (address) mergeHits(byHost, resolveIpAtTime(index, address, e.timestamp, toleranceMs), "address");
    if (account) mergeHits(byHost, resolveAccountAtTime(index, account, e.timestamp, toleranceMs), "account");

    const hosts = [...byHost.entries()]
      .map(([host, { bindings, via }]) => {
        const sorted = [...bindings].sort((a, b) => a.sampleTime.localeCompare(b.sampleTime));
        return {
          host,
          sampleTime: sorted[sorted.length - 1].sampleTime, // most recent across BOTH paths
          evidenceEventIds: [...new Set(bindings.map((b) => b.evidenceEventId))],
          via: [...via].sort(),
        };
      })
      .sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));

    const caveats: string[] = [];
    if (hosts.some((h) => h.via.includes("address"))) caveats.push(SENSOR_TOPOLOGY_CAVEAT, DHCP_LEASE_CAVEAT);
    if (hosts.some((h) => h.via.includes("account"))) caveats.push(ACCOUNT_SHARING_CAVEAT);

    results.push({
      eventId: e.id,
      address,
      account,
      outcome: hosts.length === 0 ? "no-match" : hosts.length === 1 ? "matched" : "ambiguous",
      hosts,
      locators: locatorsOf(e),
      toleranceMs,
      caveats,
    });
  }

  return results;
}
