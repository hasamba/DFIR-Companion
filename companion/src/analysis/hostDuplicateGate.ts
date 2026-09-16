import { isIP } from "node:net";
import {
  canonicalHostName,
  findNearDuplicates,
  resolveHost,
  type HostAliasIndex,
  type NearDuplicate,
} from "./hostAlias.js";
import { dismissalKey, type HostDuplicateDismissal } from "./hostDuplicateDismissals.js";
import type { HostBindingIndex } from "./hostBinding.js";
import type { InvestigationState } from "./stateTypes.js";

// The pre-synthesis gate: one machine spelled two ways (WIN11 vs WIN11.windomain.local) is two
// hosts to every derivation the model reads, so synthesis is blocked until the analyst says which
// it is. Pure — the caller supplies the host names, the alias index and the dismissals.
//
// WHY THE PENDING LIST IS DERIVED RATHER THAN STORED. A merge already resolves both spellings to
// one canonical name through the alias index, so a merged pair stops being a near-duplicate with no
// bookkeeping. Storing the pending list too would mean a second copy of the truth that has to be
// invalidated on every merge, every import and every fleet refresh. Deriving it means a duplicate
// arriving on import 47 is treated exactly like one arriving on import 1.

/** Thrown by synthesize() when a case holds an unresolved near-duplicate host pair. The route layer
 *  turns this into HTTP 409 so the dashboard can render the merge panel. */
export class HostMergeDecisionRequired extends Error {
  constructor(public readonly pairs: NearDuplicate[]) {
    super(
      `${pairs.length} possible duplicate host${pairs.length === 1 ? "" : "s"} awaiting a merge decision`,
    );
    this.name = "HostMergeDecisionRequired";
  }
}

// The host names synthesis will actually read. The forensic timeline is the complete source: the
// super timeline is only touched AFTER the model call (the second-look sweep), so a host that lives
// only there cannot reach the prompt — and scanning it here would put a full table scan on every
// synthesis. See the design doc's "Source of truth" section.
export function hostNamesFromState(state: InvestigationState): string[] {
  const seen = new Set<string>();
  for (const e of state.forensicTimeline ?? []) {
    const asset = (e.asset ?? "").trim();
    if (asset) seen.add(asset);
  }
  return [...seen];
}

export function pendingNearDuplicates(
  hostNames: readonly string[],
  aliasIndex: HostAliasIndex,
  dismissals: readonly HostDuplicateDismissal[],
): NearDuplicate[] {
  const dismissed = new Set(dismissals.map((d) => dismissalKey(d.canonical, d.other)));
  return findNearDuplicates(aliasIndex, [...hostNames]).filter(
    (pair) => !dismissed.has(dismissalKey(pair.canonical, pair.other)),
  );
}

// A SEPARATE, NON-BLOCKING candidate list — never consumed by HostMergeDecisionRequired. A network-
// only import can leave a "host" that is literally an IP address; hostBinding.ts (#1156) can
// resolve that IP to a real machine name from a Windows sign-in record naming both. This surfaces
// that guess in the same review panel as pendingNearDuplicates, worded differently, but it must
// never hold up AI synthesis the way a name-spelling duplicate does — an IP/account match is
// weaker evidence (IPs get reassigned, a shared proxy serves many machines).
//
// IPv4-shaped host names ONLY (`isIP(...) === 4`), not IPv6. `bindingIndex.byIp` is keyed by
// hostBinding.ts's `canonicalIp()` (folds IPv4-mapped/zone-scoped/compressed IPv6 forms), while
// this function's own dismissal key and the route's `readPair()` both normalize through
// `canonicalHostName()` (plain trim+lowercase, no IPv6 folding). For a bare dotted-quad IPv4
// string the two always agree; for IPv6 they can disagree, which could let a dismissed pair
// resurface under a differently-spelled-but-equivalent IPv6 address on a later import. Scoping to
// IPv4 sidesteps that whole class of bug rather than papering over one instance of it — giving
// hostAlias.ts's canonicalization IPv6 awareness is a separate, riskier change to a
// widely-depended-on module, not this function's job.
export function pendingNetworkIdentityDuplicates(
  hostNames: readonly string[],
  aliasIndex: HostAliasIndex,
  bindingIndex: HostBindingIndex,
  dismissals: readonly HostDuplicateDismissal[],
): NearDuplicate[] {
  const dismissed = new Set(dismissals.map((d) => dismissalKey(d.canonical, d.other)));
  const seenIps = new Set<string>();
  const out: NearDuplicate[] = [];

  for (const raw of hostNames) {
    if (isIP(raw.trim()) !== 4) continue;
    // Skip anything already merged: resolveHost only differs from the trimmed/lowercased input
    // once an alias link exists, so an already-resolved IP has nothing left to suggest.
    if (resolveHost(aliasIndex, raw) !== canonicalHostName(raw)) continue;
    const ip = canonicalHostName(raw); // == canonicalIp(raw) for IPv4 — see note above
    if (seenIps.has(ip)) continue;
    seenIps.add(ip);

    const bindings = bindingIndex.byIp.get(ip);
    if (!bindings?.length) continue;
    const distinctHosts = new Set(bindings.map((b) => b.host));
    if (distinctHosts.size !== 1) continue; // ambiguous (e.g. DHCP churn) — never guess
    const [host] = distinctHosts;
    if (canonicalHostName(host) === ip) continue; // trivial: the binding names itself

    const canonical = resolveHost(aliasIndex, host);
    if (dismissed.has(dismissalKey(canonical, raw))) continue;

    const latest = bindings[bindings.length - 1]; // pre-sorted by sampleTime (buildHostBindingIndex, #1156)
    out.push({ canonical, other: raw, reason: "network-identity", sampleTime: latest.sampleTime });
  }
  return out;
}
