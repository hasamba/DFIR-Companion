// A fleet-inventory row, structurally. Deliberately NOT the Velociraptor API's VeloClientRecord:
// analysis/ may not import from integrations/, and the ledger needs only these three fields, so
// depending on the integration's type would buy an architectural violation for nothing. The real
// record satisfies this shape, and so would any other fleet source added later.
export interface FleetClient {
  clientId?: string;
  hostname?: string;
  fqdn?: string;
}

// Canonical host identity for the scope ledger. A host arrives spelled three ways — short name
// ("WS-042"), FQDN ("ws-042.corp.local") and Velociraptor client id ("C.1234") — and the ledger must
// treat them as one machine or its counts are wrong. Aliases are resolved ONLY from evidence we
// actually have (the fleet snapshot's hostname↔fqdn pairing, plus explicit analyst merges); a
// short-name/FQDN pair that nothing has linked is REPORTED as a near-duplicate rather than merged,
// because a wrong merge silently clears a compromised host. Pure — no I/O.

export interface HostAliasIndex {
  canonicalOf: Map<string, string>; // any spelling → canonical name
  aliasesOf: Map<string, Set<string>>; // canonical name → every spelling seen for it
}

export interface NearDuplicate {
  canonical: string;
  other: string;
  reason: "shortname-fqdn";
}

// Lowercase, trim, drop a trailing FQDN dot. Never strips the domain — "ws-042" and
// "ws-042.corp.local" stay distinct until something links them.
export function canonicalHostName(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.+$/, "");
}

function link(index: HostAliasIndex, alias: string, canonical: string): void {
  if (!alias || !canonical) return;
  index.canonicalOf.set(alias, canonical);
  const set = index.aliasesOf.get(canonical) ?? new Set<string>();
  set.add(alias);
  index.aliasesOf.set(canonical, set);
}

// The fleet snapshot supplies hostname↔fqdn↔clientId; analyst merges override it (they are an
// explicit human decision about identity, so they win).
export function buildHostAliasIndex(
  clients: readonly FleetClient[],
  merges: Record<string, string>,
): HostAliasIndex {
  const index: HostAliasIndex = { canonicalOf: new Map(), aliasesOf: new Map() };

  for (const client of clients) {
    const fqdn = canonicalHostName(client.fqdn ?? "");
    const hostname = canonicalHostName(client.hostname ?? "");
    const canonical = fqdn || hostname;
    if (!canonical) continue;
    link(index, canonical, canonical);
    if (hostname) link(index, hostname, canonical);
    if (client.clientId) link(index, canonicalHostName(client.clientId), canonical);
  }

  for (const [from, to] of Object.entries(merges)) {
    const source = canonicalHostName(from);
    const target = canonicalHostName(to);
    if (!source || !target) continue;
    // Re-point everything that already resolved to `source`, then the source itself.
    for (const alias of index.aliasesOf.get(source) ?? []) link(index, alias, target);
    index.aliasesOf.delete(source);
    link(index, source, target);
  }

  return index;
}

export function resolveHost(index: HostAliasIndex, raw: string): string {
  const name = canonicalHostName(raw);
  return index.canonicalOf.get(name) ?? name;
}

// A short name and an FQDN sharing a first label, which nothing has linked. Surfaced in the panel
// so the analyst can merge them deliberately.
export function findNearDuplicates(index: HostAliasIndex, seen: readonly string[]): NearDuplicate[] {
  const resolved = [...new Set(seen.map((h) => resolveHost(index, h)))];
  const out: NearDuplicate[] = [];
  for (const short of resolved) {
    if (short.includes(".")) continue;
    for (const fqdn of resolved) {
      if (!fqdn.includes(".")) continue;
      if (fqdn.split(".")[0] !== short) continue;
      out.push({ canonical: fqdn, other: short, reason: "shortname-fqdn" });
    }
  }
  return out;
}
