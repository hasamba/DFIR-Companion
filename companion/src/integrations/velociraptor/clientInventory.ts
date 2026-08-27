// The enrolled-client INVENTORY primitives (issue #70): the client-id shape, the normalized record
// the Companion persists per endpoint, and the host → record matcher the collect paths resolve
// against. Pure — no config, subprocess, or API-client dependency.

export const CLIENT_RE = /^C\.[A-Za-z0-9]+$/; // valid Velociraptor client id

// One enrolled endpoint as the Companion records it in the persisted client INVENTORY (issue #70).
export interface VeloClientRecord {
  clientId: string;
  hostname: string;
  fqdn: string;
  lastSeen?: string;
  /**
   * The Velociraptor labels on this client, if it carries any.
   *
   * OMITTED WHEN EMPTY, like lastSeen. The inventory is a snapshot of up to 100,000 clients that
   * is written to disk, and most of a fleet carries no label at all; an always-present `[]` would
   * put 100,000 empty arrays in the file to say nothing. Read it as `record.labels ?? []`.
   */
  labels?: string[];
}

// Normalize one `clients()` row → a record (or null if it has no usable client id). Casing-tolerant:
// `client_id`/`ClientId`, and `os_info.hostname`/`os_info.Hostname` (+ `fqdn`/`Fqdn`) differ across
// Velociraptor versions and depending on whether the VQL aliases the columns.
export function normalizeClientRow(row: unknown): VeloClientRecord | null {
  const r = (row ?? {}) as {
    client_id?: unknown;
    ClientId?: unknown;
    os_info?: Record<string, unknown>;
    OsInfo?: Record<string, unknown>;
    last_seen_at?: unknown;
    LastSeen?: unknown;
    labels?: unknown;
    Labels?: unknown;
  };
  const clientId = String(r.client_id ?? r.ClientId ?? "");
  if (!CLIENT_RE.test(clientId)) return null;
  const os = r.os_info ?? r.OsInfo ?? {};
  const hostname = String(os.hostname ?? os.Hostname ?? "").trim();
  const fqdn = String(os.fqdn ?? os.Fqdn ?? "").trim();
  const last = r.last_seen_at ?? r.LastSeen;
  const labels = normalizeLabels(r.labels ?? r.Labels);
  return {
    clientId,
    hostname,
    fqdn,
    ...(last != null && last !== "" ? { lastSeen: String(last) } : {}),
    ...(labels.length ? { labels } : {}),
  };
}

// A clients() `labels` cell → the trimmed, deduped, non-empty label names on that client. Anything
// that is not an array (an older server omits the column entirely) reads as no labels.
function normalizeLabels(cell: unknown): string[] {
  if (!Array.isArray(cell)) return [];
  const out: string[] = [];
  for (const raw of cell) {
    const label = String(raw ?? "").trim();
    if (label && !out.includes(label)) out.push(label);
  }
  return out;
}

// Pure: the best client record for a target host, from the inventory. Robust to the two real-world
// mismatches that make a naive `clients(search='host:<fqdn>')` miss: the client enrolled with its
// SHORT name while the case asset is an FQDN (or vice-versa). Exact full match (hostname or FQDN) wins
// over a first-label match; case-insensitive. Returns undefined when nothing matches.
export function matchClient(
  records: readonly VeloClientRecord[],
  host: string,
): VeloClientRecord | undefined {
  const target = String(host || "")
    .trim()
    .toLowerCase();
  if (!target) return undefined;
  const targetShort = target.split(".")[0];
  const valid = (records ?? []).filter((r) => r && CLIENT_RE.test(r.clientId));
  // Pass 1: exact full match on hostname or FQDN (the safest disambiguation).
  for (const r of valid) if (r.hostname.toLowerCase() === target || r.fqdn.toLowerCase() === target) return r;
  // Pass 2: first-label match either way ("WIN11" ↔ "WIN11.windomain.local").
  for (const r of valid) {
    const hn = r.hostname.toLowerCase(),
      fq = r.fqdn.toLowerCase();
    if (hn && (hn === targetShort || hn.split(".")[0] === targetShort)) return r;
    if (fq && (fq === targetShort || fq.split(".")[0] === targetShort)) return r;
  }
  return undefined;
}
