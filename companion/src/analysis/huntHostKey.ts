import type { HostRenameRecord } from "./hostRenameRecord.js";
import type { VeloHuntJob } from "./veloHuntStore.js";

/**
 * Stable host identity for hunting (#2670): a host is the Velociraptor SERVER plus its CLIENT ID,
 * never its name. Names change (a rename, a re-image that keeps the agent), and two clients behind
 * different servers can share a name; a server + client id pair does neither.
 *
 * The key is resolved from the hunt's own record of which clients answered (`reachedClients`: client
 * id, hostname, fqdn), matched on the short host name the rows carry. The case's rename ledger maps a
 * former name onto the current one first, so a renamed host keeps one key. A host the hunts never
 * reported (an uploaded export) gets a NAME key, marked as such — it is never counted as an answering
 * host, because nothing proves it answered.
 */

/** The first DNS label, upper-cased — hostIdentity.shortHostName's rule (that module sits in ingest). */
export function shortHostName(name: string): string {
  return name.trim().split(".")[0].toUpperCase();
}

export interface HostKey {
  key: string;
  /** "client": server + client id, from a hunt that answered. "name": only a host name is known. */
  basis: "client" | "name";
  /** The name the analyst sees. */
  hostname: string;
}

/** `server/clientId` — the stable identity. Server "" (no server set) reads as "default". */
export function stableHostKey(serverId: string, clientId: string): string {
  return `${serverId.trim() || "default"}/${clientId.trim()}`;
}

export interface HostKeyIndex {
  byShortName: ReadonlyMap<string, HostKey>;
}

/** The answering clients of every collected hunt, by short name. A name two clients share is dropped. */
export function buildHostKeyIndex(jobs: readonly VeloHuntJob[], serverId: string): HostKeyIndex {
  const out = new Map<string, HostKey>();
  const clash = new Set<string>();
  for (const j of jobs) {
    for (const c of j.reachedClients ?? []) {
      const key = stableHostKey(serverId, c.clientId);
      for (const name of [c.hostname, c.fqdn]) {
        if (!name?.trim()) continue;
        const short = shortHostName(name);
        const seen = out.get(short);
        if (seen && seen.key !== key) clash.add(short);
        else out.set(short, { key, basis: "client", hostname: c.hostname || c.fqdn });
      }
    }
  }
  // An ambiguous short name cannot name ONE host: it falls back to a name key rather than a guess.
  for (const short of clash) out.delete(short);
  return { byShortName: out };
}

/** The current name for a former one, by the case's rename ledger (short-name compare). */
export function currentHostName(host: string, renames: readonly HostRenameRecord[] = []): string {
  const short = shortHostName(host);
  const hit = renames.find((r) => shortHostName(r.formerName) === short);
  return hit ? hit.currentName : host;
}

export function resolveHostKey(
  index: HostKeyIndex,
  host: string,
  renames: readonly HostRenameRecord[] = [],
): HostKey | null {
  if (!host?.trim()) return null;
  const current = currentHostName(host, renames);
  const known = index.byShortName.get(shortHostName(current));
  if (known) return known;
  return { key: `name/${shortHostName(current)}`, basis: "name", hostname: current };
}
