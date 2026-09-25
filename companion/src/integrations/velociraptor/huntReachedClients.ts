import { CLIENT_RE } from "./clientInventory.js";
import type { HuntClientCounts } from "./huntClientCounts.js";

/**
 * Which clients a hunt actually finished on, read from Velociraptor's `hunt_flows()` (#1625).
 *
 * Velociraptor schedules a hunt on a client only when that client checks in, so hunt stats cannot see
 * a client that stayed offline. An empty hunt result speaks only for the clients whose flow finished
 * without error, so the collect records them by client id, and an empty result settles an evidence
 * class only for those hosts.
 *
 * A flow state other than FINISHED (RUNNING, WAITING, IN_PROGRESS, UNRESPONSIVE, ERROR, UNSET), or a
 * non-empty error status, means "not reached". A row whose shape is not what this reads voids the whole
 * list: coverage is then unknown, never assumed. A FINISHED row with no host name (the client was
 * deleted) cannot be attributed to a host, so it is skipped.
 */
export interface HuntReachedClient {
  clientId: string;
  hostname: string;
  fqdn: string;
  /** os_info.system — "windows", "linux", "darwin"; "" when the server did not say. */
  os: string;
}

/** The VQL for one hunt. The caller validates the hunt id before it reaches the string literal. */
export function reachedClientsVql(huntId: string): string {
  const info = "client_info(client_id=Flow.client_id).os_info";
  return (
    "SELECT Flow.client_id AS ClientId, Flow.state AS State, Flow.status AS Status, " +
    `${info}.hostname AS Hostname, ${info}.fqdn AS Fqdn, ${info}.system AS OS ` +
    `FROM hunt_flows(hunt_id='${huntId}')`
  );
}

const text = (v: unknown): string => (typeof v === "string" ? v.trim() : "");

/** hunt_flows rows → the clients the hunt finished on cleanly; undefined when the shape is unknown. */
export function parseReachedClients(rows: unknown): HuntReachedClient[] | undefined {
  if (!Array.isArray(rows)) return undefined;
  const out = new Map<string, HuntReachedClient>();
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const r = row as Record<string, unknown>;
    const clientId = text(r.ClientId);
    if (!CLIENT_RE.test(clientId) || typeof r.State !== "string") return undefined;
    if (r.Status != null && typeof r.Status !== "string") return undefined;
    if (r.State.trim().toUpperCase() !== "FINISHED" || text(r.Status)) continue;
    const hostname = text(r.Hostname);
    const fqdn = text(r.Fqdn);
    if (!hostname && !fqdn) continue;
    out.set(clientId, { clientId, hostname, fqdn, os: text(r.OS).toLowerCase() });
  }
  return [...out.values()].sort((a, b) => a.clientId.localeCompare(b.clientId));
}

/** The client surface the collect needs; structural, so this file never imports the API client. */
export interface HuntCoverageClient {
  huntStatus(huntId: string): Promise<{ state: string; expires?: string; clients?: HuntClientCounts } | null>;
  huntReachedClients?(huntId: string): Promise<HuntReachedClient[] | undefined>;
}

/**
 * The live reads a collect makes before it reads any row: the hunt's status (stopped early? client
 * counts, #1612) and the clients it finished on (#1625). Both best-effort: a failed read leaves that
 * part unknown, and unknown coverage settles nothing.
 */
export async function readHuntCoverage(
  client: HuntCoverageClient,
  huntId: string,
): Promise<{
  live: Awaited<ReturnType<HuntCoverageClient["huntStatus"]>>;
  reachedClients?: HuntReachedClient[];
}> {
  const live = await client.huntStatus(huntId).catch(() => null);
  const reachedClients = await client.huntReachedClients?.(huntId).catch(() => undefined);
  return { live, ...(reachedClients ? { reachedClients } : {}) };
}
