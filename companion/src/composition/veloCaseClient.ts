// A case's Velociraptor client, resolved from the case's server set on every use. Background loops
// (live monitors, hunt status polls, hunt collects) call this on every tick, so a set edit applies
// on the next tick and a broken link never falls back to another set.
import {
  ServerSetUnavailableError,
  type ResolveResult,
  type ServerClients,
} from "../integrations/serverSets/types.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";

// Why a resolve gave no Velociraptor client, or "" when it gave one.
function problemOf(r: ResolveResult): string {
  if (!r.ok) return r.error;
  return r.servers.velociraptor ? "" : `Server set '${r.servers.setName}' has no Velociraptor server.`;
}

/**
 * The case's client and its set id, from one resolve. Throws ServerSetUnavailableError carrying the
 * route status: 409 when the set does not resolve, 501 when it has no Velociraptor. For request paths.
 */
export function requireCaseVelo(
  serverClients: ServerClients,
  caseId: string,
): { client: VelociraptorClient; setId: string } {
  const r = serverClients.forCase(caseId);
  if (!r.ok) throw new ServerSetUnavailableError(r.error, r.status);
  if (!r.servers.velociraptor) throw new ServerSetUnavailableError(problemOf(r), 501);
  return { client: r.servers.velociraptor, setId: r.servers.setId };
}

/** The set id the case resolves to, or undefined when it does not resolve. */
export function caseSetIdOf(serverClients: ServerClients, caseId: string): string | undefined {
  const r = serverClients.forCase(caseId);
  return r.ok ? r.servers.setId : undefined;
}

/**
 * For a background pass that awaits the network: true while the case still resolves to the set it
 * had when the pass started AND the hunt is still recorded. A confirmed set change forgets the hunts,
 * so a pass whose download finished after it must not write the hunt back or re-arm it.
 */
export function huntPassCurrent(
  serverClients: () => ServerClients,
  hunts: { get(caseId: string, huntId: string): Promise<unknown> } | undefined,
  caseId: string,
  huntId: string,
): () => Promise<boolean> {
  const setId = caseSetIdOf(serverClients(), caseId);
  return async () =>
    caseSetIdOf(serverClients(), caseId) === setId && !!(await hunts?.get(caseId, huntId).catch(() => null));
}

/**
 * A per-loop resolver for background ticks. A case that does not resolve to a Velociraptor client
 * gets undefined, and its reason is logged once per case per reason text. A later success clears it,
 * so the next failure logs again.
 */
export function createTickVelo(
  serverClients: () => ServerClients,
  log: (line: string) => void,
  tag: string,
): (caseId: string) => VelociraptorClient | undefined {
  const lastProblem = new Map<string, string>();
  return (caseId) => {
    const r = serverClients().forCase(caseId);
    const problem = problemOf(r);
    if (!problem && r.ok) {
      lastProblem.delete(caseId);
      return r.servers.velociraptor;
    }
    if (lastProblem.get(caseId) !== problem) log(`[${tag}] case ${caseId} skipped: ${problem}`);
    lastProblem.set(caseId, problem);
    return undefined;
  };
}
