// The Velociraptor client a route uses: the case's server set for /cases/:id/* routes, the default
// set for the case-less /velociraptor/* routes. There is no fallback from one to the other.
import type { Response } from "express";
import type { ResolveResult } from "../integrations/serverSets/types.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import type { RouteContext } from "./context.js";

export interface VeloTarget {
  client: VelociraptorClient;
  /** The server set the client belongs to — it names that server's client inventory file. */
  setId: string;
}

const notInSet = (setName: string): string =>
  `Velociraptor is not configured in server set '${setName}'. Add it in Settings → Server sets.`;

// Sends the refusal and returns undefined, or returns the client. A set that does not resolve is a
// 409 with the resolver's reason; a set without Velociraptor is a 501 (the feature is off).
function pick(r: ResolveResult, res: Response, missing?: string): VeloTarget | undefined {
  if (!r.ok) {
    res.status(r.status).json({ error: r.error });
    return undefined;
  }
  const client = r.servers.velociraptor;
  if (!client) {
    res.status(501).json({ error: missing ?? notInSet(r.servers.setName) });
    return undefined;
  }
  return { client, setId: r.servers.setId };
}

export function caseVelo(ctx: RouteContext, caseId: string, res: Response, missing?: string) {
  return pick(ctx.serverClients.forCase(caseId), res, missing);
}

export function defaultVelo(ctx: RouteContext, res: Response) {
  return pick(ctx.serverClients.forDefault(), res);
}

/** The case's client without sending anything — undefined when the case has none. */
export function caseVeloClient(ctx: RouteContext, caseId: string): VelociraptorClient | undefined {
  const r = ctx.serverClients.forCase(caseId);
  return r.ok ? r.servers.velociraptor : undefined;
}
