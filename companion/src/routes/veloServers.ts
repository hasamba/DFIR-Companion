// The Velociraptor client a route uses: the case's server set for /cases/:id/* routes, the default
// set for the case-less /velociraptor/* routes. There is no fallback from one to the other.
import type { Request, Response } from "express";
import { ServerSetUnavailableError, type ResolveResult } from "../integrations/serverSets/types.js";
import type { VelociraptorClient } from "../integrations/velociraptor/velociraptorApi.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

export interface VeloTarget {
  client: VelociraptorClient;
  /** The server set the client belongs to — it names that server's client inventory file. */
  setId: string;
  setName: string;
}

const notInSet = (setName: string): string =>
  `Velociraptor is not configured in server set '${setName}'. Add it in Settings → Server sets.`;

/** The client, or the refusal a route would send: an unresolved set (its status) or no Velociraptor (501). */
export type VeloResolution = { ok: true; vc: VeloTarget } | { ok: false; status: number; error: string };

function resolveTarget(r: ResolveResult, missing?: string): VeloResolution {
  if (!r.ok) return { ok: false, status: r.status, error: r.error };
  const client = r.servers.velociraptor;
  if (!client) return { ok: false, status: 501, error: missing ?? notInSet(r.servers.setName) };
  return { ok: true, vc: { client, setId: r.servers.setId, setName: r.servers.setName } };
}

// Sends the refusal and returns undefined, or returns the client. A set that does not resolve is a
// 409 with the resolver's reason; a set without Velociraptor is a 501 (the feature is off).
function pick(r: ResolveResult, res: Response, missing?: string): VeloTarget | undefined {
  const t = resolveTarget(r, missing);
  if (t.ok) return t.vc;
  res.status(t.status).json({ error: t.error });
  return undefined;
}

/** The case's Velociraptor without a response object (for callers that are not a route). */
export function resolveCaseVelo(ctx: RouteContext, caseId: string): VeloResolution {
  return resolveTarget(ctx.serverClients.forCase(caseId));
}

export function caseVelo(ctx: RouteContext, caseId: string, res: Response, missing?: string) {
  return pick(ctx.serverClients.forCase(caseId), res, missing);
}

export function defaultVelo(ctx: RouteContext, res: Response) {
  return pick(ctx.serverClients.forDefault(), res);
}

/**
 * For the case-less routes the dashboard calls from inside a case: the case named by `body.caseId`
 * (or `?caseId=`) uses its own set, and only a request that names no case uses the default set. A
 * named case that does not resolve is refused — never answered from the default set.
 */
export function requestVelo(ctx: RouteContext, req: Request, res: Response) {
  const raw = req.body?.caseId ?? req.query?.caseId;
  if (raw === undefined || raw === null || raw === "") return defaultVelo(ctx, res);
  const caseId = typeof raw === "string" ? raw.trim() : "";
  if (!caseId || !isValidCaseId(caseId)) {
    res.status(400).json({ error: "caseId must be a valid case id" });
    return undefined;
  }
  return caseVelo(ctx, caseId, res);
}

/**
 * For load-time reads that must not log a failed request (#2462): the named case's target, or `null`
 * when that case's set does not resolve or has no Velociraptor. The caller answers an empty 200, and
 * never consults the default set. A malformed caseId is still a 400 (sent here, returns undefined).
 */
export function namedCaseVeloOrNull(
  ctx: RouteContext,
  req: Request,
  res: Response,
): VeloTarget | null | undefined {
  const raw = req.body?.caseId ?? req.query?.caseId;
  const caseId = typeof raw === "string" ? raw.trim() : "";
  if (!caseId || !isValidCaseId(caseId)) {
    res.status(400).json({ error: "caseId must be a valid case id" });
    return undefined;
  }
  const r = ctx.serverClients.forCase(caseId);
  if (!r.ok || !r.servers.velociraptor) return null;
  return { client: r.servers.velociraptor, setId: r.servers.setId, setName: r.servers.setName };
}

/** True when the request names a case (`body.caseId` or `?caseId=`), so requestVelo resolves that case. */
export function namesCase(req: Request): boolean {
  const raw = req.body?.caseId ?? req.query?.caseId;
  return raw !== undefined && raw !== null && raw !== "";
}

/** The status for an error from a path that resolved the case itself: its 409/501, else 502. */
export function veloErrorStatus(err: unknown): number {
  return err instanceof ServerSetUnavailableError ? err.status : 502;
}
