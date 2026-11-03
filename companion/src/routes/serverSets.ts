/**
 * Server sets — named IRIS / Timesketch / Velociraptor bundles, and the set each case uses.
 *
 *   GET    /server-sets                  any signed-in user; admins see masked sets, others names only
 *   POST   /server-sets                  global admin: create
 *   PUT    /server-sets/:setId           global admin: edit (a masked secret keeps the stored one)
 *   DELETE /server-sets/:setId           global admin: delete an unused, non-default set
 *   POST   /server-sets/:setId/default   global admin: make it the default for new cases
 *   POST   /server-sets/:setId/test      global admin: probe each tool of THAT set
 *   GET    /cases/:id/server-set         case reader: the case's set and the tools it uses
 *
 * No response, log line or audit entry carries a key, a password or a Velociraptor config.
 */
import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import type { ServerSetStore } from "../integrations/serverSets/serverSetStore.js";
import {
  maskServerSet,
  type CaseServers,
  type ServerSet,
  type ToolName,
} from "../integrations/serverSets/types.js";
import type { RouteContext } from "./context.js";
import { parseServerSetInput, probeError } from "./serverSetBody.js";

const NOT_FOUND = "Server set not found."; // the resolver's own wording for an unknown set id
const UNAVAILABLE = "Server sets are not available.";
const IS_DEFAULT = "The default server set cannot be deleted. Make another set the default first.";
const TOOLS: ToolName[] = ["iris", "timesketch", "velociraptor"];

type Probe = { ok: boolean; error?: string };

function isGlobalAdmin(ctx: RouteContext, req: Request): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true; // single-user mode: the one operator is the administrator
  const auth = requestAuthentication(req) ?? teamAuth.requireSession(req);
  return !!auth && teamAuth.isGlobalAdministrator(auth);
}

function audit(ctx: RouteContext, req: Request, action: string, set: Pick<ServerSet, "id" | "name">): void {
  const auth = requestAuthentication(req);
  if (auth?.kind === "session") {
    ctx.options.teamAuth?.store.addAudit(auth.identity, action, set.id, undefined, set.name);
  }
  ctx.serverLogger.info(`[server-sets] ${action} id=${set.id} name=${JSON.stringify(set.name)}`);
}

// The store's own refusals are the caller's mistake (400) except an unknown id (404).
function storeError(res: Response, err: unknown): Response {
  const msg = (err as Error).message;
  if (msg === "server set not found") return res.status(404).json({ error: NOT_FOUND });
  if (/^(name |secret required|\w+ url must be)/.test(msg)) return res.status(400).json({ error: msg });
  return res.status(500).json({ error: "Server sets cannot be saved. Check the server log." });
}

/**
 * Links a new case to `setId` or, without one, to the default set. Never fails the case creation:
 * a case left unlinked gets the "no server set" message on its first server action.
 */
export function linkNewCase(
  ctx: RouteContext,
  caseId: string,
  opts: { setId?: string; keepExisting?: boolean } = {},
): void {
  const sets = ctx.options.serverSetStore;
  if (!sets) return;
  try {
    if (opts.setId) sets.linkCase(caseId, opts.setId);
    else sets.linkToDefault(caseId, { keepExisting: opts.keepExisting });
  } catch (err) {
    ctx.serverLogger.error(`[server-sets] could not link case ${caseId}: ${(err as Error).message}`);
  }
}

async function probe(run: () => Promise<unknown>): Promise<Probe> {
  try {
    await run();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: probeError(err) };
  }
}

async function testServers(servers: CaseServers): Promise<Partial<Record<ToolName, Probe>>> {
  const { iris, timesketch, velociraptor } = servers;
  const [i, t, v] = await Promise.all([
    iris ? probe(() => iris.ping()) : undefined,
    timesketch ? probe(() => timesketch.login()) : undefined,
    velociraptor ? probe(() => velociraptor.listClients()) : undefined,
  ]);
  return { ...(i && { iris: i }), ...(t && { timesketch: t }), ...(v && { velociraptor: v }) };
}

async function caseNames(ctx: RouteContext, ids: string[]): Promise<Array<{ id: string; name: string }>> {
  const metas = await ctx.store.listCases();
  const byId = new Map(metas.map((m) => [m.caseId, m.name]));
  return ids.map((id) => ({ id, name: byId.get(id) ?? id }));
}

function withStore(
  ctx: RouteContext,
  handler: (sets: ServerSetStore, req: Request, res: Response) => unknown,
) {
  return async (req: Request, res: Response) => {
    const sets = ctx.options.serverSetStore;
    if (!sets) return res.status(503).json({ error: UNAVAILABLE });
    try {
      return await handler(sets, req, res);
    } catch (err) {
      ctx.serverLogger.error(`[server-sets] ${req.method} ${req.path}: ${(err as Error).message}`);
      return res.status(500).json({ error: "Server sets cannot be read. Check the server log." });
    }
  };
}

export function registerServerSetRoutes(app: Express, ctx: RouteContext): void {
  app.get(
    "/server-sets",
    withStore(ctx, (sets, req, res) => {
      const list = sets.list();
      const defaultId = sets.defaultId();
      if (!isGlobalAdmin(ctx, req)) {
        return res.json({ defaultId, sets: list.map(({ id, name }) => ({ id, name })) });
      }
      const out = list.map((s) => ({ ...maskServerSet(s), usedBy: sets.casesUsing(s.id).length }));
      return res.json({ defaultId, sets: out });
    }),
  );

  app.post(
    "/server-sets",
    withStore(ctx, (sets, req, res) => {
      const parsed = parseServerSetInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      let made: ServerSet;
      try {
        made = sets.create(parsed.value);
      } catch (err) {
        return storeError(res, err);
      }
      audit(ctx, req, "server-set-created", made);
      return res.status(201).json(maskServerSet(made));
    }),
  );

  app.put(
    "/server-sets/:setId",
    withStore(ctx, (sets, req, res) => {
      const { setId } = req.params;
      if (!sets.get(setId)) return res.status(404).json({ error: NOT_FOUND });
      const parsed = parseServerSetInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      let saved: ServerSet;
      try {
        saved = sets.update(setId, parsed.value);
      } catch (err) {
        return storeError(res, err);
      }
      ctx.serverClients.invalidate(setId);
      audit(ctx, req, "server-set-updated", saved);
      return res.json(maskServerSet(saved));
    }),
  );

  app.delete(
    "/server-sets/:setId",
    withStore(ctx, async (sets, req, res) => {
      const set = sets.get(req.params.setId);
      if (!set) return res.status(404).json({ error: NOT_FOUND });
      const result = sets.remove(set.id);
      if (!result.ok) {
        if (result.usedBy.length === 0) return res.status(409).json({ error: IS_DEFAULT });
        // Case names are data the dashboard renders as text; nothing here builds markup.
        return res
          .status(409)
          .json({ error: "Server set is in use", usedBy: await caseNames(ctx, result.usedBy) });
      }
      ctx.serverClients.invalidate(set.id);
      audit(ctx, req, "server-set-deleted", set);
      return res.status(204).end();
    }),
  );

  app.post(
    "/server-sets/:setId/default",
    withStore(ctx, (sets, req, res) => {
      const set = sets.get(req.params.setId);
      if (!set) return res.status(404).json({ error: NOT_FOUND });
      sets.setDefault(set.id);
      ctx.serverClients.invalidate(); // default-set clients (the case-less routes) refresh
      audit(ctx, req, "server-set-default", set);
      return res.status(204).end();
    }),
  );

  app.post(
    "/server-sets/:setId/test",
    withStore(ctx, async (_sets, req, res) => {
      const r = ctx.serverClients.forSet(req.params.setId);
      if (!r.ok) return res.status(r.error === NOT_FOUND ? 404 : r.status).json({ error: r.error });
      return res.json(await testServers(r.servers));
    }),
  );

  app.get("/cases/:id/server-set", (req: Request, res: Response) => {
    const r = ctx.serverClients.forCase(req.params.id);
    if (!r.ok) return res.status(r.status).json({ error: r.error });
    const tools = TOOLS.filter((t) => r.servers[t] !== undefined);
    return res.json({ setId: r.servers.setId, name: r.servers.setName, tools });
  });
}
