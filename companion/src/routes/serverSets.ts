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
 *   POST   /cases/:id/server-set         case administrator: change the case's set (warn, stop, forget, relink)
 *
 * No response, log line or audit entry carries a key, a password or a Velociraptor config.
 */
import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
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

type Work = { monitors: number; irisCase?: string; hunts: number };

async function remoteWork(ctx: RouteContext, caseId: string): Promise<Work> {
  const o = ctx.options;
  const monitors = o.veloMonitorStore ? (await o.veloMonitorStore.list(caseId)).length : 0;
  const hunts = o.veloHuntStore ? (await o.veloHuntStore.list(caseId)).length : 0;
  const irisCase = o.irisExportStore ? (await o.irisExportStore.load(caseId)).caseName : "";
  return { monitors, hunts, ...(irisCase && { irisCase }) };
}

// Stops each monitor while the old set is still linked, so the release goes to the old server. A
// failure is logged (no URL, no key) and the next monitor still runs.
async function stopMonitors(ctx: RouteContext, caseId: string): Promise<number> {
  const store = ctx.options.veloMonitorStore;
  if (!store) return 0;
  let stopped = 0;
  for (const m of await store.list(caseId)) {
    try {
      await ctx.deleteVeloMonitor(caseId, m.id);
      stopped++;
    } catch (err) {
      ctx.serverLogger.error(
        `[server-sets] case ${caseId}: monitor ${m.id} could not be released on the old server: ${(err as Error).message}`,
      );
    }
  }
  return stopped;
}

function changeText(
  oldName: string,
  newName: string,
  stopped: number,
  iris: string | undefined,
  hunts: number,
) {
  const parts = [
    stopped > 0 ? `${stopped} monitors stopped` : "",
    iris ? `IRIS link '${iris}' forgotten` : "",
    hunts > 0 ? `${hunts} hunts forgotten` : "",
  ].filter(Boolean);
  return `Server set changed from '${oldName}' to '${newName}'${parts.length ? `: ${parts.join(", ")}` : ""}`;
}

async function changeCaseSet(ctx: RouteContext, sets: ServerSetStore, req: Request, res: Response) {
  const caseId = req.params.id;
  const body = (req.body ?? {}) as { setId?: unknown; confirm?: unknown };
  if (typeof body.setId !== "string" || !body.setId)
    return res.status(400).json({ error: "setId is required." });
  const target = sets.get(body.setId);
  if (!target) return res.status(404).json({ error: NOT_FOUND });
  const currentId = sets.caseSetId(caseId);
  if (currentId === target.id) return res.json({ changed: false });
  const work = await remoteWork(ctx, caseId);
  if (body.confirm !== true && (work.monitors > 0 || work.hunts > 0 || work.irisCase)) {
    return res.status(409).json({ needsConfirm: true, work });
  }
  const oldName = (currentId && sets.get(currentId)?.name) || "(none)";
  const stopped = await stopMonitors(ctx, caseId);
  await ctx.options.irisExportStore?.clear(caseId);
  const hunts = (await ctx.options.veloHuntStore?.clear(caseId)) ?? 0;
  ctx.cancelVeloHuntTimersForCase(caseId); // no old hunt id may be polled against the new server
  sets.linkCase(caseId, target.id);
  audit(ctx, req, "case-server-set-changed", target);
  await logActivity(ctx.options.activityLogStore, ctx.options.onActivity, caseId, {
    category: "settings",
    action: "server-set-changed",
    detail: changeText(oldName, target.name, stopped, work.irisCase, hunts),
    targetType: "server-set",
    targetId: target.id,
    outcome: "success",
  });
  return res.json({ changed: true, stopped, hunts, irisForgotten: !!work.irisCase });
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

  app.post(
    "/cases/:id/server-set",
    withStore(ctx, (sets, req, res) => changeCaseSet(ctx, sets, req, res)),
  );
}
