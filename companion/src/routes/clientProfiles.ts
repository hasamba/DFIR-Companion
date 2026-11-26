import type { Express, NextFunction, Request, Response } from "express";
import { z } from "zod";
import {
  applyDomains,
  applyMarks,
  archiveProfile,
  domainsInputSchema,
  editProfile,
  isArchivedProfile,
  markInputSchema,
  newProfile,
  profileInputSchema,
  unarchiveProfile,
  type ClientProfile,
} from "../analysis/clientProfile.js";
import { findLinkedCases } from "../analysis/clientProfileLinks.js";
import { parseClientCsv } from "../analysis/huntConfirmList.js";
import { currentIdentity } from "../auth/identityContext.js";
import { CLIENT_DATA_DEMO_REFUSAL } from "../auth/policy.js";
import { requestAuthentication } from "../auth/types.js";
import type { RouteContext } from "./context.js";

/**
 * Client profiles (#2670, decisions D3/D5) — instance-level, outside every case.
 *   GET  /client-profiles                    — names (+ default server set) for every signed-in user;
 *                                              archived clients left out (#2941). `?includeArchived=1`
 *                                              adds them, marked, for the administrator only.
 *   POST /client-profiles                    — create (instance administrator).
 *   GET  /client-profiles/:pid               — the full profile: baseline, versions, audit (admin).
 *   PUT  /client-profiles/:pid               — rename / default server set (admin).
 *   POST /client-profiles/:pid/archive       — archive / unarchive, all data and links kept (admin, #2941).
 *   POST /client-profiles/:pid/unarchive
 *   DELETE /client-profiles/:pid             — delete, refused (409) while any case is linked (admin, #2941).
 *   POST /client-profiles/:pid/marks         — Approved / Not allowed / Unknown marks, one version (admin).
 *   POST /client-profiles/:pid/marks/import  — the client's filled confirm-list CSV (admin).
 *   PUT  /client-profiles/:pid/domains       — blocked / approved domains and categories (admin).
 * Only GET /client-profiles is open to members (auth/policy.ts); every other route falls to the
 * administrator default. A member sees earlier-hunt data only through the cases they can open.
 * The public demo (no login) refuses every one of them, GET included.
 */
const MAX_MARKS_PER_CALL = 5000;
const MAX_CSV_BYTES = 5 * 1024 * 1024;
const sourceSchema = z.string().trim().min(1, "source is required (e.g. 'client email 2026-11-20')").max(200);

const actor = (): string => currentIdentity()?.displayName || "analyst";

const summary = (p: ClientProfile) => ({
  id: p.id,
  name: p.name,
  ...(p.defaultServerSetId ? { defaultServerSetId: p.defaultServerSetId } : {}),
  ...(isArchivedProfile(p) ? { archived: true } : {}),
});

const NOT_FOUND = "client profile not found";
const LINKED =
  "This client is linked to cases and cannot be deleted. Archive it instead: it disappears from the client lists and every linked case keeps working.";

/** True for the instance administrator, and for the one operator in single-user mode. */
function isGlobalAdmin(ctx: RouteContext, req: Request): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true;
  const auth = requestAuthentication(req) ?? teamAuth.requireSession(req);
  return !!auth && teamAuth.isGlobalAdministrator(auth);
}

/**
 * The instance activity log (#2941) — the audit log GET /auth/audit reads, which server-set deletes
 * write too. A deleted client's own trail goes with it, so this is the delete's only lasting record:
 * the server log line is written first, and a failed audit write is logged, never thrown.
 */
function instanceAudit(
  ctx: RouteContext,
  req: Request,
  action: string,
  p: Pick<ClientProfile, "id" | "name">,
) {
  ctx.serverLogger.info(
    `[client-profiles] ${action} id=${p.id} name=${JSON.stringify(p.name)} by=${actor()}`,
  );
  const auth = requestAuthentication(req);
  if (auth?.kind !== "session") return;
  try {
    ctx.options.teamAuth?.store.addAudit(auth.identity, action, p.id, undefined, `client "${p.name}"`);
  } catch (err) {
    ctx.serverLogger.error(
      `[client-profiles] audit write failed for ${action} id=${p.id}: ${(err as Error).message}`,
    );
  }
}

function firstIssue(err: z.ZodError): string {
  const i = err.issues[0];
  return i ? `${i.path.join(".") || "body"}: ${i.message}` : "invalid request";
}

/** Every profile route answers a store failure with a 500 and its message, never an unhandled rejection. */
function guarded(fn: (req: Request, res: Response) => Promise<unknown>) {
  return async (req: Request, res: Response) => {
    try {
      await fn(req, res);
    } catch (err) {
      if (!res.headersSent) res.status(500).json({ error: (err as Error).message });
    }
  };
}

export function registerClientProfileRoutes(app: Express, ctx: RouteContext): void {
  const store = () => ctx.options.clientProfileStore;
  // The public demo has no login: every profile route is refused there, GET included. The demo gate
  // (composition/httpStack.ts) refuses first; this is the second line.
  app.use(
    "/client-profiles",
    function clientProfilesDemoRefusal(_req: Request, res: Response, next: NextFunction) {
      if (ctx.options.demoMode) return res.status(403).json({ error: CLIENT_DATA_DEMO_REFUSAL, demo: true });
      return next();
    },
  );

  app.get("/client-profiles", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(200).json([]);
    const flag = String(req.query.includeArchived ?? "");
    // A member asking for archived clients still gets the active list: they never manage clients.
    const withArchived = (flag === "1" || flag === "true") && isGlobalAdmin(ctx, req);
    try {
      const list = await s.list();
      return res
        .status(200)
        .json((withArchived ? list : list.filter((p) => !isArchivedProfile(p))).map(summary));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/client-profiles", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(501).json({ error: "client profiles not configured" });
    const parsed = profileInputSchema.safeParse(req.body ?? {});
    if (!parsed.success) return res.status(400).json({ error: firstIssue(parsed.error) });
    try {
      return res.status(201).json(await s.create(newProfile(parsed.data, actor(), new Date().toISOString())));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get(
    "/client-profiles/:pid",
    guarded(async (req: Request, res: Response) => {
      const p = await store()?.get(req.params.pid);
      return p ? res.status(200).json(p) : res.status(404).json({ error: "client profile not found" });
    }),
  );

  app.put(
    "/client-profiles/:pid",
    guarded(async (req: Request, res: Response) => {
      const parsed = profileInputSchema.safeParse(req.body ?? {});
      if (!parsed.success) return res.status(400).json({ error: firstIssue(parsed.error) });
      const at = new Date().toISOString();
      const next = await store()?.update(req.params.pid, (p) => editProfile(p, parsed.data, actor(), at));
      return next ? res.status(200).json(next) : res.status(404).json({ error: NOT_FOUND });
    }),
  );

  for (const [verb, apply, action] of [
    ["archive", archiveProfile, "client-profile-archived"],
    ["unarchive", unarchiveProfile, "client-profile-unarchived"],
  ] as const) {
    app.post(
      `/client-profiles/:pid/${verb}`,
      guarded(async (req: Request, res: Response) => {
        let changed = false;
        const next = await store()?.update(req.params.pid, (p) => {
          const out = apply(p, actor(), new Date().toISOString());
          changed = out !== p;
          return out;
        });
        if (!next) return res.status(404).json({ error: NOT_FOUND });
        if (changed) instanceAudit(ctx, req, action, next);
        return res.status(200).json(summary(next));
      }),
    );
  }

  app.delete(
    "/client-profiles/:pid",
    guarded(async (req: Request, res: Response) => {
      const s = store();
      if (!s) return res.status(404).json({ error: NOT_FOUND });
      // Check and delete are one step under the client's lock; a link takes the same lock (huntClient.ts).
      const result = await s.remove(req.params.pid, async (p) => {
        const linked = await findLinkedCases(ctx.store, p.id);
        return linked.length ? linked : null;
      });
      if (result.status === "missing") return res.status(404).json({ error: NOT_FOUND });
      // Case names are data the dashboard renders as text; nothing here builds markup.
      if (result.status === "refused")
        return res.status(409).json({ error: LINKED, linkedCases: result.reason });
      instanceAudit(ctx, req, "client-profile-deleted", result.profile);
      return res.status(200).json({ deleted: result.profile.id });
    }),
  );

  app.post(
    "/client-profiles/:pid/marks",
    guarded(async (req: Request, res: Response) => {
      const body = z
        .object({
          marks: z.array(markInputSchema).min(1).max(MAX_MARKS_PER_CALL),
          source: sourceSchema,
          note: z.string().max(2000).optional(),
        })
        .safeParse(req.body ?? {});
      if (!body.success) return res.status(400).json({ error: firstIssue(body.error) });
      const meta = {
        by: actor(),
        at: new Date().toISOString(),
        source: body.data.source,
        note: body.data.note,
      };
      const next = await store()?.update(req.params.pid, (p) => applyMarks(p, body.data.marks, meta));
      return next ? res.status(200).json(next) : res.status(404).json({ error: "client profile not found" });
    }),
  );

  app.post(
    "/client-profiles/:pid/marks/import",
    guarded(async (req: Request, res: Response) => {
      const body = z
        .object({ csv: z.string().min(1).max(MAX_CSV_BYTES), source: sourceSchema })
        .safeParse(req.body ?? {});
      if (!body.success) return res.status(400).json({ error: firstIssue(body.error) });
      const { marks, skipped } = parseClientCsv(body.data.csv);
      if (!marks.length) return res.status(400).json({ error: "no row carried a verdict", skipped });
      const meta = {
        by: actor(),
        at: new Date().toISOString(),
        source: body.data.source,
        note: "client CSV import",
      };
      const next = await store()?.update(req.params.pid, (p) => applyMarks(p, marks, meta));
      return next
        ? res.status(200).json({ profile: next, imported: marks.length, skipped })
        : res.status(404).json({ error: "client profile not found" });
    }),
  );

  app.put(
    "/client-profiles/:pid/domains",
    guarded(async (req: Request, res: Response) => {
      const body = domainsInputSchema.extend({ source: sourceSchema }).safeParse(req.body ?? {});
      if (!body.success) return res.status(400).json({ error: firstIssue(body.error) });
      const meta = { by: actor(), at: new Date().toISOString(), source: body.data.source };
      const next = await store()?.update(req.params.pid, (p) => applyDomains(p, body.data, meta));
      return next ? res.status(200).json(next) : res.status(404).json({ error: "client profile not found" });
    }),
  );
}
