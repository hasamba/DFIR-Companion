import type { Express, Request, Response } from "express";
import { z } from "zod";
import {
  applyDomains,
  applyMarks,
  domainsInputSchema,
  markInputSchema,
  newProfile,
  profileInputSchema,
  type ClientProfile,
} from "../analysis/clientProfile.js";
import { parseClientCsv } from "../analysis/huntConfirmList.js";
import { currentIdentity } from "../auth/identityContext.js";
import type { RouteContext } from "./context.js";

/**
 * Client profiles (#2670, decisions D3/D5) — instance-level, outside every case.
 *   GET  /client-profiles                    — names (+ default server set) for every signed-in user.
 *   POST /client-profiles                    — create (instance administrator).
 *   GET  /client-profiles/:pid               — the full profile: baseline, versions, audit (admin).
 *   PUT  /client-profiles/:pid               — rename / default server set (admin).
 *   POST /client-profiles/:pid/marks         — Approved / Not allowed / Unknown marks, one version (admin).
 *   POST /client-profiles/:pid/marks/import  — the client's filled confirm-list CSV (admin).
 *   PUT  /client-profiles/:pid/domains       — blocked / approved domains and categories (admin).
 * Only GET /client-profiles is open to members (auth/policy.ts); every other route falls to the
 * administrator default. A member sees earlier-hunt data only through the cases they can open.
 */
const MAX_MARKS_PER_CALL = 5000;
const MAX_CSV_BYTES = 5 * 1024 * 1024;
const sourceSchema = z.string().trim().min(1, "source is required (e.g. 'client email 2026-11-20')").max(200);

const actor = (): string => currentIdentity()?.displayName || "analyst";

const summary = (p: ClientProfile) => ({
  id: p.id,
  name: p.name,
  ...(p.defaultServerSetId ? { defaultServerSetId: p.defaultServerSetId } : {}),
});

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

  app.get("/client-profiles", async (_req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(200).json([]);
    try {
      return res.status(200).json((await s.list()).map(summary));
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
      const next = await store()?.update(req.params.pid, (p) => ({
        ...p,
        name: parsed.data.name,
        defaultServerSetId: parsed.data.defaultServerSetId,
        audit: [
          ...p.audit,
          {
            at,
            by: actor(),
            action: "profile",
            detail: `renamed / server set "${parsed.data.defaultServerSetId ?? ""}"`,
            version: p.version,
          },
        ],
        updatedAt: at,
      }));
      return next ? res.status(200).json(next) : res.status(404).json({ error: "client profile not found" });
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
