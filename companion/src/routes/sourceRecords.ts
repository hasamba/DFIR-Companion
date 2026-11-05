// GET /cases/:id/source-records/:group — one page of the source records an aggregated cloud event
// stands for (#2301). The event carries `sourceRecords: { group, count, refs }` with only a bounded
// sample of references; this route pages through the rest of the case's disk-backed relation
// (analysis/cloudRecordStore.ts) without loading the whole member list, however large.
//
//   ?after=<cursor from the previous page>&limit=<1..5000, default 500>
//   → { members: [{ ref, locator? }], next: <cursor> | null, total }
//
// A case-scoped GET, so it takes the case read permission like every other /cases/:id read.

import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";

const GROUP_RE = /^[A-Za-z0-9_.-]{1,64}:[a-f0-9]{24}$/;

function intParam(raw: unknown): number | undefined {
  const n = typeof raw === "string" ? Number(raw) : NaN;
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
}

export function registerSourceRecordRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  app.get("/cases/:id/source-records/:group", async (req: Request, res: Response) => {
    const store = options.cloudRecordStore;
    if (!store) return res.status(501).json({ error: "cloud record provenance not configured" });
    const group = req.params.group;
    if (!GROUP_RE.test(group)) return res.status(400).json({ error: "invalid source-record group" });
    try {
      const page = await store.pageMembers(req.params.id, group, {
        after: intParam(req.query.after),
        limit: intParam(req.query.limit),
      });
      return res.status(200).json(page);
    } catch (err) {
      ctx.serverLogger.error(`[source-records] page failed for case ${req.params.id}: ${String(err)}`);
      return res.status(500).json({ error: "could not read the source records" });
    }
  });
}
