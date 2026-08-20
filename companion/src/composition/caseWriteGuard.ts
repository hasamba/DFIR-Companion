/**
 * Closed/archived write guard for the MANUAL evidence routes.
 *
 * A closed case is meant to be frozen. Import, capture, custody, push, MCP, deep-pass and
 * synthesize each carry an inline `status === "closed" || "archived"` check, but the two
 * hand-authored ways in — POST /cases/:id/events and POST /cases/:id/iocs — did not. Closing a
 * case therefore froze every automated path and left the manual ones open: both returned 201,
 * persisted the record, and kicked off re-synthesis and enrichment behind it.
 *
 * MOUNTED AS A GATE rather than pasted into the two handlers, for the same reason
 * composition/aiRateLimit.ts is a gate: routes/caseLifecycle.ts and routes/threatIntel.ts are both
 * frozen by the file-size ledger, and a guard that lives here covers them without growing either.
 * It also gives the next manual-evidence route one line to opt into instead of eight to copy.
 *
 * MOUNTED PER-EXACT-PATH, not as a prefix, so it cannot swallow the sibling reads and sub-resources
 * (GET /events, POST /iocs/:iocId/enrich) that a closed case is still allowed to serve.
 *
 * REGISTRATION ORDER IS PART OF THE CONTRACT. A gate only covers what is registered after it, so
 * this must be mounted before registerThreatIntelRoutes and registerCaseLifecycleRoutes;
 * tests/architecture/routeInventory.test.ts records the interleaved layer list, and the
 * middleware's NAME and arity are what it records — hence the named `caseWriteGuardGate` below.
 */
import type { Express, Request, Response, NextFunction } from "express";
import type { CaseStore } from "../storage/caseStore.js";

/** Manual-evidence POST routes, relative to /cases/:id. Compared lowercased. */
const FROZEN_WHEN_CLOSED = new Set(["/events", "/iocs"]);

export function mountCaseWriteGuard(app: Express, store: CaseStore): void {
  app.use("/cases/:id", function caseWriteGuardGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "POST") return next();
    // Lowercased before the compare. Express routes case-insensitively, so /EVENTS reaches the same
    // handler; a case-sensitive Set lookup here would leave the guard one shift key from bypassed.
    // The optional trailing slash goes too. Express is not in "strict routing" mode, so
    // /cases/c1/events/ reaches the same handler as /cases/c1/events, while an exact Set lookup
    // does not — one keystroke past the gate.
    const rel =
      req.path
        .replace(/^\/cases\/[^/]+\//, "/")
        .replace(/\/+$/, "")
        .toLowerCase() || "/";
    if (!FROZEN_WHEN_CLOSED.has(rel)) return next();

    const caseId = req.params.id;
    void store
      .getCaseMeta(caseId)
      .catch(() => null)
      .then((meta) => {
        if (meta?.status !== "closed" && meta?.status !== "archived") return next();
        const action = meta.status === "archived" ? "restore it" : "reopen it";
        res
          .status(423)
          .json({ error: `Case "${caseId}" is ${meta.status} — ${action} before adding evidence` });
      });
  });
}
