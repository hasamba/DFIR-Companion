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
import { frozenCaseRefusal } from "../routes/importCaseGuard.js";

/** Manual-evidence POST routes, relative to /cases/:id. Compared lowercased. */
const FROZEN_WHEN_CLOSED = new Set(["/events", "/iocs"]);

/**
 * Ingest POST routes outside the /import* family (#2071), relative to /cases/:id. Each one pulls
 * evidence into the case (a drop-folder tool batch, a Velociraptor hunt, external import or collect,
 * an IRIS case import) and refuses with the import routes' "before importing evidence" wording. All
 * of them are registered after this gate in routeRegistry.ts. /velociraptor/hunt-rows is left out on
 * purpose: it only reads a hunt's results, so an analyst can still review a closed case.
 */
const INGEST_FROZEN_WHEN_CLOSED = new Set([
  "/drop/run-pending",
  "/velociraptor/run-bundle",
  "/velociraptor/import-external",
  "/velociraptor/collect",
  "/iris-import",
]);

/**
 * Analyst writes that change the case's record of the investigation (#2404): undoing or redoing an
 * import, a finding's workflow or capped severity, hypotheses, the playbook, remediation and the
 * cockpit. Each had no closed/archived check, so a frozen case could still be rewritten through
 * them. `[method, path pattern]`, the pattern relative to /cases/:id and matched lowercased.
 * Reads, reopen/archive/restore/delete and exports are not listed, so a frozen case still serves
 * them. Annotations (notebook, comments, tags, pins) are a separate product call (follow-up).
 */
const CASE_CHANGES_FROZEN_WHEN_CLOSED: ReadonlyArray<readonly [string, RegExp]> = [
  ["POST", /^\/import\/(undo|redo)$/],
  ["PATCH", /^\/findings\/[^/]+\/workflow$/],
  ["POST", /^\/findings\/[^/]+\/severity-restore$/],
  ["DELETE", /^\/findings\/[^/]+\/severity-restore$/],
  ["POST", /^\/hypotheses$/],
  ["PATCH", /^\/hypotheses\/[^/]+$/],
  ["DELETE", /^\/hypotheses\/[^/]+$/],
  ["POST", /^\/playbook$/],
  ["PUT", /^\/playbook\/control$/],
  ["POST", /^\/playbook\/(sync|suggest-hunts)$/],
  ["PATCH", /^\/playbook\/[^/]+$/], // a task, and /playbook/order
  ["DELETE", /^\/playbook\/[^/]+$/],
  ["POST", /^\/remediation$/],
  ["DELETE", /^\/remediation\/[^/]+$/],
  ["POST", /^\/remediation\/[^/]+\/(verify|attach)$/],
  ["PATCH", /^\/remediation\/[^/]+\/status$/],
  ["PATCH", /^\/cockpit\/cards\/[^/]+$/],
  ["POST", /^\/cockpit\/review$/],
];

function purposeOf(method: string, rel: string): string | null {
  if (method === "POST" && FROZEN_WHEN_CLOSED.has(rel)) return "adding evidence";
  if (method === "POST" && INGEST_FROZEN_WHEN_CLOSED.has(rel)) return "importing evidence";
  const changes = CASE_CHANGES_FROZEN_WHEN_CLOSED.some(([m, re]) => m === method && re.test(rel));
  return changes ? "changing it" : null;
}

export function mountCaseWriteGuard(app: Express, store: CaseStore): void {
  app.use("/cases/:id", function caseWriteGuardGate(req: Request, res: Response, next: NextFunction) {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
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
    const purpose = purposeOf(req.method, rel);
    if (!purpose) return next();

    frozenCaseRefusal(store, req.params.id, purpose).then((refusal) => {
      if (!refusal) return next();
      res.status(423).json({ error: refusal });
    }, next);
  });
}
