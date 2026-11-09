/**
 * The closed/archived write gate: a frozen case refuses every case-changing request (#2437).
 *
 * DENY BY DEFAULT. Every non-GET request under /cases/:id/ on a closed or archived case gets 423 with
 * the frozen-case sentence, unless composition/caseWriteAllowlist.ts lists it: reopen/archive/
 * restore/delete and the encrypted export, the case password and unlock, exports, reads sent as POST,
 * and stopping work that was already running. It used to be the other way round — an explicit list
 * of frozen routes (#2404) plus ~15 inline `closed || archived` checks — and every route nobody had
 * listed (whitelist and NSRL apply, the tagger run, second-opinion apply, super-timeline promote,
 * host merge, backup restore, ...) still rewrote a closed case. tests/server/
 * frozenCaseDenyByDefault.test.ts walks the live route stack, so a new write route is covered the day
 * it is added.
 *
 * MOUNTED FIRST among the /cases/:id routes, directly after caseWriteExistsGate (routeRegistry.ts):
 * a gate only covers what is registered after it, and the cloud, push, tool and MCP routes are
 * registered before the AI rate limiter. A refusal costs one metadata read and reaches no provider,
 * so nothing is lost by answering ahead of the limiter. The meta is read only for requests the
 * allowlist does not pass.
 *
 * A running import still finishes and is recorded (#2404): it writes from its job, not through a
 * route, so the gate never sees it. Routes that wait in a queue re-check after the wait
 * (importUndoRoutes.ts, sigmaRegrade.ts), because a case can close while they wait.
 *
 * The middleware's NAME and arity are what tests/architecture/routeInventory.test.ts records — hence
 * the named `caseWriteGuardGate` below.
 */
import type { Express, Request, Response, NextFunction } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { frozenCaseRefusal } from "../routes/importCaseGuard.js";
import { isNonCasePath } from "../auth/policy.js";
import { frozenWritePurpose } from "./caseWriteAllowlist.js";

export { frozenWritePurpose } from "./caseWriteAllowlist.js";

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function mountCaseWriteGuard(app: Express, store: CaseStore): void {
  app.use("/cases/:id", function caseWriteGuardGate(req: Request, res: Response, next: NextFunction) {
    if (READ_METHODS.has(req.method)) return next();
    // /cases/import/zip, /cases/import/encrypted and /cases/seed-demo create a NEW case; Express
    // reads "import" / "seed-demo" as the :id. Same exemption as caseWriteExistsGate.
    if (isNonCasePath(req.baseUrl + req.path)) return next();
    // Lowercased before the compare: Express routes case-insensitively, so /EVENTS reaches the same
    // handler. The optional trailing slash goes too — Express is not in strict-routing mode.
    const rel =
      req.path
        .replace(/^\/cases\/[^/]+\//, "/")
        .replace(/\/+$/, "")
        .toLowerCase() || "/";
    const purpose = frozenWritePurpose(req.method, rel);
    if (!purpose) return next();

    frozenCaseRefusal(store, req.params.id, purpose).then((refusal) => {
      if (!refusal) return next();
      res.status(423).json({ error: refusal });
    }, next);
  });
}
