/**
 * Every WRITE under /cases/:id refuses a case that was never created (#1570).
 *
 * The companion never creates a case as a side effect: creation is a deliberate dashboard action
 * (see CaseStore.caseExists). That rule used to be enforced route by route — the import guard, the
 * Velociraptor prefix gate, an inline getCaseMeta check in the newer routes — and a route that
 * forgot it opened the per-case database for whatever id it was handed. The SQLite worker mkdirs on
 * open, so a typo'd id left casesRoot/<id>/state/investigation.db behind, under a directory with no
 * case.json that GET /cases never lists. #1549 found it on the Jev review; a probe of every write
 * route then found six more that created the directory and eight that read case state for it.
 *
 * MOUNTED ONCE, as a prefix, ahead of every /cases/:id route, so the next route is covered without
 * having to remember anything — the argument caseExistsGate.ts and caseIdGate.ts make at length.
 * It runs after caseIdGate (an unsafe id is still a 400) and caseLockGate (a locked case still asks
 * for its password first), both mounted in httpStack.
 *
 * WRITES ONLY. Reads are out of scope: the dashboard probes a few GETs (/jev/status) before a case
 * exists, and GET /state already 404s. The Velociraptor prefix keeps its own all-method gate.
 *
 * The routes it deliberately lets through, and why:
 *   - /cases/import/encrypted and /cases/seed-demo are not cases at all — Express reads "import"
 *     and "seed-demo" as the :id. Both create a NEW case, so gating them would break both.
 *   - /lock only clears this browser's unlock cookie. It is idempotent and must work after the
 *     case is gone (casePassword.ts; pinned by casePasswordRoutes.test.ts).
 *   - /push authenticates its push token BEFORE it checks the case. Answering 404 first would let
 *     a caller with no token learn which case ids exist. Its own inline check still runs.
 *   - /velociraptor/* already sits behind its own createCaseExistsGate, mounted after the AI rate
 *     limiter on purpose.
 *   - /sigma/compile and /hunt-query/validate are pure syntax checks that read no case state, and
 *     answer for any id on purpose (pinned by sigmaCompile.test.ts). They cannot touch disk.
 *
 * The 404 wording matches the import guard and the terminal CaseNotFoundError handler, so an
 * analyst reads one sentence for this mistake whichever route they hit.
 *
 * Mounted FIRST, ahead of the AI rate limiter: a write to an unknown case is refused before it can
 * count against the limit. It costs one stat and cannot reach a provider, so there is nothing
 * for the limiter to protect.
 *
 * This is a check, not a lock: a case deleted between the check and a handler's write can still
 * race. Closing that needs the store to refuse, not the router.
 */
import type { Express, Request, Response, NextFunction } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { createCaseExistsGate } from "../analysis/caseExistsGate.js";
import { isNonCasePath } from "../auth/policy.js";

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
/** Sub-paths of /cases/:id that keep their own ordering. Compared lowercased, trailing slash off. */
const OWN_ORDER_ROUTES = new Set(["/lock", "/push"]);
/** Syntax checks that never read case state. Same spelling rules as OWN_ORDER_ROUTES. */
const STATELESS_ROUTES = new Set(["/sigma/compile", "/hunt-query/validate"]);
const OWN_GATE_PREFIX = "/velociraptor";

/** Express's spelling of a path: case-insensitive, trailing slash optional. */
function normalize(path: string): string {
  return (path.length > 1 ? path.replace(/\/+$/, "") : path).toLowerCase();
}

/** True when a write to this full path is allowed to reach its route without a case.json. */
export function bypassesCaseWriteExistsGate(fullPath: string): boolean {
  if (isNonCasePath(fullPath)) return true;
  const rel = normalize(fullPath).replace(/^\/cases\/[^/]+/, "") || "/";
  if (OWN_ORDER_ROUTES.has(rel) || STATELESS_ROUTES.has(rel)) return true;
  return rel === OWN_GATE_PREFIX || rel.startsWith(`${OWN_GATE_PREFIX}/`);
}

export function mountCaseWriteExistsGate(app: Express, store: CaseStore): void {
  const exists = createCaseExistsGate(
    store,
    (caseId) => `case ${caseId} does not exist — create it in the dashboard first`,
  );
  app.use("/cases/:id", function caseWriteExistsGate(req: Request, res: Response, next: NextFunction) {
    if (READ_METHODS.has(req.method)) return next();
    if (bypassesCaseWriteExistsGate(req.baseUrl + req.path)) return next();
    return exists(req, res, next);
  });
}
