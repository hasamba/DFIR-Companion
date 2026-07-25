import type { Request, Response, NextFunction } from "express";
import { isValidCaseId } from "../storage/caseStore.js";

/**
 * Gates every `/cases/:id/*` route behind `isValidCaseId` — CaseStore's own methods
 * (caseDir/caseExists/getCaseMeta/...) do zero sanitization, just `join(root, caseId)`, so an
 * unvalidated `:id` of e.g. `../other` resolves outside the cases root. #248 fixed this for
 * import.ts alone (a per-file `app.use`); auditing every route file for `isValidCaseId` coverage
 * found the identical gap in a dozen others (aiSynthesis, findings, threatIntel, tools,
 * velociraptor, pushNotify, reportsExport, reportVersions, tagger, playbookHunts, analysisGraph,
 * captures' evidence/count/ocr-search routes) — some of them write evidence (pushNotify's /push
 * runs the same import pipeline as the Import button) or read files (captures' /evidence/:file)
 * with the exact same unvalidated id. A per-file opt-in is exactly how that happened: it's easy to
 * add to a new route file and easy to forget. Mount ONCE via
 * `app.use('/cases/:id', createCaseIdGate())`, as early as possible (before ANY `/cases/:id/*`
 * route is registered, and before createCaseLockGate — that gate's own getCaseMeta() call is
 * itself unvalidated, so this must run first) — Express's prefix matching then covers every route
 * registered after it, current or future, with no per-route changes.
 */
export function createCaseIdGate() {
  return function caseIdGate(req: Request, res: Response, next: NextFunction): void {
    if (!isValidCaseId(req.params.id)) {
      res.status(400).json({ error: "invalid caseId" });
      return;
    }
    next();
  };
}
