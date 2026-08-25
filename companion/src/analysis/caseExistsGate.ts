import type { Request, Response, NextFunction } from "express";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * Gates a `/cases/:id/...` prefix behind "this case was actually created".
 *
 * The third of the three case gates, and the one nothing had: createCaseIdGate validates the SHAPE
 * of `:id`, createCaseLockGate calls next() for a case with no meta (there is nothing to unlock),
 * and neither asks whether the case EXISTS. Most route files check `store.caseExists` themselves —
 * routes/velociraptor.ts checked in no handler at all.
 *
 * What that cost there: the dashboard's case picker is PRE-FILLED from localStorage on a bare
 * /dashboard without connecting (see restoreCaseFromUrl), so "the field has a value" was never
 * evidence of a case, and an analyst could type any id into it. POST
 * /cases/:id/velociraptor/run-bundle then LAUNCHED A HUNT ON LIVE ENDPOINTS for it. Worse, the
 * per-case job record is written AFTER the launch and atomicWrite does no mkdir, so it failed
 * ENOENT on the missing state dir and the run answered 502 with the hunt already running in
 * Velociraptor: untracked, no collect timer, no job card, no way to collect it from the Companion
 * at all. Evidence pulled off production hosts with no case to attach it to is evidence with no
 * chain of custody.
 *
 * MOUNT IT, don't call it per route — `app.use("/cases/:id/velociraptor", createCaseExistsGate(store))`
 * above the first route of the prefix. Express's prefix matching then covers every route registered
 * after it, current and future, which is the whole argument caseIdGate.ts makes at length: a
 * per-route opt-in is easy to add to a new route and easy to forget, and forgetting is exactly how
 * this gap opened. Mount it BELOW createCaseIdGate so an unsafe `:id` is still rejected as a 400
 * before it reaches the filesystem here.
 *
 * NOT for a prefix whose routes legitimately serve a case that does not exist yet — case creation,
 * and the probes the dashboard uses to decide whether it can create one.
 */
export function createCaseExistsGate(store: CaseStore) {
  return function caseExistsGate(req: Request, res: Response, next: NextFunction): void {
    const caseId = req.params.id;
    void store
      .caseExists(caseId)
      .then((exists) => {
        if (exists) {
          next();
          return;
        }
        res.status(404).json({ error: `case "${caseId}" not found — create or connect to a case first` });
      })
      // Fail CLOSED, as caseLockGate does: caseExists resolves false for a missing case and throws
      // only on an unexpected fs error, and a gate whose whole job is to block must not default to
      // open when it cannot answer.
      .catch(() => {
        res.status(500).json({ error: "could not verify the case" });
      });
  };
}
