import type { Express, Request, Response } from "express";
import { requestAuthentication, type AuthIdentity } from "../auth/types.js";
import type { RouteContext } from "./context.js";
import { CaseImportConflictError } from "../analysis/caseExportArchive.js";
import { forgetCaseKeyedState } from "../storage/caseKeyedState.js";

/**
 * A case id's life apart from its folder — the two ends of it.
 *
 * Both halves exist because a case id outlives the directory it names, and the codebase used to
 * assume it did not. Deleting a case removed the folder and nothing else, so the next case to
 * claim the id inherited the previous one's background jobs: the job table is keyed by case id
 * alone, and every orphan still offered a live Resume that would replay a deleted case's import
 * into the new one. The wizard made that collision easy to reach by suggesting the lowest free
 * number, which is exactly the number a delete had just freed.
 *
 * Split out of routes/caseLifecycle.ts rather than added to it: that file is under a size freeze
 * (see scripts/check-file-size.mjs), and this is a coherent seam rather than more catch-all.
 */

/**
 * The new-case wizard's suggested incident number.
 *
 * Computed server-side because the browser cannot see either input that matters: archived cases
 * (folder moved out of the active root) and retired ids (cases deleted through the app — see
 * CaseStore.retireCaseId). The old client-side "max of /cases + 1" could see neither, so it
 * reissued deleted numbers.
 *
 * NOT mounted under /cases/: every /cases/<segment> path resolves to a per-case auth policy, so it
 * would have 404'd under team auth as a case nobody can see, and it would have run the
 * caseIdGate/caseLockGate pair against an id that names no case. It is a sibling of POST /cases and
 * carries that route's policy — authenticated, since anyone who may create a case may ask what to
 * call it. See NON_CASE_PATHS in auth/policy.ts for why an exemption there was the worse option.
 *
 * Deliberately NOT filtered by teamAuth visibility, unlike GET /cases: an id is taken whether or
 * not this caller may see the case behind it, and suggesting one that is already claimed only sends
 * the user into a collision. It discloses no more than how high the year's numbering has reached.
 */
export function registerCaseIdentityRoutes(app: Express, ctx: RouteContext): void {
  const { store } = ctx;
  app.get("/api/next-case-id", async (_req: Request, res: Response) => {
    try {
      const year = new Date().getFullYear();
      const claimed = [
        ...(await store.listCases()).map((item) => item.caseId),
        ...(await store.listRetiredCaseIds()),
      ];
      const pattern = new RegExp(`^INC-${year}-(\\d+)$`);
      let highest = 0;
      for (const caseId of claimed) {
        const match = pattern.exec(caseId);
        if (match) highest = Math.max(highest, Number.parseInt(match[1], 10));
      }
      return res.status(200).json({ caseId: `INC-${year}-${String(highest + 1).padStart(3, "0")}` });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

/**
 * Clears the state that outlives a deleted case's folder. Called once the folder is actually gone.
 *
 * The jobs are the dangerous half: orphans re-attach to the next case that claims the id, and each
 * still offers a live Resume that would replay the deleted case's import into that one. Retiring
 * the id is the belt to that braces — the wizard then stops handing the number out at all.
 *
 * Each step is independently guarded and NONE of them can fail the delete. The folder is already
 * irreversibly gone by the time these run, so letting one throw would report deleted:false for a
 * case that no longer exists — telling the user their evidence is still on disk when it is not.
 * Failures are logged instead, and the steps are independent, so a failed forget still lets the id
 * be retired.
 */
export async function clearStateOutlivingCase(
  ctx: RouteContext,
  id: string,
  actor?: AuthIdentity,
): Promise<void> {
  const { store, options, serverLogger } = ctx;
  const steps: [string, () => Promise<void> | void][] = [
    ["revoke case access", () => options.teamAuth?.store.deleteCaseAccess(id, actor)],
    ["forget background jobs", () => options.jobManager?.forgetCase(id)],
    ["retire case id", () => store.retireCaseId(id)],
    // Every per-case in-memory map (capture buffers, synthesis timers and in-flight marks, deferred
    // kicks, enrichment pending, drop-scan state, …) drops the deleted case's entries, and its
    // timers are cleared: nothing of it can be analysed into, or coalesce with, a new case (#1866).
    // CaseStore.deleteCaseFolder already did this; repeated here so a delete path that bypasses
    // it still forgets (idempotent).
    ["drop in-memory case state", () => forgetCaseKeyedState(store.casesRoot, id)],
  ];
  for (const [what, run] of steps) {
    try {
      await run();
    } catch (err) {
      serverLogger.error(`[delete] case=${id} deleted, but could not ${what}: ${(err as Error).message}`);
    }
  }
}

/** The 409 for a create of an id whose deleted case still has jobs winding down (#1831). */
export function stoppingMessage(caseId: string): string {
  return `case ${caseId} was just deleted and its background jobs are still stopping — try again in a moment`;
}

/**
 * The check a whole-case import (.dfircase, ZIP) runs right before it publishes a new case under
 * `caseId` (#1831). It refuses an id whose delete is still in flight or whose deleted case still has
 * jobs winding down, then clears access rows such a case may have left behind — before the publish,
 * so a failed clear leaves nothing published. The id is free at this point, so any row is stale.
 */
export function importedCaseIdClaim(ctx: RouteContext, req: Request): (caseId: string) => void {
  return (caseId) => {
    if (ctx.store.isDeleting(caseId))
      throw new CaseImportConflictError(
        caseId,
        `case ${caseId} is being deleted — try again once the delete finishes`,
      );
    if (ctx.options.jobManager?.isStopping(caseId))
      throw new CaseImportConflictError(caseId, stoppingMessage(caseId));
    ctx.options.teamAuth?.store.deleteCaseAccess(caseId, requestAuthentication(req)?.identity);
  };
}
