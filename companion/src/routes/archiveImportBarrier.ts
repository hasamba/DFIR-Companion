import type { NextFunction, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { admitIngest, beginArchive, CaseArchivingError } from "../analysis/caseIngestAdmission.js";

/**
 * An archive of a case and an import into it never overlap (#1903, #1920).
 *
 * Archive used to zip the case folder while imports were still merging: the zip held every raw
 * import but a half-merged state database, and with removeFromList the live case kept changing after
 * the manifest was written. The archive now REFUSES (409) rather than waits — an import stores its raw
 * evidence before it queues for the import section, so waiting would still zip unmerged evidence, and
 * an archive request should not hang for the length of a multi-minute import. It refuses while:
 *
 *   - the case's import section (analysis/importLock.ts) is held or queued;
 *   - an import or MCP JOB is queued or running for the case (an MCP run or agent writes its output,
 *     its report and its preview state in the background, after its request has answered);
 *   - any ingest holds a reservation (analysis/caseIngestAdmission.ts) — every ingest path takes one
 *     before its first evidence write, which covers the window the two checks above cannot see.
 *
 * Otherwise it marks the case (new ingest is refused or deferred while the mark is set) and builds
 * its file inside the import section. The checks, the mark and the enqueue all happen in one
 * synchronous step, so an ingest and an archive cannot both get through.
 */

type Handler = (req: Request, res: Response) => Promise<unknown>;

export function archiveBusyMessage(caseId: string): string {
  return `case ${caseId} has an import or an archive in progress — wait for it to finish, then try again`;
}

/**
 * Wraps a route that zips the whole case: 409 while an import runs, else run it inside the section.
 * `zips` says whether THIS request builds an archive: a delete with archiveFirst "none" builds none,
 * and must still be able to delete a case whose imports are running — it aborts them (#1831).
 */
export function withArchiveBarrier(
  ctx: RouteContext,
  handler: Handler,
  zips: (req: Request) => boolean = () => true,
): Handler {
  return async (req, res) => {
    if (!zips(req)) return handler(req, res);
    const caseId = String(req.params.id);
    const importRunning =
      ctx.importLock.isBusy(caseId) ||
      (ctx.options.jobManager?.hasActive(caseId, "import") ?? false) ||
      (ctx.options.jobManager?.hasActive(caseId, "mcp") ?? false);
    const endArchive = importRunning ? null : beginArchive(ctx.store.casesRoot, caseId);
    if (!endArchive) return res.status(409).json({ error: archiveBusyMessage(caseId) });
    try {
      return await ctx.importLock.runExclusive(caseId, () => handler(req, res));
    } finally {
      endArchive();
    }
  };
}

/** A delete builds an archive only when asked to archive first. */
export function deleteArchivesFirst(req: Request): boolean {
  const archiveFirst = (req.body as { archiveFirst?: unknown } | undefined)?.archiveFirst;
  return archiveFirst === "zip" || archiveFirst === "encrypted";
}

/**
 * Reserve the case for a whole write request — staging, run, ingest, report — and refuse it with a 409
 * while an archive holds the case (#1920). Mounted ahead of the MCP and external-tool routes, whose
 * requests stage files inside the case before anything reaches ingestStreamed. Reads pass through.
 */
export function reserveCaseForWrites(casesRoot: string) {
  return function caseIngestReservation(req: Request, res: Response, next: NextFunction): void {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    try {
      res.once("close", admitIngest(casesRoot, String(req.params.id)));
    } catch (err) {
      if (err instanceof CaseArchivingError) {
        res.status(409).json({ error: err.message });
        return;
      }
      return next(err);
    }
    next();
  };
}
