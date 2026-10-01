import type { Request, Response } from "express";
import type { RouteContext } from "./context.js";

/**
 * An archive of a case and an import into it never overlap (#1903).
 *
 * Archive used to zip the case folder while imports were still merging: the zip held every raw
 * import but a half-merged state database, and with removeFromList the live case kept changing after
 * the manifest was written. Every import path holds the case's import section (analysis/importLock.ts)
 * through its merge, so the archive takes that section too — but it REFUSES rather than waits:
 *
 *   - an import stores its raw evidence BEFORE it queues for the section, so waiting would still zip a
 *     raw import whose merge has not happened;
 *   - a queued or running import JOB counts as running even when it is between those two steps;
 *   - an archive request should not hang for the length of a multi-minute import.
 *
 * The same guard mounted ahead of every evidence-import route (importCaseGuard.ts) covers the gap
 * before an import is visible as a job or in the section: it reserves the case from before the route
 * writes anything until its response closes — by then the import has finished, or registered its
 * job, or queued for the section — and the archive refuses while any reservation is open. While the
 * archive runs, the case is marked, and that guard refuses a NEW import with a 409.
 *
 * NOT covered: ingest that does not go through those routes (Velociraptor monitors and hunt collect,
 * external ingest, MCP, /push) stores its evidence before it queues for the section, and is invisible
 * here until it does. It runs after the archive, and with removeFromList its merge is refused as a
 * late write to a moved case — but its raw file may or may not be in the zip.
 *
 * The busy check, the mark and the enqueue all happen in one synchronous step, so two requests
 * cannot both pass the check.
 */

type Handler = (req: Request, res: Response) => Promise<unknown>;

const archiving = new Set<string>();
/** Evidence-import requests between the route guard and their response closing, per case. */
const reservations = new Map<string, number>();
const keyOf = (casesRoot: string, caseId: string) => `${casesRoot}\u0000${caseId}`;

/** Holds the case against an archive until the returned release runs (idempotent). */
export function reserveImport(casesRoot: string, caseId: string): () => void {
  const key = keyOf(casesRoot, caseId);
  reservations.set(key, (reservations.get(key) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const left = (reservations.get(key) ?? 1) - 1;
    if (left > 0) reservations.set(key, left);
    else reservations.delete(key);
  };
}

/** True while an archive or export of this case is building its file. */
export function isCaseArchiving(casesRoot: string, caseId: string): boolean {
  return archiving.has(keyOf(casesRoot, caseId));
}

export function archiveBusyMessage(caseId: string): string {
  return `case ${caseId} has an import or an archive in progress — wait for it to finish, then try again`;
}

export function importWhileArchivingMessage(caseId: string): string {
  return `case ${caseId} is being archived — import again once the archive finishes`;
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
    const key = keyOf(ctx.store.casesRoot, caseId);
    const busy =
      archiving.has(key) ||
      reservations.has(key) ||
      ctx.importLock.isBusy(caseId) ||
      (ctx.options.jobManager?.hasActive(caseId, "import") ?? false);
    if (busy) return res.status(409).json({ error: archiveBusyMessage(caseId) });
    archiving.add(key);
    try {
      return await ctx.importLock.runExclusive(caseId, () => handler(req, res));
    } finally {
      archiving.delete(key);
    }
  };
}

/** A delete builds an archive only when asked to archive first. */
export function deleteArchivesFirst(req: Request): boolean {
  const archiveFirst = (req.body as { archiveFirst?: unknown } | undefined)?.archiveFirst;
  return archiveFirst === "zip" || archiveFirst === "encrypted";
}
