import type { NextFunction, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import {
  admitIngest,
  beginArchive,
  CaseArchivingError,
  hasIngestReservation,
} from "../analysis/caseIngestAdmission.js";

/** How long an archive waits for in-flight ingest before it answers 409. */
export const ARCHIVE_INGEST_WAIT_MS = 30_000;
/** The first re-check interval of the wait; each later one doubles, up to the cap. */
const ARCHIVE_INGEST_FIRST_POLL_MS = 25;
const ARCHIVE_INGEST_MAX_POLL_MS = 250;

/** The wait option when it is a finite, non-negative number (0 means "never wait"), else the default. */
export function archiveWaitMs(option: unknown): number {
  return typeof option === "number" && Number.isFinite(option) && option >= 0
    ? option
    : ARCHIVE_INGEST_WAIT_MS;
}

/** The next re-check interval: 25, 50, 100, 200, then 250 ms — never past the deadline, at least 1 ms. */
export function nextArchivePollMs(previousMs: number, remainingMs: number): number {
  const grown =
    previousMs > 0 ? Math.min(previousMs * 2, ARCHIVE_INGEST_MAX_POLL_MS) : ARCHIVE_INGEST_FIRST_POLL_MS;
  return Math.max(1, Math.min(grown, remainingMs));
}

/**
 * An archive of a case and an import into it never overlap (#1903, #1920).
 *
 * Archive used to zip the case folder while imports were still merging: the zip held every raw
 * import but a half-merged state database, and with removeFromList the live case kept changing after
 * the manifest was written. An import counts as in flight while:
 *
 *   - any ingest holds a reservation (analysis/caseIngestAdmission.ts) — every ingest path takes one
 *     before its first evidence write, which covers the window before it is a job or in the section;
 *   - the case's import section (analysis/importLock.ts) is held or queued — an import keeps it
 *     through its settle tail (demote, import meta, undo checkpoint, whitelist/NSRL/deobfuscation),
 *     well after its events are visible in the state;
 *   - an import or MCP JOB is queued or running for the case (an MCP run or agent writes its output,
 *     its report and its preview state in the background, after its request has answered).
 *
 * The archive WAITS until none of that is in flight, then — in one synchronous step — checks once
 * more, marks the case (every new ingest is refused or deferred from that moment) and queues for the
 * import section, where it builds its file. Waiting is safe because every ingest path reserves before
 * its first write, so "nothing in flight" means nothing is half-way. The case is not marked while the
 * archive waits: an ingest already running may start nested ingests of its own (a drop sweep, a tool
 * run, an MCP job each call the streamed ingest), and refusing those would fail work it already began.
 * The wait is bounded: an archive that would wait longer than the limit (a multi-minute import, a
 * long hunt collect, a steady stream of pushes) answers 409 instead of hanging. The wait re-checks with
 * a short, growing interval (25 ms up to 250 ms).
 *
 * Analysts hit the wait in practice: an import's events appear in the dashboard while its settle
 * tail still holds the section, so "import, then export at once" used to get a 409 (#1921 CI).
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
    const deadline = Date.now() + archiveWaitMs(ctx.options.archiveIngestWaitMs);
    let endArchive: (() => void) | null = null;
    let delay = 0;
    // beginArchive is null while a reservation is open or another archive holds the case.
    while (ingestInFlight(ctx, caseId) || !(endArchive = beginArchive(ctx.store.casesRoot, caseId))) {
      if (Date.now() >= deadline) return res.status(409).json({ error: archiveBusyMessage(caseId) });
      delay = nextArchivePollMs(delay, deadline - Date.now());
      await new Promise((r) => setTimeout(r, delay));
    }
    const end = endArchive;
    try {
      // The last check, the mark and the enqueue ran in this same tick: nothing can slip in between.
      return await ctx.importLock.runExclusive(caseId, () => handler(req, res));
    } finally {
      end();
    }
  };
}

function ingestInFlight(ctx: RouteContext, caseId: string): boolean {
  return (
    hasIngestReservation(ctx.store.casesRoot, caseId) ||
    ctx.importLock.isBusy(caseId) ||
    (ctx.options.jobManager?.hasActive(caseId, "import") ?? false) ||
    (ctx.options.jobManager?.hasActive(caseId, "mcp") ?? false)
  );
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
 * Which reservation shape a new route needs: see analysis/caseIngestAdmission.ts.
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
