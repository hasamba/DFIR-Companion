/**
 * The one admission point between evidence ingest and a whole-case archive (#1903, #1920).
 *
 * Every ingest path writes its raw evidence BEFORE it queues for the case's import section
 * (analysis/importLock.ts) — evidence first, so a refusal inside the section loses nothing. So the
 * import lock alone cannot tell an archive that an ingest is in flight: between "raw file written"
 * and "queued for the section" the ingest is invisible, and a zip built then holds evidence whose
 * merge has not happened. With removeFromList that merge is then refused as a late write to a moved
 * case, and the evidence never reaches the case.
 *
 * So every ingest RESERVES the case here before its first evidence write and releases after it has
 * settled; an archive refuses while any reservation is open, and while an archive holds its mark
 * every new reservation is refused with CaseArchivingError. Both the check and the change happen in
 * one synchronous step, so an ingest and an archive cannot both get through.
 *
 * Who reserves: the HTTP evidence-import guard (routes/importCaseGuard.ts), the streamed ingest
 * behind /push, MCP, the Velociraptor monitors, external tools and the drop folder
 * (composition/importIngest.ts), the Velociraptor external hunt/flow ingest
 * (composition/veloExternalIngest.ts), the hunt collect (composition/veloHunts.ts) and the
 * drop-folder sweep (composition/dropFolder.ts).
 *
 * Process-local, keyed by cases root + case id, like every other per-case in-memory map.
 */

const archiving = new Set<string>();
const reservations = new Map<string, number>();
const keyOf = (casesRoot: string, caseId: string) => `${casesRoot}\u0000${caseId}`;

export function importWhileArchivingMessage(caseId: string): string {
  return `case ${caseId} is being archived — import again once the archive finishes`;
}

/** An ingest refused because an archive of the case is building its file. Answer it with a 409. */
export class CaseArchivingError extends Error {
  readonly httpStatus = 409;
  constructor(readonly caseId: string) {
    super(importWhileArchivingMessage(caseId));
    this.name = "CaseArchivingError";
  }
}

/** An ingest refused because the case is archived: it takes no new evidence until it is restored. */
export class CaseArchivedError extends Error {
  readonly httpStatus = 423;
  constructor(readonly caseId: string) {
    super(`case ${caseId} is archived — restore it before importing`);
    this.name = "CaseArchivedError";
  }
}

/** Reads a case's lifecycle status (CaseStore.getCaseMeta(...)?.status); undefined for no case. */
export type CaseStatusOf = (caseId: string) => Promise<string | undefined>;

/** True while an archive or export of this case is building its file. */
export function isCaseArchiving(casesRoot: string, caseId: string): boolean {
  return archiving.has(keyOf(casesRoot, caseId));
}

/** True while any ingest of this case holds a reservation. */
export function hasIngestReservation(casesRoot: string, caseId: string): boolean {
  return reservations.has(keyOf(casesRoot, caseId));
}

/**
 * Reserve the case for one ingest. Throws CaseArchivingError while an archive holds the case.
 * Returns the release, which is idempotent — call it once the ingest has settled (or failed).
 */
export function admitIngest(casesRoot: string, caseId: string): () => void {
  const key = keyOf(casesRoot, caseId);
  if (archiving.has(key)) throw new CaseArchivingError(caseId);
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

/**
 * Run one ingest under a reservation. The reservation is taken synchronously, at the call, so a
 * caller that checks something and then calls this in the same tick cannot be overtaken by an archive.
 * With `statusOf`, an ARCHIVED case is refused too (CaseArchivedError): background work that was
 * deferred while an archive with removeFromList ran must not then write into the archived folder.
 */
export function withIngestAdmission<T>(
  casesRoot: string,
  caseId: string,
  fn: () => Promise<T>,
  statusOf?: CaseStatusOf,
): Promise<T> {
  let release: () => void;
  try {
    release = admitIngest(casesRoot, caseId);
  } catch (err) {
    return Promise.reject(err instanceof Error ? err : new Error(String(err)));
  }
  return Promise.resolve()
    .then(async () => {
      if (statusOf && (await statusOf(caseId)) === "archived") throw new CaseArchivedError(caseId);
      return fn();
    })
    .finally(() => release());
}

/**
 * For background work (a timer, a sweep): run under a reservation, or — while an archive holds the
 * case — skip this pass, tell `onDeferred` why, and let the caller's own schedule try again.
 */
export async function admitOrDefer<T>(
  casesRoot: string,
  caseId: string,
  fn: () => Promise<T>,
  onDeferred: (reason: string) => void,
): Promise<T | undefined> {
  if (isCaseArchiving(casesRoot, caseId)) {
    onDeferred(importWhileArchivingMessage(caseId));
    return undefined;
  }
  return withIngestAdmission(casesRoot, caseId, fn);
}

/** The lifecycle status reader for a CaseStore-like object; a missing or unreadable case.json reads as undefined. */
export function statusFromStore(store: {
  getCaseMeta(caseId: string): Promise<{ status?: string } | null>;
}): CaseStatusOf {
  return async (caseId) => (await store.getCaseMeta(caseId).catch(() => null))?.status;
}

/**
 * Mark the case as archiving, or return null when an ingest holds a reservation or another archive
 * holds the mark. The returned function clears the mark.
 */
export function beginArchive(casesRoot: string, caseId: string): (() => void) | null {
  const key = keyOf(casesRoot, caseId);
  if (archiving.has(key) || reservations.has(key)) return null;
  archiving.add(key);
  return () => {
    archiving.delete(key);
  };
}
