/**
 * The per-row grade mark (#2891). A row an import added carries `gradePending` from its insert, when
 * the import section armed the case (#2909, caseSqliteWorkerGrade.ts), or else from the moment the
 * import stamp is written (routes/importSettlePaged.ts, in the same row write as `importedAt` /
 * `importBatchId`) until the content tagger has really finished on it; a row reads as GRADED exactly
 * when it does not carry the mark. The next import's settle and start-up grade what is left
 * (routes/importRegrade.ts, composition/ungradedRecovery.ts).
 *
 * WHY. The settle stamps a batch, then dual-writes and tags it, then demotes case-wide. A crash between
 * the stamp and the tag, or a tagger that failed internally, used to leave untagged rows that the next
 * import's case-wide demote moved out as Info — so a row the tagger would have graded up (NTDS.dit,
 * `\Windows\Temp\*.ps1`) never reached the forensic timeline or the AI. Now:
 *   - the case-wide demote (composition/importDemote.ts) never moves a marked row, unless the caller
 *     says the tagger just finished on it;
 *   - start-up recovery (composition/ungradedRecovery.ts) finds marked rows and grades them.
 *
 * WHY THE POLARITY. "Pending" rather than "graded" keeps every row persisted before this change — and
 * every row a writer that never crosses the settle stamp produced (bulk Velociraptor, hunt summaries,
 * Watson, AI saves, sigma regrade, manual rows, promotions) — graded, with no per-case watermark: old
 * cases are grandfathered, and a writer this change does not know keeps today's behaviour.
 */
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import { SCAN_PAGE_ROWS, type ForensicRow, type ForensicRowStore } from "./forensicRows.js";
import type { ForensicEvent } from "./stateTypes.js";

/**
 * The mark's value (#2909): true — the plain content tagger grades the row; "held" — a Watson paste's
 * row, which only the HELD tagger may grade (its raises are proposals the analyst approves, so a plain
 * re-grade must never apply them). "held" wins wherever two marks meet (a fold, a stamp).
 */
export type GradeMode = true | "held";

export interface GradeMarkFields {
  /** Set at insert in an armed import section (#2909) or with the import stamp (#2891); removed once
   * the content tagger finished on this row. */
  gradePending?: GradeMode;
}

export const isGradePending = (e: GradeMarkFields): boolean =>
  e.gradePending === true || e.gradePending === "held";

/** The row waits for the HELD tagger (a Watson paste's row). */
export const isHeldGrade = (e: GradeMarkFields): boolean => e.gradePending === "held";

/** The mark a stamp writes onto `e`: the stamp's mode, but never a plain mark over a held one. */
export const stampedMode = (e: GradeMarkFields, mode: GradeMode): GradeMode =>
  e.gradePending === "held" ? "held" : mode;

/** `e` without the mark (the same object when it carries none). */
export function withoutGradePending<E extends GradeMarkFields>(e: E): E {
  if (!("gradePending" in e)) return e;
  const { gradePending: _mark, ...rest } = e;
  return rest as E;
}

/**
 * What the content tagger reports: the ids of the rows it did NOT finish on. Void means it finished on
 * every row (a test stand-in, or the held Watson tagger, which grades nothing by design).
 */
export type TagOutcome = { ungraded: readonly string[] } | void;

/** The ids of `events` the tagger finished on. */
export function gradedIdsOf(events: readonly ForensicEvent[], outcome: TagOutcome): string[] {
  const ungraded = new Set(outcome ? outcome.ungraded : []);
  return events.map((e) => e.id).filter((id) => !ungraded.has(id));
}

/** What a demote caller vouches for: the rows the tagger just finished on (they may leave). */
export interface DemoteOptions {
  graded?: ReadonlySet<string>;
}

type WorkerRow = { rowId: number; version: number; entity: ForensicEvent };

/**
 * Every forensic row that carries the mark. On the case database it is one SQL query (start-up runs it
 * for every case, so it must not page every row through JavaScript); any other row store is scanned.
 * Reads the forensic timeline only — never the super-timeline.
 */
export async function forensicGradePendingRows(
  store: ForensicRowStore & { databasePath?(caseId: string): string },
  caseId: string,
): Promise<ForensicRow[]> {
  if (typeof store.databasePath === "function") {
    const rows = await caseSqliteWorker.request<WorkerRow[]>({
      op: "forensicRowsGradePending",
      dbPath: store.databasePath(caseId),
    });
    return rows.map((r) => ({ rowId: r.rowId, version: r.version, event: upgradeForensicEvent(r.entity) }));
  }
  const ids: string[] = [];
  for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
    for (const e of page) if (isGradePending(e)) ids.push(e.id);
  return ids.length ? store.forensicRowsById(caseId, ids) : [];
}

type GradeStore = { databasePath?(caseId: string): string };

/**
 * The ids of every marked forensic row (#2909): on the case database from the partial index alone
 * (caseSqliteWorkerGrade.ts) — no payload is read, so a settle can ask on every import; any other row
 * store is scanned. Forensic timeline only.
 */
export async function forensicGradePendingIds(
  store: ForensicRowStore & GradeStore,
  caseId: string,
): Promise<string[]> {
  if (typeof store.databasePath === "function") {
    return caseSqliteWorker.request<string[]>({
      op: "forensicGradePendingIds",
      dbPath: store.databasePath(caseId),
    });
  }
  const ids: string[] = [];
  for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
    for (const e of page) if (isGradePending(e)) ids.push(e.id);
  return ids;
}

/**
 * Drop the grade arm (#2909): `token` — only that section's (its release); none — whatever arm the case
 * has (the settle's first act: nothing the settle itself inserts is an importer's row; a stale arm a
 * crash left). A store without a case database has no arm. Never throws.
 */
export async function disarmGrade(store: object, caseId: string, token?: string): Promise<void> {
  const { databasePath } = store as GradeStore;
  if (typeof databasePath !== "function") return;
  try {
    const dbPath = databasePath.call(store, caseId);
    await caseSqliteWorker.request<boolean>({ op: "disarmGrade", dbPath, token });
  } catch {
    // A stale arm only marks a row that a re-grade then grades or unmarks; start-up clears it.
  }
}

/**
 * Arm the grade mark on inserts (#2909) under the section's journal token, after the snapshot and
 * before the importer runs. A case with no database yet (its first import) gets an empty one. False
 * when it could not: the import then relies on the settle's stamp-time mark, as before.
 */
export async function armGrade(
  store: object,
  caseId: string,
  token: string,
  mode: GradeMode,
): Promise<boolean> {
  const { databasePath } = store as GradeStore;
  if (typeof databasePath !== "function") return false;
  try {
    return await caseSqliteWorker.request<boolean>({
      op: "armGrade",
      dbPath: databasePath.call(store, caseId),
      token,
      mode,
    });
  } catch {
    return false;
  }
}

/** Start-up's no-lock question: does the case carry a grade arm, or any marked row? */
export async function gradeProbe(
  store: ForensicRowStore & GradeStore,
  caseId: string,
): Promise<{ armed: boolean; marked: boolean }> {
  if (typeof store.databasePath === "function") {
    return caseSqliteWorker.request<{ armed: boolean; marked: boolean }>({
      op: "gradeProbe",
      dbPath: store.databasePath(caseId),
    });
  }
  return { armed: false, marked: (await forensicGradePendingIds(store, caseId)).length > 0 };
}
