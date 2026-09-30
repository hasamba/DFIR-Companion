import { caseSqliteWorker } from "./caseSqliteWorker.js";
import type { IOC } from "./stateTypes.js";
import { getServerLogger } from "../logging/serverLogger.js";

/**
 * The IOC list as an import's baseline holds it (#1874): the ids in list order and their storage rows,
 * not the IOCs. `ids[i]` is exactly `iocs[i].id` of a full load. `objects` counts IOCs whose value is
 * an object or array (see iocsDiffFromJournal).
 */
export interface IocOutline {
  rowIds: number[];
  ids: unknown[];
  objects: number;
}

/** One stored IOC row: its storage row and its payload as a full load parses it. */
export interface IocRow {
  rowId: number;
  payload: IOC;
}

export interface DiffInputs {
  after: IocOutline;
  images: IocRow[];
  current: IocRow[];
  holders: unknown[];
}

export interface UndoInputs {
  after: IocOutline;
  images: IocRow[];
  current: IocRow[];
}

/** The journal token and fence an import baseline carries; null token = the case was empty. */
export interface IocJournalRef {
  caseId: string;
  token: string | null;
  fence?: number;
  before: IocOutline;
}

/**
 * The case database's IOC journal reads (caseSqliteWorkerIoc.ts). Each returns null when the journal
 * `token` names is no longer armed. StateStore exposes one as `iocJournal`.
 */
export class IocJournalReader {
  constructor(private readonly dbPath: (caseId: string) => string) {}

  private request<T>(op: string, ref: IocJournalRef): Promise<T | null> {
    return caseSqliteWorker.request<T | null>({
      op,
      dbPath: this.dbPath(ref.caseId),
      token: ref.token,
      fence: ref.fence,
      baselineRowIds: ref.before.rowIds,
    });
  }

  diffInputs(ref: IocJournalRef): Promise<DiffInputs | null> {
    return this.request<DiffInputs>("iocDiffInputs", ref);
  }

  undoInputs(ref: IocJournalRef): Promise<UndoInputs | null> {
    return this.request<UndoInputs>("iocUndoInputs", ref);
  }

  /** Both whole lists; for what the targeted reads cannot prove equal. Logged: it reads every IOC. */
  async fullLists(ref: IocJournalRef, reason: string): Promise<{ before: IOC[]; after: IOC[] } | null> {
    getServerLogger().info(`[import] ${ref.caseId}: reading every IOC (${reason})`, { caseId: ref.caseId });
    return this.request<{ before: IOC[]; after: IOC[] }>("iocFullLists", ref);
  }
}
