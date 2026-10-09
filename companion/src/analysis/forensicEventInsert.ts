import { caseSqliteWorker } from "./caseSqliteWorker.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { storedForm, type StateStore } from "./stateStore.js";

// #2060: adding one manual event used to load the whole case, append, re-sort by event time and
// save the whole case, all under the case lock: 12-16 s on a 58k-event case. This places the one
// row where that sort would have put it (caseSqliteWorkerRows.ts insertForensicInOrder) and patches
// updatedAt, in one transaction, so the cost no longer grows with the case.
//
// Kept out of stateStore.ts, which sits at its size limit.

type InsertStore = Pick<StateStore, "databasePath" | "loadOverview" | "save">;

async function insertRow(store: InsertStore, caseId: string, entity: ForensicEvent, updatedAt: string) {
  return caseSqliteWorker.request<boolean>({
    op: "insertForensicInOrder",
    dbPath: store.databasePath(caseId),
    entity,
    updatedAt,
  });
}

/** Insert one forensic event at its time-ordered position; the case's `updatedAt` becomes `updatedAt`. */
export async function insertForensicEventInOrder(
  store: InsertStore,
  caseId: string,
  event: ForensicEvent,
  updatedAt: string = new Date().toISOString(),
): Promise<void> {
  const entity = storedForm(event);
  if (await insertRow(store, caseId, entity, updatedAt)) return;
  // No stored state yet. Reading the overview migrates a legacy JSON case (once); a case with no
  // state at all is created holding just this row.
  const overview = await store.loadOverview(caseId);
  if (await insertRow(store, caseId, entity, updatedAt)) return;
  await store.save({ ...overview, forensicTimeline: [entity], updatedAt });
}

interface StatePushOptions {
  onStateChanged?: (caseId: string) => void;
  onState?: (state: InvestigationState) => void;
  stateStore?: Pick<StateStore, "load">;
}

/**
 * Tell the dashboards a case changed, after its lock is released: the coalesced push loads the case
 * only when a dashboard watches it (#1874). Without one, fall back to a full-state push.
 */
export function announceCaseChanged(options: StatePushOptions, caseId: string): void {
  if (options.onStateChanged) return options.onStateChanged(caseId);
  if (options.onState && options.stateStore)
    void options.stateStore.load(caseId).then(options.onState, () => undefined);
}
