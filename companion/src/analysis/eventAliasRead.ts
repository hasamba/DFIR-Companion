// The case's event lineage (#1715) read on its own (#2059). Every stored-case resolver used to call
// loadOverview for it, which parses every finding and IOC row to return one map that lives in the
// state's meta blob — ~300 ms per call on a large case, paid by every tag list, comment list,
// super-timeline page and hypothesis-evidence read. The worker's loadEventAliases op extracts just
// that map. stateStore.ts has no line headroom, so the adapter lives here.

import { caseSqliteWorker } from "./caseSqliteWorker.js";
import type { EventAliases } from "./eventAliases.js";
import type { EventAliasSource } from "./eventAliasLookup.js";
import type { StateStore } from "./stateStore.js";

type LineageStore = Pick<StateStore, "databasePath" | "loadOverview" | "hasForensicEventIds">;

/** The lineage alone; a case whose database holds no state yet falls back to the overview, which migrates it. */
export async function readEventAliases(
  store: LineageStore,
  caseId: string,
): Promise<EventAliases | undefined> {
  const read = await caseSqliteWorker.request<{ aliases: EventAliases | null } | null>({
    op: "loadEventAliases",
    dbPath: store.databasePath(caseId),
  });
  if (read) return read.aliases ?? undefined;
  return (await store.loadOverview(caseId)).eventAliases;
}

/** A StateStore as a resolver's EventAliasSource; undefined when there is no store. */
export function eventAliasSource(store: LineageStore | undefined): EventAliasSource | undefined {
  if (!store) return undefined;
  return {
    loadEventAliases: (caseId) => readEventAliases(store, caseId),
    hasForensicEventIds: (caseId, ids) => store.hasForensicEventIds(caseId, ids),
  };
}
