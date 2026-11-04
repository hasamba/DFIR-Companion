import type { RouteContext } from "./context.js";
import { logSafeError } from "../integrations/serverSets/logSafeError.js";

/** The server set a listed case uses: its id and name only, never a URL or a secret. */
export interface CaseSetRef {
  id: string;
  name: string;
}

type WithSet<T> = T & { serverSet?: CaseSetRef | null };

/**
 * Adds `serverSet` to each entry of the GET /cases list, so the dashboard's case dropdown can show
 * each case's set without one request per case. With no server set store the list is unchanged. A
 * store that cannot be read gives every case `serverSet: null` and logs one line, not one per
 * request, until the store reads again.
 */
export function createCaseListServerSets(
  ctx: RouteContext,
): <T extends { caseId: string }>(items: T[]) => Array<WithSet<T>> {
  let lastError = "";
  return <T extends { caseId: string }>(items: T[]): Array<WithSet<T>> => {
    const store = ctx.options.serverSetStore;
    if (!store) return items;
    let refs: Map<string, CaseSetRef>;
    try {
      refs = store.caseSetRefs();
      lastError = "";
    } catch (err) {
      const line = `[server-sets] the case list shows no server sets: ${logSafeError(err)}`;
      if (line !== lastError) ctx.serverLogger.error(line);
      lastError = line;
      return items.map((item) => ({ ...item, serverSet: null }));
    }
    return items.map((item) => ({ ...item, serverSet: refs.get(item.caseId) ?? null }));
  };
}
