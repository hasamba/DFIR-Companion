import { IocAttributionStore } from "../analysis/iocAttributionStore.js";
import type { TrustedSyncDeps } from "../analysis/trustedActivitySync.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

/**
 * The deps of the trusted-activity recompute (#2561, analysis/trustedActivitySync.ts) from what a
 * route holds: the case's IOC attribution labels, its forensic timeline (read only) and the tags
 * store. Null when there is no tags or state store: there is nothing to tag.
 */
export function trustedSyncDeps(
  options: Pick<RouteContext["options"], "stateStore" | "tagsStore" | "onTags">,
  store: Pick<CaseStore, "stateDir">,
  logLine: (message: string) => void,
): TrustedSyncDeps | null {
  const { stateStore, tagsStore } = options;
  if (!stateStore || !tagsStore) return null;
  const labels = new IocAttributionStore(store);
  return {
    loadMarks: (caseId) => labels.load(caseId),
    loadRows: async (caseId) => (await stateStore.load(caseId)).forensicTimeline,
    tags: tagsStore,
    ...(options.onTags ? { onTags: options.onTags } : {}),
    logLine,
  };
}
