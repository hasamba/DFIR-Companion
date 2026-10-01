import { admitOrDefer, CaseArchivedError, statusFromStore } from "../analysis/caseIngestAdmission.js";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * A hunt collect under the case's archive admission (#1920; analysis/caseIngestAdmission.ts).
 *
 * The collect stores every artifact as evidence before it queues for the import section, so it holds
 * a reservation from its start to its diff, and an archive of the case refuses while it runs. While an
 * archive holds the case, the pass is SKIPPED, not failed — nothing was fetched or written yet — the
 * reason is logged, and the hunt's status poll is re-armed so a later pass collects it. Once the case
 * IS archived (an archive with removeFromList), the pass is skipped and NOT re-armed: nothing may land
 * in the archived folder after its zip. After a restore, "Collect now" collects the hunt.
 *
 * Split out of veloHunts.ts, which sits at the 800-line ceiling.
 */
export function createHuntCollectAdmission(
  store: Pick<CaseStore, "casesRoot" | "getCaseMeta">,
  logLine: (msg: string) => void,
  scheduleVeloHuntStatusPoll: (caseId: string, huntId: string) => void,
) {
  const statusOf = statusFromStore(store);
  return async (caseId: string, huntId: string, collect: () => Promise<void>): Promise<void> => {
    const guarded = async () => {
      if ((await statusOf(caseId)) === "archived") throw new CaseArchivedError(caseId);
      return collect();
    };
    try {
      await admitOrDefer(store.casesRoot, caseId, guarded, (why) => {
        logLine(`[velociraptor] collect of hunt ${huntId} deferred: ${why}`);
        scheduleVeloHuntStatusPoll(caseId, huntId);
      });
    } catch (err) {
      if (!(err instanceof CaseArchivedError)) throw err;
      logLine(`[velociraptor] collect of hunt ${huntId} skipped: ${err.message}`);
    }
  };
}
