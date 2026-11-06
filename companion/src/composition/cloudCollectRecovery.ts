// Startup recovery of live cloud collection (#2311), run by startPostListenTasks through the #2308
// hook (integrations/cloudAccounts/collectRecovery.ts — skipped on the public demo).
//
// The job manager already marks every queued or running job interrupted when it restores its
// ledger. This step does the same for the collections' own checkpoints, so the panel shows Resume
// instead of a collection "running" in a process that is gone. Nothing is resumed here: resuming
// needs the account's credential opened again, which only the analyst's Resume press does.

import type { CaseStore } from "../storage/caseStore.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import type { CloudCollectRecoverer } from "../integrations/cloudAccounts/collectRecovery.js";
import { nodeCollectFs } from "../integrations/cloudCollect/collectFs.js";
import { markInterruptedCollections } from "../integrations/cloudCollect/collectStore.js";

export function cloudCollectStartupRecoverers(
  store: CaseStore,
  log: (line: string) => void,
): CloudCollectRecoverer[] {
  return [
    async () => {
      const now = () => new Date().toISOString();
      let marked = 0;
      for (const listed of await store.listCases()) {
        marked += await runInCaseScope(
          store.casesRoot,
          listed.caseId,
          () => markInterruptedCollections(nodeCollectFs, store.caseDir(listed.caseId), now),
          generationOf(listed),
        );
      }
      if (marked)
        log(
          `[cloud-collect] ${marked} collection(s) were running when the server stopped — ` +
            "press Resume in the Cloud collection panel to continue them",
        );
    },
  ];
}
