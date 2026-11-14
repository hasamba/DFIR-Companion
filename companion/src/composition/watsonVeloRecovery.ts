import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import { markStrandedLaunches } from "../analysis/ai/watson/velo/launchResolve.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { WatsonFlowWatcher } from "./watsonVeloResults.js";

// Watson phase 3, at startup: a launch whose intent was saved but whose outcome never was (the
// server stopped between the two saves) is still `launching`. Mark each one `uncertain` so the
// analyst checks Velociraptor and decides — it is never re-launched on its own. Fire-and-forget;
// a case that fails is logged and skipped. A case with no stranded launch is not rewritten.
// Then (Task 5) each case's result watches resume: ended ones notify once, expired ones time out
// once, the rest are polled again.
export async function recoverWatsonLaunches(
  store: CaseStore,
  chatStore: WatsonChatStore | undefined,
  log: (line: string) => void,
  watcher?: Pick<WatsonFlowWatcher, "resume">,
): Promise<void> {
  if (!chatStore) return;
  let cases: Awaited<ReturnType<CaseStore["listCases"]>>;
  try {
    cases = await store.listCases();
  } catch (err) {
    log(`[watson] launch recovery could not list cases: ${(err as Error).message}`);
    return;
  }
  for (const listed of cases) {
    const caseId = listed.caseId;
    try {
      const sweep = () => markStrandedLaunches(chatStore, caseId);
      const n = await runInCaseScope(store.casesRoot, caseId, sweep, generationOf(listed));
      if (n) log(`[watson] ${n} interrupted Velociraptor launch(es) in ${caseId} marked uncertain`);
      if (watcher)
        await runInCaseScope(store.casesRoot, caseId, () => watcher.resume(caseId), generationOf(listed));
    } catch (err) {
      log(`[watson] launch recovery failed for ${caseId}: ${(err as Error).message}`);
    }
  }
}
