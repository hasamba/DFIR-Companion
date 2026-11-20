// #2757: a case's AI switch is off by default, and with it off every model-calling route answers
// 409 before its handler runs. A test that exercises one of those routes turns the switch on first.
// Written straight to the store, not through POST /ai-control: turning AI on through the route also
// starts a background analysis, which would add model calls the test did not ask for. Call it before
// the app's first request for the case, because the app caches the switch.
import { AiControlStore } from "../../src/analysis/aiControl.js";
import type { CaseStore } from "../../src/storage/caseStore.js";

export async function enableCaseAi(store: CaseStore, caseId: string): Promise<void> {
  const control = new AiControlStore(store);
  await control.save(caseId, { ...(await control.load(caseId)), enabled: true });
}
