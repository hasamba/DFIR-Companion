import { HuntInventoryStore } from "../analysis/huntInventoryStore.js";
import { huntSettle, type HuntSettleDeps } from "../analysis/huntSettle.js";
import { registerHuntSettle } from "../analysis/huntSettleHook.js";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * Wires hunt grading (#2670) onto the import seam for one app: builds the inventory store and
 * registers the grader against the app's case-state store (routes/importSettle.ts calls it before
 * demote). Returns the inventory store so routes and the report can read it.
 */
export interface HuntGradingWiring {
  store: Pick<CaseStore, "stateDir">;
  stateStore: HuntSettleDeps["stateStore"];
  incidentTypeStore: HuntSettleDeps["incidentTypeStore"];
  veloHuntStore: HuntSettleDeps["veloHuntStore"];
  serverSetId: (caseId: string) => string | undefined;
  extraGrades?: HuntSettleDeps["extraGrades"];
}

export function wireHuntGrading(w: HuntGradingWiring): HuntInventoryStore {
  const inventoryStore = new HuntInventoryStore(w.store);
  const deps: HuntSettleDeps = {
    stateStore: w.stateStore,
    inventoryStore,
    incidentTypeStore: w.incidentTypeStore,
    veloHuntStore: w.veloHuntStore,
    serverSetId: w.serverSetId,
    ...(w.extraGrades ? { extraGrades: w.extraGrades } : {}),
  };
  registerHuntSettle(w.stateStore, async (caseId, added) => (await huntSettle(deps, caseId, added)).changed);
  return inventoryStore;
}
