import { HuntInventoryStore } from "../analysis/huntInventoryStore.js";
import { huntSettle, type HuntSettleDeps } from "../analysis/huntSettle.js";
import { registerHuntSettle } from "../analysis/huntSettleHook.js";
import type { CaseStore } from "../storage/caseStore.js";
import { baselineGradesProvider, type BaselineGradeDeps } from "./huntBaselineGrades.js";

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
  /** Client baseline / policy / new-since-last-hunt grading (phase 5); its inventory store is ours. */
  baseline?: Omit<BaselineGradeDeps, "inventories">;
}

export interface HuntGradingWired {
  inventoryStore: HuntInventoryStore;
  /** The same grader the seam runs, for the analyst-pressed re-grade route. */
  deps: HuntSettleDeps;
}

export function wireHuntGrading(w: HuntGradingWiring): HuntGradingWired {
  const inventoryStore = new HuntInventoryStore(w.store);
  const deps: HuntSettleDeps = {
    stateStore: w.stateStore,
    inventoryStore,
    incidentTypeStore: w.incidentTypeStore,
    veloHuntStore: w.veloHuntStore,
    serverSetId: w.serverSetId,
    ...(w.baseline
      ? { extraGrades: baselineGradesProvider({ ...w.baseline, inventories: inventoryStore }) }
      : {}),
  };
  registerHuntSettle(w.stateStore, async (caseId, added) => (await huntSettle(deps, caseId, added)).changed);
  return { inventoryStore, deps };
}
