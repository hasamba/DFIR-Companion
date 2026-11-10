import { caseMasker, type CaseMasker } from "../analysis/ai/maskRequest.js";
import { anonRevision } from "../analysis/anonRevision.js";
import { AnonControlStore } from "../analysis/anonControl.js";
import { CustomEntitiesStore } from "../analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * The Jev routes' masker (#2515): the SHARED masking step (ai/maskRequest.ts `caseMasker`), over the
 * case's own anonymization stores.
 *
 * AppOptions carries none of those stores — only the pipeline's options do — so building a masker from
 * the route options alone gave no anonymizer and sent every row in clear (#1934). These are stateless
 * file readers over the case store; the pipeline builds the same three over the same store.
 *
 * `maskedAt` is the anonymization revision read BEFORE the lists load (#1840): a request whose masked
 * body is older than the case's current revision is held, not sent.
 */
export interface JevMasking {
  readonly maskedAt: number;
  readonly masker: CaseMasker;
}

export function jevAnonStores(store: CaseStore) {
  return {
    anonStore: new AnonControlStore(store),
    customEntitiesStore: new CustomEntitiesStore(store),
    discoveredStore: new DiscoveredEntitiesStore(store),
  };
}

export async function jevMasking(
  store: CaseStore,
  caseId: string,
  state: InvestigationState,
): Promise<JevMasking> {
  const maskedAt = anonRevision(caseId);
  const masker = await caseMasker({ log: getServerLogger(), opts: jevAnonStores(store) }, caseId, state);
  return { maskedAt, masker };
}
