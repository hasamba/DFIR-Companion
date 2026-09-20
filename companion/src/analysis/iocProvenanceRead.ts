// The two IOC-provenance reads behind GET /cases/:id/ioc-provenance and /ioc-provenance-chain.
//
// Each one streams the whole super-timeline through its #1444 builder (forensic first, then every
// super batch), which is ~75 s of case-SQLite-worker time on a capped 900k-row case. The dashboard
// asks for both on connect and after every `state` push, and a second dashboard asks again — so a
// request that arrives while the same case's computation is already in flight shares it (#1447).
// The slot is released when the computation settles, success or failure: the next request after
// that recomputes, because the data may have changed, and a failure is never handed to a later
// caller who did not see it.

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { classifyIocProvenance, createIocSeverityRankIndex, type IocProvenance } from "./iocProvenance.js";
import { createIocProvenanceChainBuilder, type IocProvenanceChain } from "./iocProvenanceChain.js";

export interface IocProvenanceReadStores {
  stateStore: { load(caseId: string): Promise<InvestigationState> };
  superTimelineStore: { eventBatches(caseId: string): AsyncIterable<readonly ForensicEvent[]> } | undefined;
}

export interface IocProvenanceReads {
  provenance(caseId: string): Promise<Record<string, IocProvenance>>;
  chains(caseId: string): Promise<Record<string, IocProvenanceChain>>;
}

export function createIocProvenanceReads(stores: IocProvenanceReadStores): IocProvenanceReads {
  const inFlight = {
    provenance: new Map<string, Promise<Record<string, IocProvenance>>>(),
    chains: new Map<string, Promise<Record<string, IocProvenanceChain>>>(),
  };

  function coalesced<T>(
    slots: Map<string, Promise<T>>,
    caseId: string,
    compute: () => Promise<T>,
  ): Promise<T> {
    const running = slots.get(caseId);
    if (running) return running;
    const promise = compute().finally(() => {
      if (slots.get(caseId) === promise) slots.delete(caseId);
    });
    slots.set(caseId, promise);
    return promise;
  }

  // Load the case, seed a builder from it, then feed it the forensic timeline and every super batch.
  async function scan<T>(
    caseId: string,
    seed: (state: InvestigationState) => { add(events: readonly ForensicEvent[]): void; finish(): T },
  ): Promise<T> {
    const state = await stores.stateStore.load(caseId);
    const builder = seed(state);
    builder.add(state.forensicTimeline);
    if (stores.superTimelineStore)
      for await (const batch of stores.superTimelineStore.eventBatches(caseId)) builder.add(batch);
    return builder.finish();
  }

  return {
    provenance: (caseId) =>
      coalesced(inFlight.provenance, caseId, () =>
        scan(caseId, (state) => {
          const index = createIocSeverityRankIndex(state.iocs);
          return {
            add: (events) => index.add(events),
            finish: () => classifyIocProvenance(state.iocs, index.finish()),
          };
        }),
      ),
    chains: (caseId) =>
      coalesced(inFlight.chains, caseId, () =>
        scan(caseId, (state) => createIocProvenanceChainBuilder(state.iocs, state.findings)),
      ),
  };
}
