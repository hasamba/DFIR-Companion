// The two IOC-provenance reads behind GET /cases/:id/ioc-provenance and /ioc-provenance-chain.
//
// Both answer "which events name each IOC?" through the #1444 builders. With a store that exposes
// `loadOverview` + `iocProvenanceCandidates` (the real StateStore) the reads take the indexed path
// (#1452): the IOC keys and authoritative `extractedFrom` ids go to the case-SQLite worker, whose
// FTS term index hands back only the candidate rows — forensic first, then super, in the order the
// streaming path fed them — and the builders do the exact matching over those. The index yields a
// superset of the true matches, so the output is bit-for-bit the streaming result at the cost of
// the matches, not the case. A store without the two methods streams the whole super-timeline
// (~75 s of worker time on a capped 900k-row case).
//
// The dashboard asks for both on connect and after every `state` push, and a second dashboard asks
// again — so a request that arrives while the same case's computation is already in flight shares
// it (#1447). The slot is released when the computation settles, success or failure: the next
// request after that recomputes, because the data may have changed, and a failure is never handed
// to a later caller who did not see it.

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { IocProvenanceCandidates } from "./stateStore.js";
import { classifyIocProvenance, createIocSeverityRankIndex, type IocProvenance } from "./iocProvenance.js";
import { createIocProvenanceChainBuilder, type IocProvenanceChain } from "./iocProvenanceChain.js";

export interface IocProvenanceReadStores {
  stateStore: {
    load(caseId: string): Promise<InvestigationState>;
    loadOverview?(caseId: string): Promise<InvestigationState>;
    iocProvenanceCandidates?(
      caseId: string,
      keys: readonly string[],
      ids: readonly string[],
    ): Promise<IocProvenanceCandidates>;
  };
  superTimelineStore: { eventBatches(caseId: string): AsyncIterable<readonly ForensicEvent[]> } | undefined;
}

/** The lookup the worker runs: the builders' own key rule, plus every authoritative extraction id. */
export function iocCandidateLookup(iocs: InvestigationState["iocs"]): { keys: string[]; ids: string[] } {
  const keys = new Set<string>();
  const ids = new Set<string>();
  for (const ioc of iocs) {
    const key = ioc.value.trim().toLowerCase();
    if (key.length >= 3) keys.add(key);
    for (const id of ioc.extractedFrom ?? []) ids.add(id);
  }
  return { keys: [...keys], ids: [...ids] };
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

  interface Builder<T> {
    add(events: readonly ForensicEvent[]): void;
    finish(): T;
  }

  // Indexed (#1452): the overview (iocs + findings, no forensic array), then only the candidate rows.
  async function lookup<T>(
    caseId: string,
    loadOverview: (caseId: string) => Promise<InvestigationState>,
    candidatesFor: NonNullable<IocProvenanceReadStores["stateStore"]["iocProvenanceCandidates"]>,
    seed: (state: InvestigationState) => Builder<T>,
  ): Promise<T> {
    const state = await loadOverview(caseId);
    const { keys, ids } = iocCandidateLookup(state.iocs);
    const cands = await candidatesFor(caseId, keys, ids);
    const builder = seed(state);
    builder.add(cands.forensic);
    builder.add(cands.super);
    return builder.finish();
  }

  // Load the case, seed a builder from it, then feed it the forensic timeline and every super batch.
  async function scan<T>(caseId: string, seed: (state: InvestigationState) => Builder<T>): Promise<T> {
    const state = await stores.stateStore.load(caseId);
    const builder = seed(state);
    builder.add(state.forensicTimeline);
    if (stores.superTimelineStore)
      for await (const batch of stores.superTimelineStore.eventBatches(caseId)) builder.add(batch);
    return builder.finish();
  }

  function read<T>(caseId: string, seed: (state: InvestigationState) => Builder<T>): Promise<T> {
    const { stateStore } = stores;
    if (stateStore.loadOverview && stateStore.iocProvenanceCandidates) {
      return lookup(
        caseId,
        stateStore.loadOverview.bind(stateStore),
        stateStore.iocProvenanceCandidates.bind(stateStore),
        seed,
      );
    }
    return scan(caseId, seed);
  }

  return {
    provenance: (caseId) =>
      coalesced(inFlight.provenance, caseId, () =>
        read(caseId, (state) => {
          const index = createIocSeverityRankIndex(state.iocs);
          return {
            add: (events) => index.add(events),
            finish: () => classifyIocProvenance(state.iocs, index.finish()),
          };
        }),
      ),
    chains: (caseId) =>
      coalesced(inFlight.chains, caseId, () =>
        read(caseId, (state) => createIocProvenanceChainBuilder(state.iocs, state.findings)),
      ),
  };
}
