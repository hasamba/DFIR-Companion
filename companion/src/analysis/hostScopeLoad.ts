import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { buildHostAliasIndex, findNearDuplicates } from "./hostAlias.js";
import { aggregateHostEvidence, overlayFindingLinks } from "./hostScopeAggregate.js";
import { buildHostScopeLedger, type HostScopeLedger } from "./hostScope.js";
import type { HostScopeStore } from "./hostScopeStore.js";
import { tacticForTechniques, type IrisTactic } from "./mitreTactics.js";
import type { ScopeWindow } from "./scope.js";
import type { AssetOverrides } from "./assetOverrides.js";
import type { VeloClientInventory } from "./velociraptorClientStore.js";

// One place that turns the case's stores into a HostScopeLedger, so the route and the report writer
// derive it identically. Everything it needs is injected, which keeps the two callers from growing
// their own subtly different versions of the same derivation.

export interface HostScopeSources {
  state: { load(caseId: string): Promise<InvestigationState> };
  superTimeline: { eventBatches(caseId: string): AsyncGenerator<ForensicEvent[]> };
  decisions: Pick<HostScopeStore, "load">;
  scope?: { load(caseId: string): Promise<ScopeWindow> };
  assetOverrides?: { load(caseId: string): Promise<AssetOverrides> };
  fleet?: { load(): Promise<VeloClientInventory> };
}

// The tactics this case has actually confirmed, from its findings' techniques. Clearance asks
// whether a host holds evidence capable of showing THESE.
export function caseTacticsOf(state: InvestigationState): IrisTactic[] {
  const tactics = new Set<IrisTactic>();
  for (const finding of state.findings) {
    const tactic = tacticForTechniques(finding.mitreTechniques ?? []);
    if (tactic) tactics.add(tactic);
  }
  return [...tactics];
}

export async function loadHostScopeLedger(
  sources: HostScopeSources,
  caseId: string,
): Promise<HostScopeLedger> {
  const state = await sources.state.load(caseId);
  const window = sources.scope ? await sources.scope.load(caseId) : { start: null, end: null };
  const overrides = sources.assetOverrides ? await sources.assetOverrides.load(caseId) : null;
  const inventory = sources.fleet ? await sources.fleet.load() : { updatedAt: "", clients: [] };

  const index = buildHostAliasIndex(inventory.clients, overrides?.merges ?? {});
  const evidence = await aggregateHostEvidence(sources.superTimeline, caseId, index);
  // The super-timeline is never synthesized, so it carries no finding links. Without this overlay a
  // host with a Critical finding against it still derives as `unknown` — see overlayFindingLinks.
  overlayFindingLinks(state.forensicTimeline, index, evidence);

  return buildHostScopeLedger({
    evidence,
    decisions: await sources.decisions.load(caseId),
    window,
    caseTactics: caseTacticsOf(state),
    clients: inventory.clients,
    fleetSnapshotAt: inventory.updatedAt,
    nearDuplicates: findNearDuplicates(index, [...evidence.keys()]),
    aliasIndex: index,
  });
}
