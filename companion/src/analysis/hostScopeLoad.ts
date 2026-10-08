import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import {
  buildHostAliasIndex,
  hostMergesFromAssetIds,
  type HostAliasIndex,
  type NearDuplicate,
} from "./hostAlias.js";
import { buildHostBindingIndex } from "./hostBinding.js";
import type { HostDuplicateDismissal } from "./hostDuplicateDismissals.js";
import {
  hostNamesFromAssets,
  hostNamesFromState,
  pendingNearDuplicates,
  pendingNetworkIdentityDuplicates,
} from "./hostDuplicateGate.js";
import {
  aggregateHostEvidence,
  collectRawHostEvidence,
  emptyRawHostEvidence,
  foldRawHostEvidence,
  overlayFindingLinks,
  type HostEvidenceMap,
  type RawHostEvidence,
} from "./hostScopeAggregate.js";
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
  state: {
    load(caseId: string): Promise<InvestigationState>;
    /** Each distinct forensic host in the order of its first row — without reading the rows (#1874). */
    forensicHostsInOrder?(caseId: string): Promise<string[]>;
  };
  superTimeline: HostEvidenceSource;
  decisions: Pick<HostScopeStore, "load">;
  scope?: { load(caseId: string): Promise<ScopeWindow> };
  assetOverrides?: { load(caseId: string): Promise<AssetOverrides> };
  fleet?: { load(): Promise<VeloClientInventory> };
  /** Pairs the analyst ruled out. Without it the ledger lists every near-duplicate, ruled out or not. */
  dismissals?: { load(caseId: string): Promise<readonly HostDuplicateDismissal[]> };
}

export interface HostEvidenceSource {
  eventBatches(caseId: string): AsyncGenerator<ForensicEvent[]>;
  // SuperTimelineStore's scan cache (#1881); a source without it scans on every call.
  memoizeScan?<T>(
    caseId: string,
    name: string,
    reduce: (batches: AsyncIterable<ForensicEvent[]>) => Promise<T>,
    opts?: { cacheable?: (value: T) => boolean },
  ): Promise<T>;
}

const HOST_EVIDENCE_SCAN = "host-scope-evidence";

// A real case has hundreds to a few thousand host spellings. Telemetry with a new spelling or peer
// name on nearly every row would make the cached collection grow with the row count, so past this
// many spellings plus reference edges it is used once and not kept (#1881).
export const MAX_CACHED_HOST_EVIDENCE_ENTRIES = 20_000;

function smallEnoughToCache(raw: RawHostEvidence): boolean {
  let size = raw.assets.size;
  for (const names of raw.references.values()) size += names.size;
  return size <= MAX_CACHED_HOST_EVIDENCE_ENTRIES;
}

async function collectRaw(batches: AsyncIterable<ForensicEvent[]>): Promise<RawHostEvidence> {
  const raw = emptyRawHostEvidence();
  for await (const batch of batches) collectRawHostEvidence(batch, raw);
  return raw;
}

// Per-host evidence from the super-timeline. The raw per-spelling totals are cached until the rows
// change (#1881), and the alias index is applied afterwards, so a fleet refresh or an analyst merge
// never forces a rescan. The fold returns fresh sets, so the caller may mutate the result.
export async function loadHostEvidence(
  source: HostEvidenceSource,
  caseId: string,
  index: HostAliasIndex,
): Promise<HostEvidenceMap> {
  if (!source.memoizeScan) return aggregateHostEvidence(source, caseId, index);
  const raw = await source.memoizeScan(caseId, HOST_EVIDENCE_SCAN, collectRaw, {
    cacheable: smallEnoughToCache,
  });
  return foldRawHostEvidence(raw, index);
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

// Standalone alias-index loader for callers that need canonical host resolution but not the full
// ledger (e.g. playbook derivation) — same recipe loadHostScopeLedger uses below, factored out so
// both stay in sync instead of growing their own copy.
export async function loadHostAliasIndex(
  sources: Pick<HostScopeSources, "assetOverrides" | "fleet">,
  caseId: string,
): Promise<HostAliasIndex> {
  const overrides = sources.assetOverrides ? await sources.assetOverrides.load(caseId) : null;
  const inventory = sources.fleet ? await sources.fleet.load() : { updatedAt: "", clients: [] };
  return buildHostAliasIndex(inventory.clients, hostMergesFromAssetIds(overrides?.merges ?? {}));
}

/**
 * THE host list every duplicate check reads: the gate before synthesis, the merge panel, the cockpit
 * card, the status pill and the Scope & Clearance banner. The forensic timeline's hosts, plus every
 * host the super-timeline names (a short `host-a` seen in `WorkstationName=HOST-A` while the rows carry
 * `host-a.corp.example.com`). The gate used to read only the forensic hosts, so the banner showed five
 * pairs and synthesis ran straight through them.
 *
 * Only NAMES come from the super-timeline, through the cached host scan (#1881). No event text
 * reaches a prompt, so the forensic / super-timeline boundary holds. `superTimeline` is optional so
 * a caller without that store keeps the forensic-only list it always had.
 */
export async function loadDuplicateCheckHostNames(
  sources: Pick<HostScopeSources, "state"> & { superTimeline?: HostEvidenceSource },
  caseId: string,
  index: HostAliasIndex,
): Promise<string[]> {
  const forensic = sources.state.forensicHostsInOrder
    ? await sources.state.forensicHostsInOrder(caseId).then(hostNamesFromAssets)
    : await sources.state.load(caseId).then(hostNamesFromState);
  const seen = sources.superTimeline
    ? [...(await loadHostEvidence(sources.superTimeline, caseId, index)).keys()]
    : [];
  return hostNamesFromAssets([...forensic, ...seen]);
}

/**
 * The pairs still awaiting a merge decision, loaded from the case's stores.
 *
 * The pure derivation lives in hostDuplicateGate.ts; this is the store recipe that feeds it, and it
 * is here for the same reason loadHostAliasIndex is — THREE callers now need the same answer (the
 * host-duplicates route, the import-time notification, and the Now cockpit's blocker card), and
 * three hand-rolled copies of "load state, load alias index, load dismissals" is exactly how they
 * drift into disagreeing about whether a case is held.
 *
 * `dismissals` is required, not optional: without it every dismissed pair reads as pending again,
 * which would resurrect a decision the analyst has already made.
 */
export async function loadPendingHostDuplicates(
  sources: Pick<HostScopeSources, "state" | "assetOverrides" | "fleet"> & {
    superTimeline?: HostEvidenceSource;
    dismissals: { load(caseId: string): Promise<readonly HostDuplicateDismissal[]> };
  },
  caseId: string,
): Promise<NearDuplicate[]> {
  const [index, dismissals] = await Promise.all([
    loadHostAliasIndex(sources, caseId),
    sources.dismissals.load(caseId),
  ]);
  return pendingNearDuplicates(await loadDuplicateCheckHostNames(sources, caseId, index), index, dismissals);
}

/**
 * PANEL DISPLAY ONLY — the union of blocking (shortname-fqdn) and non-blocking (network-identity)
 * candidates. NOT used by the AI-synthesis gate, the cockpit blocker card, or the AI status pill:
 * those keep calling loadPendingHostDuplicates() above, unchanged, so this ships with zero
 * behavior change to the existing hard gate (#1163).
 */
export async function loadHostDuplicatePanelCandidates(
  sources: Pick<HostScopeSources, "state" | "assetOverrides" | "fleet"> & {
    superTimeline?: HostEvidenceSource;
    dismissals: { load(caseId: string): Promise<readonly HostDuplicateDismissal[]> };
  },
  caseId: string,
): Promise<NearDuplicate[]> {
  const [state, index, dismissals] = await Promise.all([
    sources.state.load(caseId),
    loadHostAliasIndex(sources, caseId),
    sources.dismissals.load(caseId),
  ]);
  const hostNames = await loadDuplicateCheckHostNames(sources, caseId, index);
  const bindingIndex = buildHostBindingIndex(state.forensicTimeline ?? [], index);
  return [
    ...pendingNearDuplicates(hostNames, index, dismissals),
    ...pendingNetworkIdentityDuplicates(hostNames, index, bindingIndex, dismissals),
  ];
}

export async function loadHostScopeLedger(
  sources: HostScopeSources,
  caseId: string,
): Promise<HostScopeLedger> {
  const state = await sources.state.load(caseId);
  const window = sources.scope ? await sources.scope.load(caseId) : { start: null, end: null };
  const overrides = sources.assetOverrides ? await sources.assetOverrides.load(caseId) : null;
  const inventory = sources.fleet ? await sources.fleet.load() : { updatedAt: "", clients: [] };

  // overrides.merges is keyed by asset id, not host name — see hostMergesFromAssetIds.
  const index = buildHostAliasIndex(inventory.clients, hostMergesFromAssetIds(overrides?.merges ?? {}));
  const evidence = await loadHostEvidence(sources.superTimeline, caseId, index);
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
    // The same list and the same dismissals the pre-synthesis gate reads, so the banner never shows
    // a pair the gate waves through, or hides one it holds on.
    nearDuplicates: pendingNearDuplicates(
      hostNamesFromAssets([...hostNamesFromState(state), ...evidence.keys()]),
      index,
      sources.dismissals ? await sources.dismissals.load(caseId) : [],
    ),
    aliasIndex: index,
  });
}
