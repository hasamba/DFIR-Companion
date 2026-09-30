/**
 * Threat-intel enrichment orchestration: which providers a case may use, the reachability gate in
 * front of them, the background run itself, and the poller that resumes cases a down provider made
 * us skip. Lifted out of createApp by #416.
 *
 * OFF BY DEFAULT, ON PURPOSE. Enrichment sends indicators OFF the box, so `external`-scope
 * providers are opt-in per case (OPSEC). Nothing here runs until the analyst turns it on.
 *
 * THE PROVIDER SET IS MUTABLE (#178). `rebuildForPrefix` (composition/settingsReload.ts) swaps in a
 * freshly-built array when a key is saved in Settings, so a newly-configured source works without a
 * restart. It is always REPLACED, never mutated in place, and every reader goes through the live
 * `providers()` accessor — so the name projections below cannot go stale against it.
 *
 * WHY A REACHABILITY GATE AT ALL: a self-hosted MISP or YETI being down is routine, and without the
 * gate every IOC in the case fires its own doomed request. The cache probes once per TTL, the run
 * skips the dead provider, the case is remembered in `pending`, and the poller resumes it on
 * recovery — so "the server was down for ten minutes" costs a delay instead of a silent gap.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import {
  applyEnrichmentUpdates,
  enrichIocs,
  enrichmentUpdates,
  hasEnrichableWork,
  type EnrichLookupEvent,
  type EnrichmentUpdate,
} from "../enrichment/enrichService.js";
import { EnrichControlStore, resolveEnabledProviders } from "../enrichment/enrichControl.js";
import { ProviderHealthCache } from "../enrichment/providerHealth.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { ParentChildResult } from "../enrichment/rockyraccoon.js";
import { validateProcessChains, hasChainWork, type ChainSummary } from "../enrichment/chainValidate.js";
import { recordEnrichmentRun } from "../analysis/analysisRunRecorders.js";
import { investigationOutput, investigationOutputOfCase } from "../analysis/analysisRunSnapshot.js";
import type { AnalysisRunOutput } from "../analysis/analysisRunTypes.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { RegisteredJob } from "../analysis/jobManager.js";
import { logLine } from "../logging/serverLogger.js";
import { runInCaseScope, runInGenerationScope } from "../storage/caseIncarnation.js";
import { CaseKeyedMap, CaseKeyedSet, type PerCaseSet } from "../storage/caseKeyedState.js";

type ChainProvider = EnrichmentProvider & {
  checkParentChild: (p: string, c: string) => Promise<ParentChildResult | null>;
};

/** A RockyRaccoon provider: the one kind that validates parent→child chains, so reads events. */
function chainProviderOf(providers: readonly EnrichmentProvider[]): ChainProvider | undefined {
  return providers.find(
    (p): p is ChainProvider => typeof (p as { checkParentChild?: unknown }).checkParentChild === "function",
  );
}

/** What the locked save of a run hands back for the announce and the run record. */
interface SavedEnrichment {
  chainSummary?: ChainSummary;
  /** The whole case as saved, on the chain path only (it loaded it anyway). */
  full?: InvestigationState;
  /** The process events the chain validation looked at; none without a chain provider. */
  eventIds: string[];
  /** The case as saved, when a run store records it. */
  output?: AnalysisRunOutput;
}

/** Truncate a long indicator (e.g. a SHA-256) for a readable one-line log entry. */
function shortValue(value: string): string {
  return value.length > 24 ? `${value.slice(0, 24)}…` : value;
}

export interface EnrichmentDeps {
  store: CaseStore;
  options: AppOptions;
  /** Serializes a case's load->save critical section (see createApp's runStateExclusive). */
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
}

export interface EnrichmentEngine {
  /** The live configured provider set. An accessor, because Settings can rebuild it (#178). */
  providers(): EnrichmentProvider[];
  /** Replace the configured set after a settings reload. */
  setProviders(next: EnrichmentProvider[]): void;
  /** The subset this case has enabled (local providers default on, external opt-in). */
  enabledProvidersFor(caseId: string): Promise<EnrichmentProvider[]>;
  /** Shared reachability cache; the diagnostics route reads it. */
  readonly health: ProviderHealthCache;
  /** Cases waiting on a down provider, resumed by the poller on recovery. */
  readonly pending: PerCaseSet;
  /**
   * Self-coalescing, so N rapid kicks (a multi-file import) cost one run, not N. A kick supersedes
   * runs still QUEUED, and waits behind one already in flight — replaying after it saves, so
   * evidence that landed mid-run is still enriched without re-querying what that run covered.
   */
  enrichInBackground(caseId: string, force?: boolean, parentRunId?: string): void;
  /** Enrich fresh IOCs after synthesis/import when the toggle is on; the cache skips checked ones. */
  autoEnrichIfEnabled(caseId: string): void;
}

export function createEnrichmentEngine({
  store,
  options,
  runStateExclusive,
}: EnrichmentDeps): EnrichmentEngine {
  const enrichControl = new EnrichControlStore(store);
  let allProviders = options.enrichmentProviders ?? [];

  async function enabledProvidersFor(caseId: string): Promise<EnrichmentProvider[]> {
    const configuredNames = allProviders.map((p) => p.name);
    const localNames = allProviders.filter((p) => p.scope === "local").map((p) => p.name);
    const enabled = new Set(
      resolveEnabledProviders(await enrichControl.load(caseId), configuredNames, localNames),
    );
    return allProviders.filter((p) => enabled.has(p.name));
  }

  // Shared reachability cache probes a down self-hosted provider once per TTL and logs transitions.
  const health = new ProviderHealthCache({
    ttlMs: options.enrichHealthTtlMs,
    onProbe: (name, h) =>
      logLine(`[enrich] health ${name} ${h.ok ? "UP" : `DOWN (${h.detail ?? "unreachable"})`}`),
  });
  // Cases waiting for a down provider; the poller resumes only their unchecked IOCs on recovery.
  // #1866: both keyed by (case id, generation) — a deleted case's pending mark or deferred kick is
  // never replayed under, or absorbed by, a same-id successor.
  const pending = new CaseKeyedSet(() => store.casesRoot);
  // Cases kicked while a run was already IN FLIGHT, holding the strongest `force` asked for. Replayed
  // once that run has saved — see the deferral in enrichInBackground for why waiting beats racing.
  const deferredKicks = new CaseKeyedMap<boolean>(() => store.casesRoot);

  const isEnriching = (caseId: string): boolean =>
    options.jobManager?.list(caseId).some((j) => j.kind === "enrichment" && j.status === "running") ?? false;

  /**
   * Replay a kick that arrived mid-run, now that the run has saved. Reached only from a run that
   * actually finished: replaying after a CANCEL would re-register against the newer job that
   * cancelled it, cancel that in turn, and ping-pong the pair indefinitely.
   */
  const replayDeferredKick = (caseId: string, parentRunId?: string): boolean => {
    if (!deferredKicks.has(caseId)) return false;
    const force = deferredKicks.get(caseId)!;
    deferredKicks.delete(caseId);
    enrichInBackground(caseId, force, parentRunId);
    return true;
  };

  /**
   * Position in a batch chain. `enrichMaxIocs` bounds how long ONE run holds the case's single
   * concurrency slot — it was never meant to abandon the indicators past it, but that is what it
   * did: a 250-IOC case enriched 100 and stopped, and the analyst had to press OK again to get
   * the rest. A capped run now queues the next batch itself, bounded by `enrichMaxBatches`.
   */
  interface BatchChain {
    batch: number; // 1-based index of the run about to start
    covered: ReadonlySet<string>; // IOC values earlier batches in this chain already took on
  }

  // #1855: runs as work of the case incarnation it was kicked for (a batch chain keeps the first).
  function enrichInBackground(caseId: string, force = false, parentRunId?: string, chain?: BatchChain): void {
    runInCaseScope(store.casesRoot, caseId, () => enrichInScope(caseId, force, parentRunId, chain));
  }

  function enrichInScope(caseId: string, force: boolean, parentRunId?: string, chain?: BatchChain): void {
    if (allProviders.length === 0 || !options.stateStore) return;
    let job: RegisteredJob | undefined; // #225: registered once providers are known
    void (async () => {
      const startedAt = new Date().toISOString();
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) {
        pending.delete(caseId);
        return;
      } // nothing enabled — drop any stale pending mark so the poller can idle
      const batch = chain?.batch ?? 1;
      const maxBatches = Math.max(1, options.enrichMaxBatches ?? 20);
      // #1887: only chain validation reads events. Without a chain provider the overview (every
      // field but the forensic timeline) is all a run needs — never the whole case.
      const rocky = chainProviderOf(providers);
      const state = rocky
        ? await options.stateStore!.load(caseId)
        : await options.stateStore!.loadOverview(caseId);
      // Skip the job/status/save when every enabled provider already checked every IOC and process
      // chain. This avoids spurious enrichment after unrelated re-synthesis; force bypasses it.
      if (!force) {
        const work =
          hasEnrichableWork(state.iocs, providers) ||
          (rocky !== undefined && hasChainWork(state.forensicTimeline));
        if (!work) {
          pending.delete(caseId);
          return;
        }
      }
      // SUPERSEDE ONLY WHAT HAS NOT STARTED. Cancelling a run already in flight does not stop it:
      // enrichIocs finishes its current indicator and still merges and saves below. Meanwhile the
      // cancel frees the case's concurrency slot immediately, so the newcomer is admitted alongside
      // it holding a snapshot taken BEFORE that save — it re-queries indicators the first run
      // already paid a rate-limited provider for, and whichever saves last stamps its own older
      // copy over the other's `enrichedBy`, which is the marker that stops the next kick querying
      // them all again. Defer instead, and replay once the run in flight has saved, so evidence
      // that landed mid-run is still covered.
      if (isEnriching(caseId)) {
        deferredKicks.set(caseId, (deferredKicks.get(caseId) ?? false) || force);
        return;
      }
      // #225: track enrichment as a cancellable job — a throttled run (up to maxIocs × delayMs) can be long.
      // exclusive, so the kicks that are still QUEUED collapse into one: a multi-file import fires
      // one autoEnrichIfEnabled per file, and without it a six-file import queued six runs behind
      // the case's single concurrency slot. A queued job has made no request and saved nothing, so
      // superseding it costs nothing — the guard above is what keeps that true.
      job = options.jobManager?.register({
        caseId,
        kind: "enrichment",
        label: `enrich (${providers.map((p) => p.name).join(", ")})`,
        cancellable: true,
        exclusive: true,
      });
      if (job) await job.ready;
      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: new Date().toISOString(),
        detail: `enriching IOCs (${providers.map((p) => p.name).join(", ")})`,
      });
      logLine(
        `[enrich] ${caseId} START batch=${batch}/${maxBatches} providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`,
      );
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        perProviderDelayMs: options.enrichProviderDelayMs,
        jitterMs: options.enrichJitterMs,
        retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
        maxIocs: options.enrichMaxIocs,
        // Everything earlier batches of this chain took on — so batch 2 starts where batch 1
        // stopped instead of re-paying a rate-limited provider for the same indicators.
        skipValues: chain?.covered,
        force,
        signal: job?.signal, // #225: analyst cancel — stop between IOCs (partial enrichment is additive/safe)
        health, // probe each provider (cached ~60s) before sending — skip the dead ones
        onProgress: (done, total) =>
          options.onAiStatus?.(caseId, {
            status: "analyzing",
            phase: "extracting",
            at: new Date().toISOString(),
            detail: `enriching IOC ${done}/${total}`,
          }),
        // One audit line per outbound threat-intel API call: which provider, indicator, result.
        onLookup: (e: EnrichLookupEvent) =>
          logLine(
            `[enrich] ${caseId} ${e.provider} ${e.kind} ${shortValue(e.value)} -> ${e.outcome}${e.detail ? ` (${e.detail})` : ""} ${e.ms}ms`,
          ),
      });
      const downNote = summary.unavailable.length ? ` unavailable=[${summary.unavailable.join(", ")}]` : "";
      logLine(
        `[enrich] ${caseId} DONE batch=${batch}/${maxBatches} queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors} skipped=${summary.skipped} capped=${summary.capped}${downNote}`,
      );
      // Queue incomplete cases for recovery; clear stale pending state when all providers answered.
      if (summary.unavailable.length) pending.add(caseId);
      else pending.delete(caseId);
      const updates = enrichmentUpdates(state.iocs, iocs);
      const saved = await runStateExclusive(caseId, () => saveEnrichment(caseId, updates, rocky, force));
      announce(caseId, saved.full);
      const { chainSummary } = saved;
      if (saved.output)
        await recordEnrichmentRun(options.analysisRunStore, caseId, {
          parentRunId,
          startedAt,
          providerNames: providers.map((provider) => provider.name),
          force,
          maxIocs: options.enrichMaxIocs ?? 100,
          delayMs: options.enrichDelayMs ?? 0,
          eventIds: saved.eventIds,
          iocIds: state.iocs.map((ioc) => ioc.id),
          output: saved.output,
          summary,
        });
      const chainNote = chainSummary
        ? `; chains ${chainSummary.anomalies} anomalous/${chainSummary.checked}`
        : "";
      const skipNote = summary.unavailable.length
        ? `; skipped ${summary.unavailable.join(", ")} (unreachable — will retry)`
        : "";
      const aborted = job?.signal?.aborted === true;
      // Chain the next batch when the cap left real work behind. Three things must hold:
      //   • the batch made PROGRESS (queried > 0) — otherwise a provider that probes DOWN would
      //     burn the whole budget re-probing a dead server; the health poller owns recovery.
      //   • the analyst did not cancel.
      //   • the budget is not spent.
      // A deferred kick wins over the chain: it replays a FRESH chain that re-scans the whole
      // case, so continuing as well would register two runs for the same remaining IOCs.
      const budgetLeft = batch < maxBatches;
      const willContinue =
        summary.capped > 0 && summary.queried > 0 && !aborted && budgetLeft && !deferredKicks.has(caseId);
      const capNote =
        summary.capped === 0
          ? ""
          : willContinue
            ? `; ${summary.capped} IOC(s) left by the cap — starting batch ${batch + 1}/${maxBatches}`
            : summary.queried === 0
              ? `; ${summary.capped} IOC(s) left by the cap — no provider answered, will retry`
              : `; ${summary.capped} IOC(s) left by the cap (DFIR_ENRICH_MAX=${options.enrichMaxIocs ?? 100}` +
                `${budgetLeft ? "" : ` × DFIR_ENRICH_MAX_BATCHES=${maxBatches}`}) — enrich again to continue`;
      if (job) await options.jobManager?.finish(job.jobId); // no-op if a cancel already marked it cancelled
      // A newer exclusive registration may have superseded this run — if an enrichment job for this
      // case is still active, that newer run owns the status; don't stomp its live "enriching IOC
      // 12/40" with this run's partial total.
      if (!(aborted && options.jobManager?.hasActive(caseId, "enrichment"))) {
        options.onAiStatus?.(caseId, {
          status: "idle",
          at: new Date().toISOString(),
          detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}${skipNote}${capNote}`,
        });
      }
      // This run's results are saved, so a kick deferred behind it can now load them and enrich only
      // what it added. Not after an ABORT: the analyst cancelled, and replaying would restart the
      // work they just stopped.
      // Re-tested at the point of USE, not only where `willContinue` was decided: a kick can arrive
      // in between (the run has not released its job yet, so it still defers), and replaying while
      // also chaining would put two runs on the same remaining IOCs.
      const replayed = !aborted && replayDeferredKick(caseId, parentRunId);
      // Otherwise carry the chain on where this batch stopped. `covered` is what this batch
      // ATTEMPTED, not what succeeded: an IOC whose only provider errored is never stamped into
      // `enrichedBy`, and under `force` that stamp is ignored anyway — either would leave the
      // cursor stuck on the same first N indicators for every remaining batch.
      if (willContinue && !replayed) {
        const covered = new Set([...(chain?.covered ?? []), ...summary.attemptedValues]);
        enrichInBackground(caseId, force, parentRunId, { batch: batch + 1, covered });
      }
    })().catch(async (err) => {
      // Superseding a still-QUEUED run rejects its admission rather than resolving it, so a
      // cancellation arrives here as a rejection. It is not a failure to report: stay silent when a
      // newer run owns the case, and otherwise say cancelled rather than erroring.
      const aborted = job?.signal?.aborted === true;
      if (job) await options.jobManager?.fail(job.jobId, err); // no-op if already terminal (cancelled)
      // A failed run still releases anything deferred behind it, or that kick waits for a run that
      // will never come. Not after an abort — see the success path.
      if (!aborted) replayDeferredKick(caseId, parentRunId);
      if (aborted && options.jobManager?.hasActive(caseId, "enrichment")) return;
      options.onAiStatus?.(
        caseId,
        aborted
          ? { status: "idle", at: new Date().toISOString(), detail: "enrichment cancelled" }
          : { status: "error", at: new Date().toISOString(), detail: (err as Error).message },
      );
    });
  }

  /**
   * Merge a run's enrichment fields onto the latest IOCs and save, inside the case's state lock.
   * Without a chain provider it re-reads and writes only the overview: saveOverview leaves the
   * forensic rows exactly as stored and rewrites the other kinds from the overview reloaded here,
   * so a row an import appended mid-run survives. A chain provider needs the events, so it keeps
   * the whole-case load and save. The run output is read after the save, in the same lock.
   */
  async function saveEnrichment(
    caseId: string,
    updates: ReadonlyMap<string, EnrichmentUpdate>,
    rocky: ChainProvider | undefined,
    force: boolean,
  ): Promise<SavedEnrichment> {
    const stateStore = options.stateStore!;
    const record = options.analysisRunStore !== undefined;
    if (!rocky) {
      const latest = await stateStore.loadOverview(caseId);
      const iocs = applyEnrichmentUpdates(latest.iocs, updates);
      await stateStore.saveOverview({ ...latest, iocs, updatedAt: new Date().toISOString() });
      // No events were read, so the record lists none (#1887).
      return {
        eventIds: [],
        output: record ? await investigationOutputOfCase(stateStore, caseId) : undefined,
      };
    }
    const latest = await stateStore.load(caseId);
    // A RockyRaccoon provider validates parent→child chains with the IOC throttle and cap.
    const { events, summary: chainSummary } = await validateProcessChains(latest.forensicTimeline, {
      check: (p, c) => rocky.checkParentChild(p, c),
      delayMs: options.enrichProviderDelayMs?.["RockyRaccoon"] ?? options.enrichDelayMs,
      jitterMs: options.enrichJitterMs,
      retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
      maxChecks: options.enrichMaxIocs,
      force,
    });
    const full: InvestigationState = {
      ...latest,
      iocs: applyEnrichmentUpdates(latest.iocs, updates),
      forensicTimeline: events,
      updatedAt: new Date().toISOString(),
    };
    await stateStore.save(full);
    // The process events the chain validation looked at, from the snapshot it validated.
    const eventIds = latest.forensicTimeline.filter((e) => e.processName && e.parentName).map((e) => e.id);
    return { chainSummary, full, eventIds, output: record ? investigationOutput(full) : undefined };
  }

  // A state push for the dashboards watching the case, after the lock is released; the app loads
  // the case only if one is (#1874, as caseAppliers.announceState does).
  function announce(caseId: string, full: InvestigationState | undefined): void {
    if (options.onStateChanged) return options.onStateChanged(caseId);
    if (!options.onState) return;
    if (full) return options.onState(full);
    void options.stateStore!.load(caseId).then(options.onState, () => undefined);
  }

  function autoEnrichIfEnabled(caseId: string): void {
    if (allProviders.length === 0) return;
    enabledProvidersFor(caseId)
      .then((ps) => {
        if (ps.length > 0) enrichInBackground(caseId);
      })
      .catch(() => {});
  }

  // The opt-in reachability poller only probes known-down providers while cases are waiting, then
  // resumes those cases on recovery. Capability is checked inside each tick so rebuilt settings work
  // (#178); unref prevents the timer holding the process open.
  if (options.enrichHealthPollMs && options.enrichHealthPollMs > 0) {
    let polling = false; // guard against overlap if a probe round runs long
    const timer = setInterval(() => {
      if (polling) return;
      if (pending.size === 0) return; // no case waiting on a down provider — nothing to resume, so don't probe (or log)
      if (!allProviders.some((p) => p.probe)) return; // nothing probe-capable configured (yet)
      const down = allProviders.filter((p) => health.peek(p.name)?.ok === false);
      if (down.length === 0) return; // nothing to recover
      polling = true;
      void (async () => {
        for (const p of down) {
          health.invalidate(p.name);
          await health.check(p);
        }
        const recovered = down.some((p) => health.peek(p.name)?.ok === true);
        if (recovered && pending.size > 0) {
          const cases = pending.list();
          pending.clear();
          logLine(`[enrich] health recovered — resuming ${cases.length} case(s)`);
          // Each resumes as work of the incarnation that was waiting, never of a same-id successor.
          for (const c of cases)
            runInGenerationScope(store.casesRoot, c.caseId, c.generation, () => enrichInBackground(c.caseId));
        }
      })()
        .catch(() => {})
        .finally(() => {
          polling = false;
        });
    }, options.enrichHealthPollMs);
    timer.unref?.();
  }

  return {
    providers: () => allProviders,
    setProviders: (next) => {
      allProviders = next;
    },
    enabledProvidersFor,
    health,
    pending,
    enrichInBackground,
    autoEnrichIfEnabled,
  };
}
