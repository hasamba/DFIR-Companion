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
import { enrichIocs, hasEnrichableWork, type EnrichLookupEvent } from "../enrichment/enrichService.js";
import { EnrichControlStore, resolveEnabledProviders } from "../enrichment/enrichControl.js";
import { ProviderHealthCache } from "../enrichment/providerHealth.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { ParentChildResult } from "../enrichment/rockyraccoon.js";
import { validateProcessChains, hasChainWork, type ChainSummary } from "../enrichment/chainValidate.js";
import { recordEnrichmentRun } from "../analysis/analysisRunRecorders.js";
import type { RegisteredJob } from "../analysis/jobManager.js";
import { logLine } from "../logging/serverLogger.js";

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
  readonly pending: Set<string>;
  /**
   * Self-coalescing: a newer run supersedes an older one for the same case, so N rapid kicks (a
   * multi-file import) cost one run, not N. The superseded run keeps and saves the lookups it
   * already made.
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
  const pending = new Set<string>();

  function enrichInBackground(caseId: string, force = false, parentRunId?: string): void {
    if (allProviders.length === 0 || !options.stateStore) return;
    let job: RegisteredJob | undefined; // #225: registered once providers are known
    void (async () => {
      const startedAt = new Date().toISOString();
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) {
        pending.delete(caseId);
        return;
      } // nothing enabled — drop any stale pending mark so the poller can idle
      const state = await options.stateStore!.load(caseId);
      // Skip the job/status/save when every enabled provider already checked every IOC and process
      // chain. This avoids spurious enrichment after unrelated re-synthesis; force bypasses it.
      if (!force) {
        const chainCapable = providers.some(
          (p) => typeof (p as { checkParentChild?: unknown }).checkParentChild === "function",
        );
        const work =
          hasEnrichableWork(state.iocs, providers) || (chainCapable && hasChainWork(state.forensicTimeline));
        if (!work) {
          pending.delete(caseId);
          return;
        }
      }
      // #225: track enrichment as a cancellable job — a throttled run (up to maxIocs × delayMs) can be long.
      // exclusive, like the synthesis kick: a multi-file import fires one autoEnrichIfEnabled per
      // file, and without it a six-file import queued six runs behind the case's single concurrency
      // slot. Superseding is safe here in a way it is not for most work — enrichIocs stops BETWEEN
      // indicators and the partial result is still merged and saved below, so an aborted run keeps
      // every lookup it already paid for and the newer run skips those via `enrichedBy`. No
      // outbound request is wasted or repeated.
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
        `[enrich] ${caseId} START providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`,
      );
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        perProviderDelayMs: options.enrichProviderDelayMs,
        jitterMs: options.enrichJitterMs,
        retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
        maxIocs: options.enrichMaxIocs,
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
        `[enrich] ${caseId} DONE queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors} skipped=${summary.skipped}${downNote}`,
      );
      // Queue incomplete cases for recovery; clear stale pending state when all providers answered.
      if (summary.unavailable.length) pending.add(caseId);
      else pending.delete(caseId);
      const { chainSummary, merged: finalState } = await runStateExclusive(caseId, async () => {
        // Re-load + write only the IOCs so a concurrent state change survives.
        const latest = await options.stateStore!.load(caseId);
        const byValue = new Map(iocs.map((i) => [i.value, i]));
        let merged = {
          ...latest,
          iocs: latest.iocs.map((i) => byValue.get(i.value) ?? i),
          updatedAt: new Date().toISOString(),
        };

        // A RockyRaccoon provider validates parent→child chains with the IOC throttle and cap.
        const rocky = providers.find(
          (
            p,
          ): p is EnrichmentProvider & {
            checkParentChild: (p: string, c: string) => Promise<ParentChildResult | null>;
          } => typeof (p as { checkParentChild?: unknown }).checkParentChild === "function",
        );
        let chainSummary: ChainSummary | undefined;
        if (rocky) {
          const { events, summary: cs } = await validateProcessChains(merged.forensicTimeline, {
            check: (p, c) => rocky.checkParentChild(p, c),
            delayMs: options.enrichProviderDelayMs?.["RockyRaccoon"] ?? options.enrichDelayMs,
            jitterMs: options.enrichJitterMs,
            retry: { retries: options.enrichRetries, backoffMs: options.enrichRetryBackoffMs },
            maxChecks: options.enrichMaxIocs,
            force,
          });
          merged = { ...merged, forensicTimeline: events };
          chainSummary = cs;
        }

        await options.stateStore!.save(merged);
        options.onState?.(merged);
        return { chainSummary, merged };
      });
      await recordEnrichmentRun(options.analysisRunStore, caseId, {
        parentRunId,
        startedAt,
        providerNames: providers.map((provider) => provider.name),
        force,
        maxIocs: options.enrichMaxIocs ?? 100,
        delayMs: options.enrichDelayMs ?? 0,
        inputState: state,
        outputState: finalState,
        summary,
      });
      const chainNote = chainSummary
        ? `; chains ${chainSummary.anomalies} anomalous/${chainSummary.checked}`
        : "";
      const skipNote = summary.unavailable.length
        ? `; skipped ${summary.unavailable.join(", ")} (unreachable — will retry)`
        : "";
      const aborted = job?.signal?.aborted === true;
      if (job) await options.jobManager?.finish(job.jobId); // no-op if a cancel already marked it cancelled
      // A newer exclusive registration may have superseded this run — if an enrichment job for this
      // case is still active, that newer run owns the status; don't stomp its live "enriching IOC
      // 12/40" with this run's partial total.
      if (!(aborted && options.jobManager?.hasActive(caseId, "enrichment"))) {
        options.onAiStatus?.(caseId, {
          status: "idle",
          at: new Date().toISOString(),
          detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}${skipNote}`,
        });
      }
    })().catch(async (err) => {
      // Superseding a still-QUEUED run rejects its admission rather than resolving it, so a
      // cancellation arrives here as a rejection. It is not a failure to report: stay silent when a
      // newer run owns the case, and otherwise say cancelled rather than erroring.
      const aborted = job?.signal?.aborted === true;
      if (job) await options.jobManager?.fail(job.jobId, err); // no-op if already terminal (cancelled)
      if (aborted && options.jobManager?.hasActive(caseId, "enrichment")) return;
      options.onAiStatus?.(
        caseId,
        aborted
          ? { status: "idle", at: new Date().toISOString(), detail: "enrichment cancelled" }
          : { status: "error", at: new Date().toISOString(), detail: (err as Error).message },
      );
    });
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
          const cases = [...pending];
          pending.clear();
          logLine(`[enrich] health recovered — resuming ${cases.length} case(s)`);
          for (const c of cases) enrichInBackground(c);
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
