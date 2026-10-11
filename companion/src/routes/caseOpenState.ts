// #2126: the case-open panel GETs share one whole-case load, and the last one is kept briefly.
//
// Opening a case fires about fifteen panel GETs that each need the full forensic state (ioc-risk,
// customer-exposure, cockpit, sessions, campaign-scope, served-exposure, kerberoast-chain, tls-graph,
// sensitive-access, playbook-match, hypotheses, host-scope, host-duplicates, second-look/preview,
// known-unknowns). Each used to run its own StateStore.load: a full copy of every forensic row, two
// at a time. They now go through the same ReportLiteCache the report-lite projections use (#2057),
// over the FULL state:
//
//   - The key is the case id plus its exact read revision (caseReadRevision: the pool's write
//     sequence, bumped when a write is SUBMITTED, plus the identity of the database file, case.json
//     and the side files). Any import or edit changes it, so a request that starts after a write
//     never gets data read before it.
//   - Requests at the same revision share one load, queued or already reading.
//   - The result of a load is kept only when the revision did not move while it ran: a load that
//     raced a write is handed to its own callers and never kept as current.
//   - ONE case is kept, dropped after REPORT_LITE_IDLE_MS (5 minutes) without a request, replaced
//     when another case is loaded, and dropped when the case is deleted (onCaseForgotten). The idle
//     timer is unref'd. No revision (no database yet, a failed stat) means no sharing past the
//     coalescer and nothing kept.
//
// READ-ONLY. StateStore.load itself never shares: its write callers load, modify and save. Only the
// GET panel handlers use this, and the state they get is shared by every caller and must not be
// modified (CLAUDE.md §5). Under the test runner every shared state is deep-frozen, so any handler or
// callee that writes to it fails loudly; tests/server/caseOpenStateImmutable.test.ts runs every
// switched route over a frozen state.
//
// ABORT AND THE HEAVY-READ GATE. Each caller passes its request signal. Leaving ends only that
// caller's wait; the shared load runs on the cohort's joined signal, so it is cancelled only while
// still queued and only once every caller has left (reports/stateLoadGate.ts). The load goes through
// the wholeCaseLoads limiter and is tracked work (analysis/pendingWork.ts), counted ONCE, on the
// request that started it: that request's gate slot is held until the shared load settles even if
// its client has gone. A request that JOINED a load already started frees its slot as soon as its
// own wait ends, because the load is already counted on the starter's slot.

import { resolve } from "node:path";
import type { Response } from "express";
import { requestAbortSignal } from "../http/requestAbort.js";
import { onCaseForgotten } from "../storage/caseKeyedState.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { CaseStateReader } from "../analysis/hostScopeLoad.js";
import { ReportLiteCache, caseReadRevision } from "../reports/reportLiteCache.js";
import type { RouteContext } from "./context.js";

/** The parts of StateStore the shared read uses. */
export interface CaseOpenStateSource {
  load(caseId: string): Promise<InvestigationState>;
  databasePath(caseId: string): string;
  forensicHostsInOrder?(caseId: string): Promise<string[]>;
}

/** A shared, read-only case reader: `load` honours only `signal`; it never takes a write path. */
export interface CaseOpenStateReader extends CaseStateReader {
  forensicHostsInOrder?(caseId: string): Promise<string[]>;
}

// One cache per StateStore (production has one). Weak, so a test's store and its cache go together.
const caches = new WeakMap<CaseOpenStateSource, ReportLiteCache<InvestigationState>>();

/** True under the test runner: shared states are deep-frozen there, so a mutation throws. */
const FREEZE_SHARED = process.env.VITEST !== undefined || process.env.NODE_ENV === "test";

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) deepFreeze((value as Record<PropertyKey, unknown>)[key], seen);
  return Object.freeze(value);
}

function cacheFor(cases: CaseStore, source: CaseOpenStateSource): ReportLiteCache<InvestigationState> {
  const held = caches.get(source);
  if (held) return held;
  const cache = new ReportLiteCache<InvestigationState>((caseId) =>
    caseReadRevision(cases, source.databasePath(caseId), caseId),
  );
  caches.set(source, cache);
  forgetOnDelete(cases.casesRoot, cache);
  return cache;
}

/** A deleted case's kept state is released at once, not after the idle period. */
function forgetOnDelete(casesRoot: string, cache: ReportLiteCache<InvestigationState>): void {
  const ref = new WeakRef(cache);
  const stop = onCaseForgotten((root, caseId) => {
    const live = ref.deref();
    if (!live) return stop();
    if (root === resolve(casesRoot)) live.forget(caseId); // the root arrives resolved
  });
}

/** The case-open panels' shared reader over `source` (a StateStore). GET panel handlers only. */
export function caseOpenState(cases: CaseStore, source: CaseOpenStateSource): CaseOpenStateReader {
  const cache = cacheFor(cases, source);
  const read = (caseId: string) => async (): Promise<InvestigationState> => {
    // No caller's signal here: one caller leaving must never cancel the load for the others.
    const state = await source.load(caseId);
    return FREEZE_SHARED ? deepFreeze(state) : state;
  };
  return {
    load: (caseId, opts) => cache.load(caseId, read(caseId), opts?.signal),
    ...(source.forensicHostsInOrder
      ? { forensicHostsInOrder: (caseId: string) => source.forensicHostsInOrder!(caseId) }
      : {}),
  };
}

/** A GET panel handler's shared read of `caseId`, waited on with its own request's abort signal. */
export function loadCaseOpenState(
  ctx: RouteContext,
  caseId: string,
  res: Response,
): Promise<InvestigationState> {
  const { store, options } = ctx;
  if (!options.stateStore) return Promise.reject(new Error("state store not configured"));
  return caseOpenState(store, options.stateStore).load(caseId, { signal: requestAbortSignal(res) });
}

/** The route's shared reader, or undefined without a state store (the caller then loads its own). */
export function caseOpenStateOf(ctx: RouteContext): CaseOpenStateReader | undefined {
  return ctx.options.stateStore ? caseOpenState(ctx.store, ctx.options.stateStore) : undefined;
}

/** Cases whose full state is kept for `source` (0 or 1). For tests and diagnostics. */
export function caseOpenStateHeld(source: CaseOpenStateSource): number {
  return caches.get(source)?.size ?? 0;
}
