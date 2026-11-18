// CrowdStrike Next-Gen SIEM search (#2666): the analyst's Run on a CQL hunt.
//
//   GET  /cases/:id/crowdstrike/siem         — is the search set up, its caps, the default range
//   POST /cases/:id/crowdstrike/siem/search  — { query, start, end, title? } -> 202 { jobId }
//
// Everything that can refuse a search is checked BEFORE any call to Falcon: the feature is off
// without both DFIR_CROWDSTRIKE_SIEM_CLIENT_ID and _SECRET; the time range must fit the window cap
// (refused, never clipped). The search then runs as a `siem-search` job (Jobs panel, the case's
// one-job slot, cancellable), and its rows are imported as evidence (crowdstrikeSiemImport.ts).
// A closed or archived case is refused by the case-write guard before this route runs; the job
// checks again just before it calls Falcon.

import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import { ScopeStore, NO_SCOPE } from "../analysis/scope.js";
import {
  checkSearchWindow,
  defaultSearchRange,
  readSiemLimits,
  siemSearchText,
  type SiemSearchOutcome,
} from "../analysis/siemSearch.js";
import { requestAuthentication } from "../auth/types.js";
import { ngsiemCredentialsFromEnv, ngsiemSettingsError } from "../integrations/crowdstrike/ngsiemConfig.js";
import { NgsiemSearchClient } from "../integrations/crowdstrike/ngsiemSearch.js";
import { falconConsoleOrigin } from "../integrations/crowdstrike/falconConsole.js";
import type { RouteContext } from "./context.js";
import { activityDetail, landSearchResult, type SiemSearchSpec } from "./crowdstrikeSiemImport.js";
import { isFrozenCase } from "./importCaseGuard.js";
import { csSearchKey } from "../analysis/ai/watson/crowdstrike/csLaunchCheck.js";
import { fingerprintStoreFor } from "../analysis/ai/watson/velo/fingerprintIndex.js";

const iso = (ms: number): string => new Date(ms).toISOString();

const QUERY_MAX = 20_000;
const TITLE_MAX = 200;
export const SIEM_NOT_CONFIGURED =
  "CrowdStrike Next-Gen SIEM search is not set up. Add the SIEM API client in Settings (DFIR_CROWDSTRIKE_SIEM_CLIENT_ID and _SECRET).";

export interface SiemSearchRequest {
  query: string;
  start: unknown;
  end: unknown;
  title?: string;
}

export type SiemStartResult =
  { ok: true; jobId: string; spec: SiemSearchSpec } | { ok: false; status: number; error: string };

/** What happened to a search, for a caller that waits on it (Watson's card, Part B). */
export type SiemDone = (outcome: SiemSearchOutcome & { storedName?: string }) => void | Promise<void>;

const oneLine = (s: string): string => s.replace(/\s+/g, " ").trim();

/** Validate a search and freeze what will run (query, range, repository, caps) — before any call. */
export function prepareSiemSearch(
  caseId: string,
  body: SiemSearchRequest,
  actor: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
  now = Date.now(),
): { ok: true; spec: SiemSearchSpec } | { ok: false; status: number; error: string } {
  if (!ngsiemCredentialsFromEnv(env)) return { ok: false, status: 409, error: SIEM_NOT_CONFIGURED };
  const settingsError = ngsiemSettingsError(env);
  if (settingsError) return { ok: false, status: 400, error: settingsError };
  const query = typeof body.query === "string" ? body.query : "";
  if (!query.trim()) return { ok: false, status: 400, error: "The search needs a CQL query." };
  if (query.length > QUERY_MAX) {
    return { ok: false, status: 400, error: `The query is longer than ${QUERY_MAX} characters.` };
  }
  const limits = readSiemLimits(env);
  const window = checkSearchWindow(body.start, body.end, limits.maxWindowDays, now);
  if (!window.ok) return { ok: false, status: 400, error: window.error };
  const title = oneLine(typeof body.title === "string" ? body.title : "").slice(0, TITLE_MAX) || "CQL hunt";
  return {
    ok: true,
    spec: {
      caseId,
      title,
      query,
      startMs: window.startMs,
      endMs: window.endMs,
      repository: limits.repository,
      maxRows: limits.maxRows,
      timeoutMs: limits.timeoutMs,
      actor,
    },
  };
}

/** Run the frozen search: Falcon -> evidence -> import -> activity entry. Throws on abort. */
async function runSearch(
  ctx: RouteContext,
  spec: SiemSearchSpec,
  signal: AbortSignal | undefined,
  progress: (rows: number) => void,
  closeCancel: () => boolean,
): Promise<{ outcome: SiemSearchOutcome & { storedName?: string }; warnings: string[] }> {
  if (await isFrozenCase(ctx.store, spec.caseId)) {
    return { outcome: failed(spec, "the case is closed or archived. Nothing was searched."), warnings: [] };
  }
  const creds = ngsiemCredentialsFromEnv(process.env);
  if (!creds) return { outcome: failed(spec, SIEM_NOT_CONFIGURED), warnings: [] };
  let result;
  try {
    // Built inside the try: a bad base URL or CA bundle is a Settings sentence, not a crash (#2685).
    const client = new NgsiemSearchClient({
      ...creds,
      repository: spec.repository,
      ...(ctx.options.crowdstrikeSiemFetch ? { fetchFn: ctx.options.crowdstrikeSiemFetch } : {}),
      log: (line) => ctx.serverLogger.warn(`[crowdstrike-siem] ${spec.caseId}: ${line}`),
    });
    result = await client.run({
      query: spec.query,
      startMs: spec.startMs,
      endMs: spec.endMs,
      maxRows: spec.maxRows,
      timeoutMs: spec.timeoutMs,
      ...(signal ? { signal } : {}),
      onProgress: progress,
    });
  } catch (err) {
    if ((err as { name?: string })?.name === "AbortError") throw err;
    return { outcome: failed(spec, (err as Error).message), warnings: [] };
  }
  return { outcome: await landSearchResult(ctx, spec, result, closeCancel), warnings: result.warnings };
}

function failed(spec: SiemSearchSpec, why: string): SiemSearchOutcome {
  return { title: spec.title, rows: 0, events: 0, added: 0, truncated: false, timedOut: false, failed: why };
}

/**
 * Register the search as a job and run it in the background. The caller has already answered
 * nothing; it gets the job id to answer with. `onDone` hears the outcome (never on a cancel).
 */
export async function startSiemSearch(
  ctx: RouteContext,
  spec: SiemSearchSpec,
  onDone?: SiemDone,
  extra: { parameters?: Record<string, string>; idempotencyKey?: string } = {},
): Promise<string> {
  const jm = ctx.options.jobManager;
  const job = jm?.register({
    caseId: spec.caseId,
    kind: "siem-search",
    label: `CrowdStrike NG-SIEM search: ${spec.title}`.slice(0, 200),
    detail: "waiting for the case",
    cancellable: true,
    resumable: false,
    ...(extra.idempotencyKey ? { idempotencyKey: extra.idempotencyKey } : {}),
    parameters: {
      repository: spec.repository,
      start: new Date(spec.startMs).toISOString(),
      end: new Date(spec.endMs).toISOString(),
      ...(extra.parameters ?? {}),
    },
  });
  await job?.durable;
  const jobId = job?.jobId ?? "";
  // The same card registered twice (a retry after a lost save): the first job is the search.
  if (job?.reused) return jobId;
  // The search is remembered on the case (Watson's duplicate check): idempotent, never refuses.
  const key = csSearchKey(spec.query, spec.repository, iso(spec.startMs), iso(spec.endMs));
  await fingerprintStoreFor(ctx.store)
    .add(spec.caseId, [key])
    .catch((err: unknown) =>
      ctx.serverLogger.warn(`[crowdstrike-siem] could not record the search key: ${(err as Error).message}`),
    );
  const work = async (): Promise<void> => {
    await job?.ready;
    const progress = (rows: number) =>
      void jm
        ?.checkpoint(jobId, { done: rows, total: spec.maxRows, detail: `${rows} rows read` })
        .catch(() => undefined);
    const closeCancel = (): boolean => {
      // No await between these two lines: that is what makes them atomic with a cancel.
      if (jm && jobId) jm.setCancellable(jobId, false);
      return job?.signal?.aborted === true;
    };
    const { outcome, warnings } = await runSearch(ctx, spec, job?.signal, progress, closeCancel);
    const text = siemSearchText(outcome);
    await logActivity(ctx.options.activityLogStore, ctx.options.onActivity, spec.caseId, {
      actor: spec.actor,
      category: "hunt",
      action: "crowdstrike-siem.search",
      detail: activityDetail(spec, outcome, warnings),
      targetType: "hunt",
      ...(outcome.failed ? { outcome: "error" as const } : {}),
    });
    if (jm && jobId) {
      if (outcome.failed) await jm.fail(jobId, new Error(text), { code: "siem-search", retryable: false });
      else {
        await jm.checkpoint(jobId, { done: outcome.rows, total: outcome.rows, detail: text });
        await jm.finish(jobId);
      }
    }
    await onDone?.(outcome);
  };
  void work().catch(async (err: unknown) => {
    if ((err as { name?: string })?.name === "AbortError") {
      // The job row is already cancelled; a waiting card (Watson's) hears it too.
      await Promise.resolve(onDone?.(failed(spec, "the search was cancelled"))).catch(() => undefined);
      return;
    }
    ctx.serverLogger.warn(`[crowdstrike-siem] ${spec.caseId}: search failed — ${(err as Error).message}`);
    if (jm && jobId) await jm.fail(jobId, err, { code: "siem-search" }).catch(() => undefined);
    await Promise.resolve(onDone?.(failed(spec, (err as Error).message))).catch(() => undefined);
  });
  return jobId;
}

const SEVERE = ["High", "Critical"] as const;

/**
 * The span of the case's High/Critical forensic events — the same window
 * incidentWindowFromTimeline (linuxPersistImport.ts) takes, without loading the timeline. Each
 * severity is read through the indexed severity filter, so only the severe rows are read, never the
 * whole timeline (#2672). Fewer than two such events: no span. Forensic timeline only (CLAUDE.md §7).
 */
async function severeSpan(ctx: RouteContext, caseId: string) {
  const store = ctx.options.stateStore;
  if (!store) return undefined;
  let lo = Infinity;
  let hi = -Infinity;
  let count = 0;
  for (const severity of SEVERE) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS, severity })) {
      for (const e of batch) {
        // The store interface does not promise to honour the filter; keep the check as a guard.
        if (e.severity !== severity) continue;
        const t = Date.parse(e.timestamp ?? "");
        if (!Number.isFinite(t)) continue;
        count++;
        lo = Math.min(lo, t);
        hi = Math.max(hi, t);
      }
    }
  }
  return count < 2 ? undefined : { start: new Date(lo).toISOString(), end: new Date(hi).toISOString() };
}

async function defaultRange(ctx: RouteContext, caseId: string, maxDays: number) {
  const scope = await new ScopeStore(ctx.store).load(caseId).catch(() => NO_SCOPE);
  const severe = await severeSpan(ctx, caseId).catch(() => undefined);
  return defaultSearchRange(scope, severe, maxDays, Date.now());
}

export function registerCrowdstrikeSiemRoutes(app: Express, ctx: RouteContext): void {
  app.get("/cases/:id/crowdstrike/siem", async (req: Request, res: Response) => {
    const creds = ngsiemCredentialsFromEnv(process.env);
    if (!creds) return res.status(200).json({ configured: false });
    if ((await ctx.store.getCaseMeta(req.params.id).catch(() => null)) === null) {
      return res.status(404).json({ error: "case not found" });
    }
    const limits = readSiemLimits(process.env);
    // The console origin for "Open in Falcon" (#2685): a plain link, never a credential.
    const consoleUrl = falconConsoleOrigin(creds);
    try {
      const range = await defaultRange(ctx, req.params.id, limits.maxWindowDays);
      return res
        .status(200)
        .json({ configured: true, ...limits, defaultRange: range, ...(consoleUrl ? { consoleUrl } : {}) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/crowdstrike/siem/search", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if ((await ctx.store.getCaseMeta(caseId).catch(() => null)) === null) {
      return res.status(404).json({ error: "case not found" });
    }
    const actor = requestAuthentication(req)?.identity.displayName ?? "analyst";
    const prepared = prepareSiemSearch(caseId, (req.body ?? {}) as SiemSearchRequest, actor);
    if (!prepared.ok) return res.status(prepared.status).json({ error: prepared.error });
    try {
      const jobId = await startSiemSearch(ctx, prepared.spec);
      return res.status(202).json({ accepted: true, jobId });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
