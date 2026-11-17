// Watson's CrowdStrike Next-Gen SIEM search seams (#2666): what running a cs_search card needs. It
// starts the SAME `siem-search` job as the analyst's Run on a CQL hunt (crowdstrikeSiemSearch.ts), so
// the rows are stored as evidence and imported through the normal settle seam; the job's outcome is
// saved on the card with one `hunt` case event that wakes Watson.

import { readSiemLimits, siemConfigured, type SiemSearchOutcome } from "../analysis/siemSearch.js";
import { withCsResult } from "../analysis/ai/watson/crowdstrike/csSearchWatch.js";
import { fingerprintStoreFor } from "../analysis/ai/watson/velo/fingerprintIndex.js";
import type { CsSearchDeps } from "../analysis/ai/watson/writers/csSearchWriter.js";
import type { RouteContext } from "./context.js";
import { prepareSiemSearch, startSiemSearch } from "./crowdstrikeSiemSearch.js";
import { isFrozenCase } from "./importCaseGuard.js";

/** Save the search's outcome on its card and note its `hunt` event, once; then wake Watson. */
export async function noteCsSearchResult(
  ctx: RouteContext,
  caseId: string,
  proposalId: string,
  outcome: SiemSearchOutcome,
): Promise<void> {
  const chatStore = ctx.options.watsonChatStore;
  if (!chatStore) return;
  try {
    let sent = false;
    await chatStore.update(caseId, (c) => {
      const r = withCsResult(c, proposalId, outcome, new Date().toISOString());
      sent = r.sent;
      return r.chat;
    });
    if (!sent) return;
    ctx.options.onWatson?.(caseId);
    ctx.watsonWake?.(caseId);
  } catch (err) {
    ctx.serverLogger.warn(
      `[watson] ${caseId}: could not note the CrowdStrike search result — ${(err as Error).message}`,
    );
  }
}

export function watsonCsSearchDeps(ctx: RouteContext): CsSearchDeps {
  return {
    limits: () => (siemConfigured(process.env) ? readSiemLimits(process.env) : null),
    start: async (caseId, req, actor, proposalId) => {
      const prepared = prepareSiemSearch(caseId, req, actor);
      if (!prepared.ok) throw new Error(prepared.error);
      if (prepared.spec.repository !== req.repository)
        throw new Error("the SIEM repository changed in Settings");
      const jobId = await startSiemSearch(
        ctx,
        prepared.spec,
        (outcome) => noteCsSearchResult(ctx, caseId, proposalId, outcome),
        { parameters: { proposalId }, idempotencyKey: `watson-cs:${caseId}:${proposalId}` },
      );
      return { jobId };
    },
    fingerprints: fingerprintStoreFor(ctx.store),
    isFrozen: (caseId) => isFrozenCase(ctx.store, caseId),
    jobFor: (caseId, proposalId) => {
      const job = ctx.options.jobManager
        ?.list(caseId)
        .find((j) => j.kind === "siem-search" && j.parameters?.proposalId === proposalId);
      return job
        ? { jobId: job.id, status: job.status, ...(job.detail ? { detail: job.detail } : {}) }
        : undefined;
    },
  };
}
