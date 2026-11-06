/**
 * The cloud collection pre-check (#2312), shown before the analyst confirms a start:
 *
 *   POST /cases/:id/cloud-collect/precheck   { accountId, sources[], start, end, overlapMinutes? }
 *
 * Per source: the windows outside retention, the "off by default" warnings and the ingestion-delay
 * overlap; for a provider with a shared daily quota (Microsoft), this companion's own use of it for
 * the account's tenant (an ESTIMATE — never "what the tenant has left") and the estimated cost.
 * No credential is opened: the tenant id is in the account's non-secret settings. Needs write on
 * the case and is refused on the public demo, like every cloud-collect route (auth/policy.ts).
 */
import type { Express } from "express";
import type { CloudAccountView } from "../integrations/cloudAccounts/types.js";
import type { QueryBudget } from "../integrations/cloudCollect/collectBudget.js";
import { precheckSource } from "../integrations/cloudCollect/collectCoverage.js";
import type { CloudCollectProvider, CollectWindow } from "../integrations/cloudCollect/collectTypes.js";
import { cloudAccountInCase, sendCloudRefusal, withCloudVault } from "./cloudAccountAccess.js";
import type { RouteContext } from "./context.js";

const MAX_OVERLAP_MINUTES = 1440;

/** `overlapMinutes` from a start or pre-check body: one value for every source, or the defaults. */
export function parseOverlap(
  body: unknown,
  sources: readonly string[],
): Record<string, number> | undefined | string {
  const raw = ((body ?? {}) as Record<string, unknown>).overlapMinutes;
  if (raw === undefined || raw === null || raw === "") return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > MAX_OVERLAP_MINUTES)
    return `The overlap must be 0–${MAX_OVERLAP_MINUTES} minutes.`;
  return Object.fromEntries(sources.map((s) => [s, Math.round(n * 60_000)]));
}

/** The account's shared-quota budget, when its provider has one and the server keeps a count. */
export function quotaBudgetFor(
  ctx: RouteContext,
  provider: CloudCollectProvider,
  account: Pick<CloudAccountView, "settings">,
): QueryBudget | undefined {
  const store = ctx.options.cloudQueryUsage;
  const scope = provider.quotaScope?.(account.settings as unknown as Record<string, unknown>);
  if (!store || !scope) return undefined;
  return store.budget(scope, ctx.options.cloudQueryBudget ?? 50);
}

/** True when some chosen source spends from the shared quota. */
export function spendsQuota(provider: CloudCollectProvider, sources: readonly string[]): boolean {
  return provider.sources.some((s) => sources.includes(s.id) && (s.queryCost ?? 0) > 0);
}

async function quotaView(budget: QueryBudget | undefined, provider: CloudCollectProvider, sources: string[]) {
  if (!budget || !spendsQuota(provider, sources)) return null;
  let used: number;
  try {
    used = await budget.used();
  } catch (err) {
    // An unreadable quota record fails closed: the start will be refused with the same reason.
    const note = err instanceof Error ? err.message : String(err);
    return { usedByCompanion: null, budget: budget.limit, estimatedQueries: 0, enough: false, note };
  }
  const minimum = provider.sources
    .filter((s) => sources.includes(s.id))
    .reduce((n, s) => n + (s.queryCost ?? 0), 0);
  return {
    usedByCompanion: used,
    budget: budget.limit,
    estimatedQueries: minimum,
    enough: used + minimum <= budget.limit,
    note:
      `Used by this companion (estimate): ${used} of its ${budget.limit} query submissions for this ` +
      `tenant in the last 24 h. This collection needs at least ${minimum}; a window that must split ` +
      "into N pieces costs about 2N−1. Other tools share the tenant's quota and are not counted here.",
  };
}

export function registerCloudCollectPrecheck(
  app: Express,
  ctx: RouteContext,
  parse: (body: unknown) => { accountId: string; sources: string[]; window: CollectWindow } | string,
): void {
  app.post(
    "/cases/:id/cloud-collect/precheck",
    withCloudVault(ctx, async (vault, req, res) => {
      const caseId = req.params.id;
      if (!(await ctx.store.caseExists(caseId)))
        return res.status(404).json({ error: "Case not found or access denied." });
      const parsed = parse(req.body);
      if (typeof parsed === "string") return res.status(400).json({ error: parsed });
      const overlap = parseOverlap(req.body, parsed.sources);
      if (typeof overlap === "string") return res.status(400).json({ error: overlap });
      const found = cloudAccountInCase(ctx, req, vault, caseId, parsed.accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const provider = ctx.options.cloudCollectProviders?.[found.value.provider];
      if (!provider)
        return res.status(501).json({ error: "Live collection from this provider is not available yet." });
      const chosen = provider.sources.filter((s) => parsed.sources.includes(s.id));
      if (chosen.length !== parsed.sources.length)
        return res.status(400).json({ error: "Unknown log source." });
      const nowMs = Date.now();
      return res.json({
        sources: chosen.map((s) => precheckSource(s, parsed.window, nowMs, overlap)),
        quota: await quotaView(quotaBudgetFor(ctx, provider, found.value), provider, parsed.sources),
      });
    }),
  );
}
