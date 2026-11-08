/**
 * Live cloud collection (#2311). Every route needs WRITE on the case, GET included, and the public
 * demo refuses all of them (auth/policy.ts CASE_CLOUD_WRITE_PATTERN; composition/httpStack.ts).
 *
 *   GET  /cases/:id/cloud-collect                        providers available here + the case's collections
 *   POST /cases/:id/cloud-collect                        { accountId, sources[], start, end } — start
 *   POST /cases/:id/cloud-collect/:collectionId/resume   resume an interrupted / failed / partial one
 *   POST /cases/:id/cloud-collect/precheck               retention, overlap and quota before a start (#2312)
 *   POST /cases/:id/cloud-collect/regions                the AWS region picker's list (#2363)
 *
 * A credential is opened ONLY through openCloudAccountForCollect — on start and again on every
 * resume — so the attachment, case-write and demo checks and the audit entry are never skipped.
 * No response carries a secret: collections hold identifiers, hashes and counts only.
 */
import type { Express, Request, Response } from "express";
import { CLOUD_PROVIDERS, type CloudProvider } from "../integrations/cloudAccounts/types.js";
import type { CloudAccountVault } from "../integrations/cloudAccounts/cloudAccountVault.js";
import { nodeCollectFs } from "../integrations/cloudCollect/collectFs.js";
import { createCollection } from "../integrations/cloudCollect/collectEngine.js";
import {
  isCollectionId,
  listCollections,
  newCollectionId,
  readCollection,
} from "../integrations/cloudCollect/collectStore.js";
import type { CloudCollectProvider, CollectWindow } from "../integrations/cloudCollect/collectTypes.js";
import { budgetStopReason, type QueryBudget } from "../integrations/cloudCollect/collectBudget.js";
import { runInCaseScope } from "../storage/caseIncarnation.js";
import { getAppVersion } from "../version.js";
import {
  cloudAccountInCase,
  openCloudAccountForCollect,
  sendCloudRefusal,
  withCloudVault,
} from "./cloudAccountAccess.js";
import {
  collectionDir,
  launchCollectJob,
  parkResumeSession,
  registerCloudCollectResumeHandler,
  unparkResumeSession,
} from "./cloudCollectJob.js";
import type { RouteContext } from "./context.js";
import {
  parseOverlap,
  quotaBudgetFor,
  registerCloudCollectPrecheck,
  spendsQuota,
} from "./cloudCollectPrecheck.js";
import {
  parseRegionChoice,
  regionChoiceRefusal,
  registerCloudCollectRegions,
} from "./cloudCollectRegions.js";

const CASE_NOT_FOUND = "Case not found or access denied.";
const PROVIDER_LABEL: Record<CloudProvider, string> = { aws: "AWS", gcp: "GCP", microsoft: "Microsoft" };
const PROVIDER_ISSUE: Record<CloudProvider, string> = { aws: "#2313", gcp: "#2314", microsoft: "#2315" };
const MAX_WINDOW_DAYS = 400;

function notAvailable(provider: CloudProvider): string {
  return (
    `Live collection from ${PROVIDER_LABEL[provider]} is not available in this version yet ` +
    `(${PROVIDER_ISSUE[provider]}). Import an export of the logs instead.`
  );
}

function providerList(ctx: RouteContext) {
  return CLOUD_PROVIDERS.map((provider) => {
    const p = ctx.options.cloudCollectProviders?.[provider];
    return {
      provider,
      label: PROVIDER_LABEL[provider],
      available: !!p,
      sources: p ? p.sources.map((s) => ({ id: s.id, label: s.label })) : [],
      ...(p?.regionPicker ? { regionPicker: true } : {}),
      ...(p?.notes?.length ? { notes: [...p.notes] } : {}),
      ...(p ? {} : { notice: notAvailable(provider) }),
    };
  });
}

type StartBody = { accountId: string; sources: string[]; window: CollectWindow };

function parseStart(body: unknown): StartBody | string {
  const b = (body ?? {}) as Record<string, unknown>;
  if (typeof b.accountId !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(b.accountId))
    return "Pick a cloud account.";
  const sources = Array.isArray(b.sources) ? b.sources : [];
  if (
    !sources.length ||
    sources.length > 20 ||
    !sources.every((s) => typeof s === "string" && /^[a-z0-9-]{1,40}$/.test(s))
  )
    return "Pick at least one log source.";
  const start = typeof b.start === "string" ? Date.parse(b.start) : NaN;
  const end = typeof b.end === "string" ? Date.parse(b.end) : NaN;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "The time window needs a valid start and end.";
  if (start >= end) return "The window's start must be before its end.";
  if (end - start > MAX_WINDOW_DAYS * 86_400_000)
    return `The window may span at most ${MAX_WINDOW_DAYS} days.`;
  return {
    accountId: b.accountId,
    sources: [...new Set(sources as string[])],
    window: { start: new Date(start).toISOString(), end: new Date(end).toISOString() },
  };
}

/** The account's provider adapter, after the case-scoped visibility check (no secret opened yet). */
function providerFor(
  ctx: RouteContext,
  req: Request,
  vault: CloudAccountVault,
  caseId: string,
  accountId: string,
):
  | { ok: true; provider: CloudCollectProvider; name: string; budget?: QueryBudget }
  | { ok: false; status: number; error: string } {
  const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
  if (!found.ok) return found;
  const provider = ctx.options.cloudCollectProviders?.[found.value.provider];
  if (!provider) return { ok: false, status: 501, error: notAvailable(found.value.provider) };
  const budget = quotaBudgetFor(ctx, provider, found.value);
  return { ok: true, provider, name: found.value.name, ...(budget ? { budget } : {}) };
}

/** Refuse a start whose tenant budget is already used up: it would send nothing. */
async function budgetRefusal(
  budget: QueryBudget | undefined,
  provider: CloudCollectProvider,
  sources: string[],
) {
  if (!budget || !spendsQuota(provider, sources)) return null;
  let used: number;
  try {
    used = await budget.used();
  } catch (err) {
    return err instanceof Error ? err.message : String(err); // an unreadable record fails closed
  }
  if (used < budget.limit) return null;
  return budgetStopReason(used, budget.limit);
}

function registerList(app: Express, ctx: RouteContext): void {
  app.get(
    "/cases/:id/cloud-collect",
    withCloudVault(ctx, async (_vault, req, res) => {
      const caseId = req.params.id;
      if (!(await ctx.store.caseExists(caseId))) return res.status(404).json({ error: CASE_NOT_FOUND });
      const collections = await listCollections(nodeCollectFs, ctx.store.caseDir(caseId));
      return res.json({ providers: providerList(ctx), collections });
    }),
  );
}

function registerStart(app: Express, ctx: RouteContext): void {
  app.post(
    "/cases/:id/cloud-collect",
    withCloudVault(ctx, async (vault, req, res) => {
      const caseId = req.params.id;
      const manager = ctx.options.jobManager;
      if (!manager) return res.status(503).json({ error: "Background jobs are not available." });
      if (!(await ctx.store.caseExists(caseId))) return res.status(404).json({ error: CASE_NOT_FOUND });
      const parsed = parseStart(req.body);
      if (typeof parsed === "string") return res.status(400).json({ error: parsed });
      const found = providerFor(ctx, req, vault, caseId, parsed.accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const known = new Set(found.provider.sources.map((s) => s.id));
      const unknown = parsed.sources.filter((s) => !known.has(s));
      if (unknown.length)
        return res.status(400).json({ error: `Unknown log source: ${unknown.join(", ")}.` });
      const overlapMs = parseOverlap(req.body, parsed.sources);
      if (typeof overlapMs === "string") return res.status(400).json({ error: overlapMs });
      const regionChoice = parseRegionChoice(req.body);
      if (typeof regionChoice === "string") return res.status(400).json({ error: regionChoice });
      const regionRefused = regionChoiceRefusal(found.provider, regionChoice);
      if (regionRefused) return res.status(400).json({ error: regionRefused });
      const refused = await budgetRefusal(found.budget, found.provider, parsed.sources);
      if (refused) return res.status(409).json({ error: refused });
      if (manager.hasActive(caseId, "cloud-collect"))
        return res.status(409).json({ error: "A cloud collection is already running for this case." });
      const opened = openCloudAccountForCollect(ctx, req, caseId, parsed.accountId);
      if (!opened.ok) return sendCloudRefusal(res, opened);
      const session = found.provider.open(opened.value);
      const collectionId = newCollectionId();
      const dir = collectionDir(ctx, caseId, collectionId);
      const jobId = await launchCollectJob(ctx, manager, {
        caseId,
        dir,
        ref: { provider: found.provider, session, ...(found.budget ? { budget: found.budget } : {}) },
        resume: false,
        label: `cloud collect: ${PROVIDER_LABEL[found.provider.provider]} ${found.name}`,
        parameters: { collectionId, accountId: parsed.accountId, provider: found.provider.provider },
        before: async (id, signal) =>
          createCollection(
            nodeCollectFs,
            session,
            {
              dir,
              collectionId,
              caseId,
              accountId: parsed.accountId,
              accountName: found.name,
              provider: found.provider.provider,
              sources: parsed.sources,
              window: parsed.window,
              // #2363: the region scope, decided now and recorded in the header (resume reuses it).
              filters: session.prepareFilters ? await session.prepareFilters(regionChoice ?? {}, signal) : {},
              companionVersion: getAppVersion(),
              jobId: id,
              ...(overlapMs ? { overlapMs } : {}),
            },
            () => new Date().toISOString(),
            signal,
          ),
      });
      return res.status(202).json({ collectionId, jobId });
    }),
  );
}

async function resumeCollection(ctx: RouteContext, vault: CloudAccountVault, req: Request, res: Response) {
  const caseId = req.params.id;
  const collectionId = req.params.collectionId;
  const manager = ctx.options.jobManager;
  if (!manager) return res.status(503).json({ error: "Background jobs are not available." });
  if (!isCollectionId(collectionId)) return res.status(404).json({ error: "Collection not found." });
  const dir = collectionDir(ctx, caseId, collectionId);
  const summary = await readCollection(nodeCollectFs, dir);
  if (!summary) return res.status(404).json({ error: "Collection not found." });
  const cp = summary.checkpoint;
  if (cp.status === "complete") return res.status(409).json({ error: "This collection is complete." });
  const existing = cp.jobId ? manager.get(cp.jobId) : undefined;
  if (existing && (existing.status === "running" || existing.status === "queued"))
    return res.status(409).json({ error: "This collection is already running." });
  const found = providerFor(ctx, req, vault, caseId, cp.accountId);
  if (!found.ok) return sendCloudRefusal(res, found);
  const opened = openCloudAccountForCollect(ctx, req, caseId, cp.accountId); // again, on every resume
  if (!opened.ok) return sendCloudRefusal(res, opened);
  const ref = {
    provider: found.provider,
    session: found.provider.open(opened.value),
    ...(found.budget ? { budget: found.budget } : {}),
  };
  if (existing && (existing.status === "interrupted" || existing.status === "failed")) {
    parkResumeSession(existing.id, ref);
    const result = await runInCaseScope(ctx.store.casesRoot, caseId, () => manager.resume(existing.id));
    if (result.ok) return res.status(202).json({ collectionId, jobId: existing.id });
    unparkResumeSession(existing.id);
    // The job ledger refused the requeue (#2409): the row is still resumable, so a fresh job would
    // only duplicate the collection. Say so and let the analyst retry.
    if (result.reason === "ledger-write-failed") {
      return res
        .status(503)
        .json({ error: "Could not record the resume. Nothing was restarted; try again." });
    }
    // a spent or cancelled row: a new job carries the collection on
  }
  const jobId = await launchCollectJob(ctx, manager, {
    caseId,
    dir,
    ref,
    resume: true,
    label: `cloud collect (resumed): ${PROVIDER_LABEL[found.provider.provider]} ${found.name}`,
    parameters: { collectionId, accountId: cp.accountId, provider: found.provider.provider },
  });
  return res.status(202).json({ collectionId, jobId });
}

export function registerCloudCollectRoutes(app: Express, ctx: RouteContext): void {
  registerCloudCollectResumeHandler(ctx);
  registerList(app, ctx);
  registerStart(app, ctx);
  registerCloudCollectPrecheck(app, ctx, parseStart);
  registerCloudCollectRegions(app, ctx);
  app.post(
    "/cases/:id/cloud-collect/:collectionId/resume",
    withCloudVault(ctx, (vault, req, res) => resumeCollection(ctx, vault, req, res)),
  );
}
