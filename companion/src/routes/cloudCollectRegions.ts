/**
 * The region picker of the Cloud Collection panel (#2363):
 *
 *   POST /cases/:id/cloud-collect/regions   { accountId }  →  { regions, home, source, note? }
 *
 * The regions enabled on an AWS account, asked with the read-only `ec2:DescribeRegions`; without
 * the permission the fallback list comes back with `source: "fallback"` and the disclosure in
 * `note`. Listing signs in with the account's credential, so it opens the account through
 * openCloudAccountForCollect (attachment, case-write and demo checks) and is audited as
 * "cloud-account-regions". Needs write on the case and is refused on the public demo, like every
 * cloud-collect route (auth/policy.ts). No response carries a secret.
 *
 * Also parses the start body's region choice (`regions`, `excludeRegions`).
 */
import type { Express } from "express";
import type { CloudCollectProvider, CollectRegionChoice } from "../integrations/cloudCollect/collectTypes.js";
import { AWS_REGION_NAME } from "../integrations/cloudCollect/aws/awsRegions.js";
import { AwsCollectSetupError } from "../integrations/cloudCollect/aws/awsCollectClients.js";
import {
  cloudAccountInCase,
  openCloudAccountForCollect,
  sendCloudRefusal,
  withCloudVault,
} from "./cloudAccountAccess.js";
import type { RouteContext } from "./context.js";

const MAX_REGIONS = 60;
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,80}$/;
export const NO_REGION_PICKER = "This provider has no regions to pick.";

function regionList(raw: unknown, field: string): string[] | undefined | string {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw) || raw.length > MAX_REGIONS)
    return `${field} must be a list of at most ${MAX_REGIONS} regions.`;
  if (!raw.every((r) => typeof r === "string" && AWS_REGION_NAME.test(r)))
    return `${field} holds a value that is not a region name.`;
  return [...new Set(raw as string[])];
}

/**
 * The picker's choice from a start or pre-check body: undefined when the body has none. A choice
 * that ticks nothing is refused here — the panel blocks it too.
 */
export function parseRegionChoice(body: unknown): CollectRegionChoice | undefined | string {
  const b = (body ?? {}) as Record<string, unknown>;
  const regions = regionList(b.regions, "regions");
  if (typeof regions === "string") return regions;
  const excludeRegions = regionList(b.excludeRegions, "excludeRegions");
  if (typeof excludeRegions === "string") return excludeRegions;
  if (!regions && !excludeRegions) return undefined;
  if (regions && !regions.length) return "Tick at least one region.";
  return { ...(regions ? { regions } : {}), ...(excludeRegions ? { excludeRegions } : {}) };
}

/** A region choice is refused for a provider without a picker (only AWS has one). */
export function regionChoiceRefusal(
  provider: CloudCollectProvider,
  choice: CollectRegionChoice | undefined,
): string | null {
  return choice && !provider.regionPicker ? "Regions can only be picked for an AWS account." : null;
}

export function registerCloudCollectRegions(app: Express, ctx: RouteContext): void {
  app.post(
    "/cases/:id/cloud-collect/regions",
    withCloudVault(ctx, async (vault, req, res) => {
      const caseId = req.params.id;
      if (!(await ctx.store.caseExists(caseId)))
        return res.status(404).json({ error: "Case not found or access denied." });
      const accountId = ((req.body ?? {}) as Record<string, unknown>).accountId;
      if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId))
        return res.status(400).json({ error: "Pick a cloud account." });
      const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const provider = ctx.options.cloudCollectProviders?.[found.value.provider];
      if (!provider)
        return res.status(501).json({ error: "Live collection from this provider is not available yet." });
      if (!provider.regionPicker) return res.status(501).json({ error: NO_REGION_PICKER });
      const opened = openCloudAccountForCollect(ctx, req, caseId, accountId, "cloud-account-regions");
      if (!opened.ok) return sendCloudRefusal(res, opened);
      const session = provider.open(opened.value);
      try {
        if (!session.listRegions) return res.status(501).json({ error: NO_REGION_PICKER });
        const listing = await session.listRegions();
        return res.json(listing);
      } catch (err) {
        // An account that cannot sign in as stored says why in fixed text; anything else is logged.
        if (err instanceof AwsCollectSetupError) return res.status(400).json({ error: err.message });
        ctx.serverLogger.error(
          `[cloud-collect] region listing failed: ${err instanceof Error ? err.name : "error"}`,
        );
        return res.status(502).json({ error: "The regions could not be listed. Check the server log." });
      } finally {
        await Promise.resolve(session.close?.()).catch(() => {});
      }
    }),
  );
}
