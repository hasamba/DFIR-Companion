/**
 * Cloud account read check (#2309).
 *
 *   POST /cases/:id/cloud-accounts/:accountId/check   { sources?, s3Bucket?, s3Prefix? }
 *
 * Makes one READ per selected source with the account's credential and answers which reads worked,
 * which failed and why, in a fixed sentence that also says writes were not tested. It never says the
 * account is read-only. Same gate as collection: WRITE on the case (auth/policy.ts), the account
 * attached to the case, refused on the demo — and audited as "cloud-account-check".
 */
import type { Express } from "express";
import { cloudSafeError } from "../integrations/cloudAccounts/errors.js";
import { parseCloudCheckRequest } from "../integrations/cloudCheck/runCloudCheck.js";
import {
  cloudAccountInCase,
  openCloudAccountForCollect,
  sendCloudRefusal,
  withCloudVault,
} from "./cloudAccountAccess.js";
import type { RouteContext } from "./context.js";

const UNAVAILABLE = "The cloud account check is not available on this server.";
const FAILED = "The cloud account check could not run. Check the server log.";

export function registerCloudAccountCheckRoute(app: Express, ctx: RouteContext): void {
  app.post(
    "/cases/:id/cloud-accounts/:accountId/check",
    withCloudVault(ctx, async (vault, req, res) => {
      const { id: caseId, accountId } = req.params;
      const runner = ctx.options.cloudCheck;
      if (!runner) return res.status(503).json({ error: UNAVAILABLE });
      const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const parsed = parseCloudCheckRequest(found.value.provider, req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const opened = openCloudAccountForCollect(ctx, req, caseId, accountId, "cloud-account-check");
      if (!opened.ok) return sendCloudRefusal(res, opened);
      try {
        const report = await runner(opened.value, parsed.value);
        const counts = report.results.map((r) => `${r.id}=${r.status}`).join(" ");
        ctx.serverLogger.info(
          `[cloud-accounts] check id=${accountId} case=${JSON.stringify(caseId)} ${counts}`,
        );
        return res.json({ report });
      } catch (err) {
        ctx.serverLogger.error(`[cloud-accounts] check id=${accountId}: ${cloudSafeError(err)}`);
        return res.status(500).json({ error: FAILED });
      }
    }),
  );
}
