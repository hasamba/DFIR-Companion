import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { buildDiagnosticsPayload } from "./diagnosticsReport.js";
import { buildSupportBundleZip } from "../reports/supportBundleBuilder.js";
import { supportBundleFilename } from "../analysis/supportBundleZip.js";
import { CustomEntitiesStore } from "../analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { getAppVersion } from "../version.js";

/**
 * Redacted support bundle (#1735): one zip an analyst can send with a bug report — the Diagnostics
 * report, the session log, the always-on debug log, optionally the open case's log, and the shape of
 * each failed import, all through one support redactor. See reports/supportBundleBuilder.ts.
 *
 * The body carries SELECTIONS only (`caseId`, `includeCaseLog`), never text: the diagnostics report
 * is regenerated here, so nothing a client sends can land in the zip. Authorization comes from the
 * central policy — `/diagnostics` is a global-admin prefix in team mode (auth/policy.ts). This route
 * is global, so it does not pass the /cases/:id lock gate; it applies the unlock check itself.
 */
export function registerSupportBundleRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const customEntities = new CustomEntitiesStore(store);
  const discoveredEntities = new DiscoveredEntitiesStore(store);

  app.post("/diagnostics/support-bundle", async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as { caseId?: unknown; includeCaseLog?: unknown };
    const caseId = typeof body.caseId === "string" && body.caseId !== "" ? body.caseId : undefined;
    if (caseId !== undefined && !isValidCaseId(caseId)) {
      return res.status(400).json({ error: "invalid case id" });
    }
    try {
      const metas = new Map((await store.listCases()).map((m) => [m.caseId, m]));
      const canSee = (id: string): boolean => {
        const meta = metas.get(id);
        if (!meta) return false;
        return !meta.password || ctx.readUnlockState(req, id, meta.password.salt).unlocked;
      };
      const payload = await buildDiagnosticsPayload(ctx);
      const stateStore = options.stateStore;
      const zip = await buildSupportBundleZip(
        {
          store,
          loadState: stateStore ? (id) => stateStore.load(id) : undefined,
          loadCustomEntities: (id) => customEntities.load(id),
          loadDiscovered: (id) => discoveredEntities.load(id),
          logPaths: getServerLogger().paths?.() ?? null,
          recentImportFailures: ctx.recentImportFailures,
          canSee,
        },
        {
          generatedAt: payload.report.generatedAt,
          version: options.appVersion ?? getAppVersion(),
          diagnosticsText: payload.text,
          supportJson: payload.supportPreview,
          caseId,
          includeCaseLog: body.includeCaseLog === true,
        },
      );
      res.type("application/zip");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${supportBundleFilename(payload.report.generatedAt)}"`,
      );
      res.setHeader("Cache-Control", "no-store");
      return res.send(zip);
    } catch (err) {
      getServerLogger().error(`[support-bundle] build failed: ${(err as Error).message}`);
      return res.status(500).json({ error: "could not build the support bundle — see the server log" });
    }
  });
}
