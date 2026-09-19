import type { Express, Request, Response } from "express";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { mobilePermissionChains } from "../analysis/mobilePermissionChain.js";
import type { RouteContext } from "./context.js";

/**
 * Android requested ↔ granted ↔ used permission chains for one subject device (#1363, 932.15's
 * second half). Read-time only, never persisted — the same shape as routes/proxyHostIdentity.ts
 * (#993) and the #1316 matches route: recomputed on every read from the timeline plus the active
 * MobSF attestations (`staticReportAttestationStore`, tool "mobsf") for that device. When the
 * attestation store is absent the join is still computed — every report then reads as an
 * unbound candidate, which is the honest answer, not a 501.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
const DEVICE_MAX = 120; // the LEAPP import route's own bound on the device option (#988)

export function registerMobilePermissionChainRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/mobile-permission-chains", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const device = typeof req.query.device === "string" ? req.query.device.trim() : "";
    if (!device || device.length > DEVICE_MAX) {
      return res.status(400).json({
        error: `device is required: the subject device as named at LEAPP import (1-${DEVICE_MAX} chars)`,
      });
    }
    try {
      const caseId = req.params.id;
      const [state, attestations, aliasIndex] = await Promise.all([
        options.stateStore.load(caseId),
        options.staticReportAttestationStore?.load(caseId) ?? Promise.resolve([]),
        loadHostAliasIndex(
          {
            ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
            ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
          },
          caseId,
        ),
      ]);
      return res
        .status(200)
        .json(mobilePermissionChains({ device, events: state.forensicTimeline, attestations, aliasIndex }));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
