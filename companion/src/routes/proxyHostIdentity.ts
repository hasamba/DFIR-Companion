import type { Express, Request, Response } from "express";
import { z } from "zod";
import { resolveProxyHostIdentity } from "../analysis/proxyWorkstationChain.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import type { RouteContext } from "./context.js";

/**
 * Proxy -> workstation host-identity matches (#993, proxy->workstation half of #933 item 1) — a
 * proxy/web-log event's own `network.source.address` AND (when the record carries one) its own
 * authenticated `account.name`, each resolved against hostBinding.ts's own host-identity index
 * (#1156). Read-time only, recomputed every call, never persisted.
 *   - GET /cases/:id/proxy-host-identity-matches[?toleranceMs=]
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * NEVER an unconditional "this is the workstation" claim — see proxyWorkstationChain.ts's own
 * header for the sensor-topology, DHCP-lease and account-sharing caveats this route's own output
 * cannot resolve.
 *
 * Uses `stateStore.load()` (the FULL state), not `loadOverview()` or `forensicTimelineBatches()`
 * (#1186): this route needs the whole forensicTimeline (buildHostBindingIndex/
 * resolveProxyHostIdentity both scan it once, index-first, and offer no incremental-batch form),
 * and every comparable read-only join route in this codebase (dnsCrossUploadConnMatches.ts,
 * dnsEndpointCrossUploadConnMatches.ts, resolverEndpointIdentity.ts) already accepts an
 * O(events) full-load per call. A future purpose-built streaming query would bound peak memory
 * further, but is not a small change today — this is a deliberate choice, not an oversight.
 */

const DEFAULT_TOLERANCE_MS = 21_600_000; // 6 hours — no existing precedent value in this codebase
// A ceiling, not a recommendation: past this, "same IP" stops being a meaningful proxy for "same
// lease/machine" at all (DHCP churn, VPN pools) and a `matched` outcome would overclaim more than
// this feature's own disclosure can carry. 30 days.
const MAX_TOLERANCE_MS = 2_592_000_000;

const querySchema = z.object({
  toleranceMs: z.coerce.number().int().positive().max(MAX_TOLERANCE_MS).optional(),
});

export function registerProxyHostIdentityRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/proxy-host-identity-matches", async (req: Request, res: Response) => {
    if (!options.stateStore) {
      return res.status(501).json({ error: "state store not configured" });
    }
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.message });
    try {
      const caseId = req.params.id;
      const [state, aliasIndex] = await Promise.all([
        options.stateStore.load(caseId),
        loadHostAliasIndex(
          {
            ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
            ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
          },
          caseId,
        ),
      ]);
      const toleranceMs = parsed.data.toleranceMs ?? DEFAULT_TOLERANCE_MS;
      const matches = resolveProxyHostIdentity(state.forensicTimeline, aliasIndex, toleranceMs);
      return res.status(200).json({ matches });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
