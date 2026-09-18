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
 * MEMORY (#1186): this route calls `stateStore.load()` — the full InvestigationState, including
 * the entire forensic timeline — rather than `StateStore.forensicTimelineBatches()`, the
 * streaming path crossCase.ts's own "loadOverview, not load: the forensic timeline is by far the
 * largest kind" precedent uses for a read path that only needs events. Deliberate, not an
 * oversight: `resolveProxyHostIdentity` needs `buildHostBindingIndex` built from every logon-shaped
 * event before it can resolve a single proxy row against it, so a true streaming rewrite needs TWO
 * passes over the timeline (one to collect logons for the index, one to resolve every event
 * against it) and a public-contract change to `proxyWorkstationChain.ts` to make that possible
 * without holding the whole array — real, but a bigger change than this route's own severity
 * (behavior is correct; this is a peak-memory concern, not a correctness one) warrants without
 * concrete evidence it is an actual bottleneck in a real case. If it becomes one, batch through
 * `forensicTimelineBatches()`: accumulate only logon-shaped events into the index-building pass,
 * then a second pass resolving each batch against the already-built index.
 */

const DEFAULT_TOLERANCE_MS = 21_600_000; // 6 hours — no existing precedent value in this codebase
// A ceiling, not a recommendation: past this, "same IP" stops being a meaningful proxy for "same
// lease/machine" at all (DHCP churn, VPN pools) and a `matched` outcome would overclaim more than
// this feature's own disclosure can carry. 30 days.
const MAX_TOLERANCE_MS = 2_592_000_000;

// toleranceMs=0 is accepted, not rejected (#1189): resolveIpAtTime/resolveAccountAtTime compare
// with `Math.abs(diff) <= toleranceMs`, so 0 is a real, meaningful value — an exact-instant match —
// not a degenerate one.
const querySchema = z.object({
  toleranceMs: z.coerce.number().int().nonnegative().max(MAX_TOLERANCE_MS).optional(),
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
