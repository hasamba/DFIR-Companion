import type { Express, Request, Response } from "express";
import { z } from "zod";
import { resolveProxyHostIdentity } from "../analysis/proxyWorkstationChain.js";
import type { IpExclusionReason } from "../analysis/hostBinding.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
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
 *
 * READS forensic ∪ super-timeline (#1243): an import-time proxy/web-log row can be routed to the
 * super-timeline under the severity gate rather than the forensic timeline (see ARCHITECTURE.md's
 * forensic/super-timeline boundary). This route is a plain analyst-facing read — no AI synthesis in
 * its call graph — so joining both stores is the same recipe threatIntel.ts's ioc-provenance routes
 * already use, not the AI-boundary promotion pattern viewSummary needs. Same full-load tradeoff as
 * the MEMORY note above, extended to the super-timeline read.
 *
 * DISCLOSES `excludedLogonSamples` (#1345): the count of logon samples hostBinding.ts refused to
 * index, by reason. `not-edge-observed` (#1342) once covered every 4624 persisted before its writer
 * stamped provenance; #1352's canonicalProvenanceRestamp.ts re-stamps those on read for the audited
 * writers, so the reason is left for an importer outside that allowlist. On such a case the IP->host
 * binding is absent and a row that used to say `matched` says `no-match` with `caveats: []`;
 * the count is the only signal the analyst gets that exclusion, not absent evidence, is the cause.
 * Route-level counter beside the rows, same shape as `skipped` on velociraptor.ts / import.ts.
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
      const [state, aliasIndex, superEvents] = await Promise.all([
        options.stateStore.load(caseId),
        loadHostAliasIndex(
          {
            ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
            ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
          },
          caseId,
        ),
        options.superTimelineStore
          ? options.superTimelineStore.all(caseId)
          : Promise.resolve<ForensicEvent[]>([]),
      ]);
      const toleranceMs = parsed.data.toleranceMs ?? DEFAULT_TOLERANCE_MS;
      const excluded = new Map<IpExclusionReason, number>();
      const matches = resolveProxyHostIdentity(
        [...state.forensicTimeline, ...superEvents],
        aliasIndex,
        toleranceMs,
        excluded,
      );
      return res.status(200).json({ matches, excludedLogonSamples: Object.fromEntries(excluded) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
