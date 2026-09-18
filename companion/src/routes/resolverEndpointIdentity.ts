import type { Express, Request, Response } from "express";
import { z } from "zod";
import { resolveResolverEndpointIdentity } from "../analysis/dnsResolverEndpointJoin.js";
import type { IpExclusionReason } from "../analysis/hostBinding.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

/**
 * DNS resolver -> endpoint host-identity matches (#996, resolver-endpoint half of #933 item 2) —
 * a DNS Server Analytical row's own `client` IP resolved against hostBinding.ts's own host-identity
 * index (#1158), then checked against that host's OWN endpoint-side DNS record for the same query.
 * Read-time only, recomputed every call, never persisted. Modeled directly on
 * routes/proxyHostIdentity.ts (#993), the working precedent for this shape of join.
 *   - GET /cases/:id/resolver-endpoint-matches[?hostToleranceMs=&queryToleranceMs=]
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * NEVER an unconditional "this is the host" or "this never happened" claim — see
 * dnsResolverEndpointJoin.ts's own header for the forwarding-topology, DHCP-lease, cache-hit and
 * CNAME-chain caveats this route's own output cannot resolve.
 *
 * READS forensic ∪ super-timeline (#1243): an import-time DNS Server Analytical / Sysmon-22 row can
 * be routed to the super-timeline under the severity gate rather than the forensic timeline (see
 * ARCHITECTURE.md's forensic/super-timeline boundary). This route is a plain analyst-facing read —
 * no AI synthesis in its call graph — so joining both stores is the same recipe threatIntel.ts's
 * ioc-provenance routes already use, not the AI-boundary promotion pattern viewSummary needs.
 * Reading the whole super-timeline into memory is the same deliberate full-load tradeoff #1269
 * documents on proxyHostIdentity.ts.
 *
 * DISCLOSES `excludedLogonSamples` (#1345): the count of logon samples hostBinding.ts refused to
 * index, by reason (`not-edge-observed` since #1342 — every 4624 persisted before its writer stamped
 * provenance, which `upgradeForensicEvent` never revisits). On such a case every IP->host binding
 * vanishes and a row that used to say `matched` says `no-match` with `caveats: []`; the count is the
 * only signal the analyst gets that a re-import, not absent evidence, is the cause. Route-level
 * counter beside the rows, same shape as `skipped` on velociraptor.ts / import.ts. Repair is #1352.
 */

// Stage 1 (IP -> host): the same kind of "how stale is this logon sample" question
// proxyHostIdentity.ts asks, so it reuses that route's own bounds unchanged.
const DEFAULT_HOST_TOLERANCE_MS = 21_600_000; // 6 hours
const MAX_HOST_TOLERANCE_MS = 2_592_000_000; // 30 days

// Stage 2 (query timing): a resolver row and its OWN endpoint-side log line describe the SAME real
// DNS transaction, seconds apart in practice — a multi-hour window would let an unrelated later
// query on the same host false-match as "confirmed." Tight default, a day at most.
const DEFAULT_QUERY_TOLERANCE_MS = 300_000; // 5 minutes
const MAX_QUERY_TOLERANCE_MS = 86_400_000; // 24 hours

const querySchema = z.object({
  hostToleranceMs: z.coerce.number().int().positive().max(MAX_HOST_TOLERANCE_MS).optional(),
  queryToleranceMs: z.coerce.number().int().positive().max(MAX_QUERY_TOLERANCE_MS).optional(),
});

export function registerResolverEndpointIdentityRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/resolver-endpoint-matches", async (req: Request, res: Response) => {
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
      const hostToleranceMs = parsed.data.hostToleranceMs ?? DEFAULT_HOST_TOLERANCE_MS;
      const queryToleranceMs = parsed.data.queryToleranceMs ?? DEFAULT_QUERY_TOLERANCE_MS;
      const excluded = new Map<IpExclusionReason, number>();
      const matches = resolveResolverEndpointIdentity(
        [...state.forensicTimeline, ...superEvents],
        aliasIndex,
        hostToleranceMs,
        queryToleranceMs,
        excluded,
      );
      return res.status(200).json({ matches, excludedLogonSamples: Object.fromEntries(excluded) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
