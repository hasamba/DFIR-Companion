import type { Express, Request, Response } from "express";
import { z } from "zod";
import { resolveEndpointCrossUploadDnsConnLeads } from "../analysis/dnsEndpointCrossUploadConnJoin.js";
import type { IpExclusionReason } from "../analysis/hostBinding.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import type { RouteContext } from "./context.js";

/**
 * Windows endpoint DNS query -> connection, cross-upload (#996, the last query-to-connection pair)
 * — a Sysmon 22 / DNS-Client row's own returned address matched against a connection recorded in a
 * SEPARATE upload, via hostBinding.ts's own host-identity index (#1158) on the connection's source
 * IP. Read-time only, recomputed every call, never persisted. Modeled on
 * routes/dnsCrossUploadConnMatches.ts (#1248) plus routes/resolverEndpointIdentity.ts's own
 * aliasIndex load.
 *   - GET /cases/:id/endpoint-dns-connection-cross-upload-matches[?hostToleranceMs=&windowSeconds=]
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * NEVER an unconditional "this host connected" or "this never happened" claim — see
 * dnsEndpointCrossUploadConnJoin.ts's own header for the forwarding-topology, DHCP-lease,
 * aggregation-width and other-host caveats this route's own output cannot resolve.
 *
 * DISCLOSES `excludedLogonSamples` (#1345): the count of logon samples hostBinding.ts refused to
 * index, by reason (`not-edge-observed` since #1342 — every 4624 persisted before its writer stamped
 * provenance, which `upgradeForensicEvent` never revisits). On such a case every IP->host binding
 * vanishes and a lead that used to say "connected inside the window" says "no connection found in
 * this case"; the count is the only signal the analyst gets that a re-import, not absent evidence,
 * is the cause. Route-level counter beside the rows, same shape as `skipped` on velociraptor.ts /
 * import.ts. Repair is #1352.
 */

// Same "how stale is this logon sample" question dnsResolverEndpointJoin.ts and
// proxyWorkstationChain.ts already answer with these exact bounds — a fourth, different number for
// the same question would be its own inconsistency.
const DEFAULT_HOST_TOLERANCE_MS = 21_600_000; // 6 hours
const MAX_HOST_TOLERANCE_MS = 2_592_000_000; // 30 days

// Same query-to-connection gap question dnsCrossUploadConnJoin.ts already answers with these bounds.
const DEFAULT_WINDOW_SECONDS = 300; // 5 minutes
const MAX_WINDOW_SECONDS = 86_400; // 24 hours

const querySchema = z.object({
  hostToleranceMs: z.coerce.number().int().positive().max(MAX_HOST_TOLERANCE_MS).optional(),
  windowSeconds: z.coerce.number().int().positive().max(MAX_WINDOW_SECONDS).optional(),
});

export function registerDnsEndpointCrossUploadConnRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/endpoint-dns-connection-cross-upload-matches", async (req: Request, res: Response) => {
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
      const hostToleranceMs = parsed.data.hostToleranceMs ?? DEFAULT_HOST_TOLERANCE_MS;
      const windowSeconds = parsed.data.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
      const excluded = new Map<IpExclusionReason, number>();
      const matches = resolveEndpointCrossUploadDnsConnLeads(
        state.forensicTimeline,
        aliasIndex,
        hostToleranceMs,
        windowSeconds,
        excluded,
      );
      return res.status(200).json({ matches, excludedLogonSamples: Object.fromEntries(excluded) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
