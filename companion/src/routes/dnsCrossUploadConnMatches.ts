import type { Express, Request, Response } from "express";
import { z } from "zod";
import { DNS_FIXED_WINDOW_S } from "../analysis/canonicalDns.js";
import { resolveCrossUploadDnsConnLeads } from "../analysis/dnsCrossUploadConnJoin.js";
import type { RouteContext } from "./context.js";

/**
 * DNS answer -> connection, cross-upload (#996, query-to-connection half of #933 item 2) — a
 * sensor-vantage DNS row's own `client`/returned address matched against ANY connection-shaped
 * event anywhere in the case, by shared IP pair. Read-time only, recomputed every call, never
 * persisted. Modeled on the same report-time pattern as routes/proxyHostIdentity.ts and
 * routes/resolverEndpointIdentity.ts, but needs no host-identity index — both sides are already
 * plain IPs.
 *   - GET /cases/:id/dns-connection-cross-upload-matches[?windowSeconds=]
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * NEVER an unconditional "this is the connection" claim — see dnsCrossUploadConnJoin.ts's own
 * header for the aggregation-width and shared-address caveats this route's own output cannot
 * resolve.
 */

// A ceiling, not a recommendation — past this, "somewhere in the case" stops being a meaningful
// window at all. 24 hours: the same reasoning dnsResolverEndpointJoin.ts's query-timing tolerance
// uses, not the host-binding staleness one — this module has no host-binding stage.
const MAX_WINDOW_SECONDS = 86_400;

const querySchema = z.object({
  windowSeconds: z.coerce.number().int().positive().max(MAX_WINDOW_SECONDS).optional(),
});

export function registerDnsCrossUploadConnRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/dns-connection-cross-upload-matches", async (req: Request, res: Response) => {
    if (!options.stateStore) {
      return res.status(501).json({ error: "state store not configured" });
    }
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.message });
    try {
      const state = await options.stateStore.load(req.params.id);
      const windowSeconds = parsed.data.windowSeconds ?? DNS_FIXED_WINDOW_S;
      const matches = resolveCrossUploadDnsConnLeads(state.forensicTimeline, windowSeconds);
      return res.status(200).json({ matches });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
