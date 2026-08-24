import type { Express, Request, Response } from "express";
import { reloadEnvPrefix } from "../settings/envManager.js";
import type { RouteContext } from "./context.js";

/**
 * "Test / reconnect" for the SELF-HOSTED threat-intel providers in Settings → Enrichment.
 *
 * Its own module rather than three more screens of routes/threatIntel.ts, which the file-size
 * ledger caps at 952 lines: the gate exists to stop a file that is already too big from absorbing
 * every new thing that touches its domain, and this is a self-contained seam — one route, one
 * allowlist, no shared state with the IOC/whitelist/NSRL routes it would have sat among.
 *
 * WHY ONLY TWO PROVIDERS. A provider earns a test button when it has a probe() — a real auth
 * round-trip that sends NO indicator, which matters for sources whose whole OPSEC promise is that
 * indicators stay on the analyst's own box — and when its config has something to get wrong that a
 * key alone cannot reveal (a URL). The external SaaS have neither: no health endpoint, and nothing
 * to configure but a key. MISP is the third self-hosted source and has its own control, on the same
 * tab, because its keys also feed a PUSH client (see routes/casePush.ts).
 */
export function registerEnrichmentTestRoutes(app: Express, ctx: RouteContext): void {
  // A Map, not an object literal: `req.params.id` is analyst-supplied, and a plain object would
  // resolve "constructor" to something truthy off the prototype chain.
  const TESTABLE_PROVIDERS = new Map<string, { prefix: string; name: string; missing: string }>([
    [
      "yeti",
      {
        prefix: "DFIR_YETI_",
        name: "YETI",
        missing: "YETI not configured (set DFIR_YETI_URL and DFIR_YETI_KEY)",
      },
    ],
    [
      "opencti",
      {
        prefix: "DFIR_OPENCTI_",
        name: "OpenCTI",
        missing: "OpenCTI not configured (set DFIR_OPENCTI_URL and DFIR_OPENCTI_KEY)",
      },
    ],
  ]);

  // Re-read that provider's DFIR_* group from .env, rebuild the provider set, and probe. Answers
  // the same {configured, ok, error} tri-state as the integration reconnects, always 200 — a
  // provider that rejects our key is a successful test reporting a failure, not a failed request.
  //
  // The probe runs THROUGH the health cache (invalidated first) rather than beside it. That cache
  // is the gate that skips a provider it last saw down, for ~60s: probing independently would let
  // the button say "connected" while enrichment kept skipping the instance, and would replay a
  // stale "down" as though the analyst's fix had not worked. One probe, and the whole server
  // learns from it.
  app.post("/enrichment/:id/reconnect", async (req: Request, res: Response) => {
    const spec = TESTABLE_PROVIDERS.get(req.params.id);
    if (!spec)
      return res.status(404).json({
        error: `no connection test for "${req.params.id}" — testable providers: ${[...TESTABLE_PROVIDERS.keys()].join(", ")}`,
      });
    try {
      await reloadEnvPrefix(spec.prefix);
      ctx.rebuildForPrefix(spec.prefix); // swaps the live provider set
      const provider = ctx.enrichmentProviders().find((p) => p.name === spec.name);
      if (!provider) return res.status(200).json({ configured: false, ok: false, error: spec.missing });
      if (!provider.probe)
        return res.status(200).json({
          configured: true,
          ok: false,
          provider: spec.name,
          error: `${spec.name} has no reachability check`,
        });
      const health = ctx.enrichHealth();
      health.invalidate(spec.name); // never answer a click from the cached verdict
      const result = await health.check(provider);
      return res.status(200).json({
        configured: true,
        ok: result.ok,
        provider: spec.name,
        error: result.ok ? undefined : (result.detail ?? "probe failed"),
      });
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });
}
