// Settings → CrowdStrike Next-Gen SIEM → Test (#2685).
//
//   POST /crowdstrike/siem/test -> 200 { configured, ok, host, repository, steps[], warnings[], error? }
//
// Same tri-state answer as the other Settings "Test / reconnect" routes, always 200: a Falcon that
// rejects the client is a successful test reporting a failure. The dashboard saves the fields first,
// and DFIR_CROWDSTRIKE_ is a reloadable prefix, so process.env already holds what was typed. It
// starts one tiny query job, polls it once and cancels it — no case id, no store, nothing imported.

import type { Express, Request, Response } from "express";
import { ngsiemCredentialsFromEnv, readSiemLimits } from "../integrations/crowdstrike/ngsiemConfig.js";
import { probeNgsiem } from "../integrations/crowdstrike/ngsiemProbe.js";
import type { RouteContext } from "./context.js";
import { SIEM_NOT_CONFIGURED } from "./crowdstrikeSiemSearch.js";

export function registerCrowdstrikeSiemTestRoutes(app: Express, ctx: RouteContext): void {
  app.post("/crowdstrike/siem/test", async (_req: Request, res: Response) => {
    const creds = ngsiemCredentialsFromEnv(process.env);
    if (!creds) return res.status(200).json({ configured: false, ok: false, error: SIEM_NOT_CONFIGURED });
    try {
      const result = await probeNgsiem({
        ...creds,
        repository: readSiemLimits(process.env).repository,
        ...(ctx.options.crowdstrikeSiemFetch ? { fetchFn: ctx.options.crowdstrikeSiemFetch } : {}),
        log: (line) => ctx.serverLogger.warn(`[crowdstrike-siem] test: ${line}`),
      });
      if (!result.ok) ctx.serverLogger.warn(`[crowdstrike-siem] test failed: ${result.error ?? "unknown"}`);
      return res.status(200).json(result);
    } catch (err) {
      ctx.serverLogger.warn(`[crowdstrike-siem] test crashed: ${(err as Error).message}`);
      return res.status(500).json({
        configured: true,
        ok: false,
        error: "The test could not run; the server log has the reason.",
      });
    }
  });
}
