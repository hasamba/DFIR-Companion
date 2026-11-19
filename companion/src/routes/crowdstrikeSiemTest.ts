// Settings → CrowdStrike Next-Gen SIEM → Test (#2685).
//
//   POST /crowdstrike/siem/test -> 200 { configured, ok, host, repository, steps[], warnings[], error? }
//
// Same tri-state answer as the other Settings "Test / reconnect" routes, always 200: a Falcon that
// rejects the client is a successful test reporting a failure. The dashboard saves the fields first,
// and DFIR_CROWDSTRIKE_ is a reloadable prefix, so process.env already holds what was typed. It
// starts one tiny query job, polls it once and cancels it — no case id, no store, nothing imported.
//
// Capped (#2695): each configured test spends a token request and three SIEM calls from the tenant's
// Falcon API budget, and this route is outside the per-case request limiter. One allowance per
// server, counted when a configured test starts — a failed or crashed probe still counts, since
// Falcon may already have been called; a not-configured answer costs nothing and is never counted.
// The window is fixed, not rolling: at most 5 per window, so at most 10 across one window boundary.

import type { Express, Request, Response } from "express";
import { ngsiemCredentialsFromEnv, readSiemLimits } from "../integrations/crowdstrike/ngsiemConfig.js";
import { probeNgsiem } from "../integrations/crowdstrike/ngsiemProbe.js";
import { SlidingWindowLimiter, sendRateLimited } from "../http/rateLimiter.js";
import type { RouteContext } from "./context.js";
import { SIEM_NOT_CONFIGURED } from "./crowdstrikeSiemSearch.js";

export const SIEM_TEST_MAX_PER_WINDOW = 5;
export const SIEM_TEST_WINDOW_MS = 60_000;
const SIEM_TEST_KEY = "crowdstrike-siem-test";

export function registerCrowdstrikeSiemTestRoutes(app: Express, ctx: RouteContext): void {
  const limiter = new SlidingWindowLimiter(SIEM_TEST_MAX_PER_WINDOW, SIEM_TEST_WINDOW_MS);
  app.post("/crowdstrike/siem/test", async (_req: Request, res: Response) => {
    const creds = ngsiemCredentialsFromEnv(process.env);
    if (!creds) return res.status(200).json({ configured: false, ok: false, error: SIEM_NOT_CONFIGURED });
    const now = Date.now();
    if (!limiter.tryAcquire(SIEM_TEST_KEY, now)) {
      const waitMs = limiter.retryAfterMs(SIEM_TEST_KEY, now);
      const seconds = Math.max(1, Math.ceil(waitMs / 1000));
      return sendRateLimited(res, waitMs, `Too many SIEM tests in a row — wait ${seconds}s and test again.`);
    }
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
