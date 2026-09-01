import { readFile } from "node:fs/promises";
import type { Express, Request, Response } from "express";
import { KevFeedShapeError } from "../analysis/kevStore.js";
import {
  ResponseTooLargeError,
  RESPONSE_SIZE_LIMITS,
  readBoundedJson,
} from "../providers/boundedResponse.js";
import { fetchOutbound, OutboundUrlBlockedError } from "./outboundFetchGuard.js";
import type { RouteContext } from "./context.js";

// CISA KEV catalog routes (issue #99). The catalog is global (like NSRL/whitelist).
//   GET    /kev              — stats for the Settings → KEV panel.
//   POST   /kev/import-url   — fetch the CISA feed from a URL (body: { url }).
//   POST   /kev/import-file  — load the feed from a server-side file path (body: { path }).
//   DELETE /kev              — wipe the catalog.
//
// Lifted out of routes/threatIntel.ts when the SSRF guard below pushed that file past its frozen
// size cap (#384's ledger). Registered from the same position in registerThreatIntelRoutes, so the
// Express layer order — which tests/architecture/routeInventory.test.ts pins — is unchanged.

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** Whether the feed URL may point inside the operator's own network. Off unless explicitly set;
 *  a blank or "false" value has to read as off, or a toggle turned on from Settings → KEV could
 *  never be turned back off from there. */
function allowsInternalUrl(): boolean {
  return /^(1|true|yes|on)$/i.test((process.env.DFIR_KEV_ALLOW_INTERNAL_URL ?? "").trim());
}

export function registerKevRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  app.get("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(200).json({ count: 0, enabled: false });
    try {
      const m = await options.kevStore.meta();
      return res.status(200).json({ ...m, enabled: m.count > 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fetch the CISA KEV feed from a URL and ingest it. Body: { url? } (defaults to the CISA feed).
  // Passes the raw JSON through so meta() can read catalogVersion/dateReleased.
  //
  // The URL is the caller's, so the fetch is guarded (issue #760): https only, no loopback/private/
  // link-local target, re-checked at every redirect hop, body read under a byte cap, and NO fetched
  // content in the reply. That last one is not belt-and-braces — the old handler returned
  // (err as Error).message, and V8's JSON.parse error quotes the first bytes of what it failed to
  // parse, so a non-JSON reply from an internal endpoint came straight back to the caller.
  app.post("/kev/import-url", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const url = typeof req.body?.url === "string" && req.body.url.trim() ? req.body.url.trim() : CISA_KEV_URL;
    // Closes the pinned connection once the body is read. fetchOutbound cleans up after itself when
    // it throws, so this only ever has work to do on the success path.
    let dispose: (() => Promise<void>) | null = null;
    try {
      const {
        response,
        url: fetched,
        dispose: close,
      } = await fetchOutbound(url, {
        allowInternal: allowsInternalUrl(),
        timeoutMs: 30_000,
      });
      dispose = close;
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        return res.status(502).json({ error: `fetch failed: HTTP ${response.status}` });
      }
      const json = await readBoundedJson(response, {
        maxBytes: RESPONSE_SIZE_LIMITS.json,
        context: "kev import-url",
      });
      const { total } = await options.kevStore.ingestRaw(json);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] imported ${total} entries from ${fetched.href}`);
      return res.status(200).json({ total, source: fetched.href });
    } catch (err) {
      if (err instanceof OutboundUrlBlockedError) {
        return res.status(400).json({
          error:
            `refused to fetch that URL — ${err.message}. Load an internal or offline copy with ` +
            `POST /kev/import-file, or set DFIR_KEV_ALLOW_INTERNAL_URL=true to allow internal hosts.`,
        });
      }
      // These two carry a message that is safe to hand back: ResponseTooLargeError states only the
      // limit and the label, KevFeedShapeError only what shape was expected.
      if (err instanceof ResponseTooLargeError || err instanceof KevFeedShapeError) {
        logLine(`[kev] import-url failed for ${url} — ${err.message}`);
        return res.status(502).json({ error: err.message });
      }
      // Everything else stays server-side. A fetch or parse failure describes the RESPONSE, and the
      // response is the one thing the caller must not get to read.
      logLine(`[kev] import-url failed for ${url} — ${(err as Error).message}`);
      return res.status(502).json({ error: "could not fetch or parse a KEV feed from that URL" });
    } finally {
      if (dispose) await dispose();
    }
  });

  // Load the CISA KEV feed JSON from a file on the server filesystem. Body: { path }.
  // Localhost-only tool: reading an operator-specified path is intentional (like NSRL import-file).
  app.post("/kev/import-file", async (req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    const path = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!path) return res.status(400).json({ error: "path is required (a local copy of the CISA KEV JSON)" });
    try {
      const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
      const { total } = await options.kevStore.ingestRaw(raw);
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] loaded ${total} entries from file ${path}`);
      return res.status(200).json({ total, source: path });
    } catch (err) {
      // The operator named this file, so its own error text is theirs to see. A file that is not a
      // KEV feed is a 400 they can act on, not a 500 (issue #760 — the same shape check that stops
      // import-url overwriting the catalog with a fetched body).
      if (err instanceof KevFeedShapeError) return res.status(400).json({ error: err.message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Wipe the KEV catalog.
  app.delete("/kev", async (_req: Request, res: Response) => {
    if (!options.kevStore) return res.status(501).json({ error: "KEV store not configured" });
    try {
      await options.kevStore.clear();
      if (options.pipeline) options.pipeline.invalidateKevCache();
      logLine(`[kev] catalog cleared`);
      return res.status(200).json({ cleared: true, count: 0 });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
