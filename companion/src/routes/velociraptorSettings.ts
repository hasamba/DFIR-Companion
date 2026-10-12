import type { Express, Request, Response } from "express";
import { readdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { downloadLatestVelociraptor } from "../analysis/velociraptorDownload.js";
import type { RouteContext } from "./context.js";
import { fetchOutbound, OutboundUrlBlockedError } from "./outboundFetchGuard.js";

/**
 * Two settings-page routes for the Velociraptor binary/API-config path fields:
 *   - GET /settings/browse-fs — lists a directory for the dashboard's in-page file picker.
 *   - POST /settings/velociraptor/download-latest — fetches the current release for this server's
 *     OS/arch from the project's own GitHub releases.
 *
 * Split out of routes/caseLifecycle.ts, which sits at its size-ledger cap — these two are the only
 * settings routes that touch the filesystem/network rather than just .env, which is also why
 * GET /settings/browse-fs needs its own demo-mode carve-out (see httpStack.ts): unlike every other
 * GET, it walks the server's own filesystem on request, which the blanket "GETs are safe" demo-mode
 * allowance does not account for.
 */
export function registerVelociraptorSettingsRoutes(app: Express, ctx: RouteContext): void {
  const { store, serverLogger } = ctx;
  const errLine = (msg: string): void => serverLogger.error(msg);

  // Settings "Browse…" file pickers (API config path / binary path etc): this is a plain web app
  // with no native OS file dialog, so the dashboard drives a simple in-page directory browser
  // against this listing endpoint instead. `dir` may be a file (the field's current value) — in
  // that case we list its PARENT so the browser opens already showing that file's folder.
  app.get("/settings/browse-fs", async (req: Request, res: Response) => {
    try {
      const raw = typeof req.query.dir === "string" ? req.query.dir.trim() : "";
      let dir = raw ? resolve(raw) : homedir();
      try {
        const st = await stat(dir);
        if (!st.isDirectory()) dir = dirname(dir);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        dir = homedir();
      }
      const dirents = await readdir(dir, { withFileTypes: true });
      const entries = dirents
        .map((d) => ({ name: d.name, path: join(dir, d.name), isDir: d.isDirectory() }))
        .sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
      const parent = dirname(dir);
      return res.json({ dir, parent: parent === dir ? null : parent, entries });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Settings "Download latest release" button next to the Velociraptor binary path field: fetches
  // the current release for THIS SERVER's OS/arch from the project's own GitHub releases and saves
  // it under <cases-root-sibling>/tools, mirroring customToolStore/mcpServerStore's own "tools" dir
  // (runtimeStores.ts). Analyst-triggered only — see velociraptorDownload.ts's header comment.
  app.post("/settings/velociraptor/download-latest", async (_req: Request, res: Response) => {
    try {
      const destDir = join(dirname(store.casesRoot), "tools");
      const result = await downloadLatestVelociraptor({
        destDir,
        fetchFn: fetch,
        // The asset bytes become an executable, so they go through the SSRF guard (every redirect
        // hop https + public + connection-pinned); the downloader adds the GitHub host pin and the
        // published-digest check on top (#2133).
        fetchAsset: (url, timeoutMs) => fetchOutbound(url, { timeoutMs }),
        platform: process.platform,
        arch: process.arch,
      });
      return res.json({ ok: true, path: result.path, version: result.version, assetName: result.assetName });
    } catch (err) {
      const message = (err as Error).message;
      errLine(`POST /settings/velociraptor/download-latest failed: ${message}`);
      // A refused or tampered download is an upstream problem, not a server fault.
      const upstream =
        err instanceof OutboundUrlBlockedError || /unexpected host|checksum mismatch/.test(message);
      return res.status(upstream ? 502 : 500).json({ error: message });
    }
  });
}
