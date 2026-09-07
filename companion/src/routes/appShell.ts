import type { Express } from "express";
import { readPublicAsset } from "../serverAssets.js";
import { withNonce } from "../http/securityHeaders.js";
import { sendMaybeGzipped } from "../http/compressibleResponse.js";

/**
 * The static app shell: GET /, /dashboard, /mobile, /manifest.webmanifest, /sw.js.
 *
 * These five lived in server.ts, then moved into routes/caseLifecycle.ts so server.ts held zero
 * literal route registrations. They move again here for the same reason caseLifecycle took them:
 * that file hit its size cap, and the ledger's rule is a new module rather than a raised ceiling.
 * They are a coherent group — the browser-facing shell — and were never really case lifecycle.
 *
 * Registered immediately after registerCaseLifecycleRoutes so the stack order is unchanged.
 *
 * NOTE: /dashboard and /mobile have no try/catch and sit BEFORE the terminal error handler, so an
 * (unreachable in a real install) asset-read failure yields the standard JSON 500 instead of
 * Express's default HTML page — the only observable delta from their original home in startServer.
 */
export function registerAppShellRoutes(app: Express): void {
  // Redirect root to the dashboard.
  app.get("/", (_req, res) => {
    res.redirect("/dashboard");
  });

  // Serve the dashboard. withNonce stamps this response's CSP nonce into the inline <script>
  // blocks — without it they carry a placeholder the browser won't match, and none of them run.
  app.get("/dashboard", async (req, res) => {
    const html = await readPublicAsset("dashboard.html", "utf8");
    // The single largest item on the page, previously sent uncompressed. Measured on this branch:
    // 520,588 -> 120,043 bytes, 77% smaller (#882).
    await sendMaybeGzipped(req, res, "html", withNonce(html, String(res.locals.cspNonce ?? "")));
  });

  // Mobile companion (#59): a read-only, phone-optimized view (timeline / findings / IOCs / status)
  // for quick glances during IR away from the workstation. It's a PWA — installable via the
  // web manifest + a minimal service worker (offline app-shell). All three are static files in
  // public/; the SW is served at root so its default control scope covers /mobile.
  app.get("/mobile", async (_req, res) => {
    const html = await readPublicAsset("mobile.html", "utf8");
    res.type("html").send(withNonce(html, String(res.locals.cspNonce ?? "")));
  });

  app.get("/manifest.webmanifest", async (_req, res) => {
    try {
      const json = await readPublicAsset("manifest.webmanifest", "utf8");
      res.type("application/manifest+json").set("Cache-Control", "no-cache").send(json);
    } catch {
      res.status(404).end();
    }
  });

  app.get("/sw.js", async (_req, res) => {
    try {
      const js = await readPublicAsset("sw.js", "utf8");
      // no-cache + a same-origin allowed scope so the SW can control /mobile even if it's
      // ever moved into a subdirectory; browsers re-check sw.js on every navigation anyway.
      res
        .type("application/javascript")
        .set("Cache-Control", "no-cache")
        .set("Service-Worker-Allowed", "/")
        .send(js);
    } catch {
      res.status(404).end();
    }
  });
}
