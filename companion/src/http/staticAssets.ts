import type { Express } from "express";
import { readPublicAsset } from "../serverAssets.js";

/**
 * Whitelisted static client assets: vendored libraries (Leaflet for the Geographic map, #133;
 * cytoscape+dagre for the graphs) plus first-party browser modules (the shared graph-view module
 * used by the Login/Assets/Evidence graphs, the command palette #238, the Settings search filter,
 * and the case-load progress bar).
 *
 * WHITELISTED PATHS ONLY — public/js is deliberately not served as a static directory. A new module
 * under public/js/ is NOT served until it is named here, and the browser's only symptom is a silent
 * 404 with the feature simply absent: no console error the dashboard surfaces, nothing failing in
 * any other suite. tests/settings/settingsSearch.test.ts pins every /js/ module dashboard.html
 * loads to an entry in this map, so the next one cannot ship half-wired.
 *
 * Lives in its own module rather than inline in server.ts because server.ts is one of the files
 * frozen by the file-size ratchet (#385): the map grows every time a browser module is added, and
 * a list that grows by design does not belong in a file that may not grow.
 */
export const STATIC_ASSETS: Record<string, string> = {
  "/vendor/leaflet/leaflet.js": "application/javascript; charset=utf-8",
  "/vendor/leaflet/leaflet.css": "text/css; charset=utf-8",
  "/vendor/cytoscape/cytoscape.min.js": "application/javascript; charset=utf-8",
  "/vendor/cytoscape/dagre.min.js": "application/javascript; charset=utf-8",
  "/vendor/cytoscape/cytoscape-dagre.js": "application/javascript; charset=utf-8",
  "/js/safe-dom.js": "application/javascript; charset=utf-8",
  "/js/graph-view.js": "application/javascript; charset=utf-8",
  "/js/command-palette.js": "application/javascript; charset=utf-8",
  "/js/settings-search.js": "application/javascript; charset=utf-8",
  "/js/case-load-progress.js": "application/javascript; charset=utf-8",
  "/js/hunt-workbench.js": "application/javascript; charset=utf-8",
  "/js/diagnostics-panel.js": "application/javascript; charset=utf-8",
  // Pure helpers lifted out of dashboard.html's inline script (#415). CLASSIC scripts, not modules
  // — the dashboard calls them by bare name, so they have to declare real globals; see
  // public/js/dashboard-escape.js. That distinction matters here because the allowlist test used to
  // look only at `<script type="module">` tags, which would have skipped all eight of these.
  "/js/dashboard-state.js": "application/javascript; charset=utf-8",
  "/js/dashboard-escape.js": "application/javascript; charset=utf-8",
  "/js/dashboard-time.js": "application/javascript; charset=utf-8",
  "/js/dashboard-text.js": "application/javascript; charset=utf-8",
  "/js/dashboard-glyphs.js": "application/javascript; charset=utf-8",
  "/js/dashboard-filters.js": "application/javascript; charset=utf-8",
  "/js/dashboard-ioc.js": "application/javascript; charset=utf-8",
  "/js/dashboard-values.js": "application/javascript; charset=utf-8",
  "/js/dashboard-fragments.js": "application/javascript; charset=utf-8",
  // Tier 2's first owner: the investigation scope window, its projection, and its controls (#415).
  // Unlike the helpers above this one holds state, so a 404 here is not a missing helper — every
  // scope read would throw and the dashboard would not render at all.
  "/js/dashboard-scope.js": "application/javascript; charset=utf-8",
  // Tier 2's selection owners: what the analyst has ticked (DfirSelection) and starred
  // (DfirStarred). Same failure mode as the scope module — these hold state, so a 404 is not a
  // missing helper, it is every selection read throwing.
  "/js/dashboard-selection.js": "application/javascript; charset=utf-8",
  // The first whole FEATURE module of #415 tier 3, as opposed to the pure-helper modules above.
  "/js/dashboard-tagger.js": "application/javascript; charset=utf-8",
  "/js/dashboard-kev.js": "application/javascript; charset=utf-8",
  // Accessibility primitives (#386). modal-autowire is the only one dashboard.html loads directly;
  // the other two are its static imports, and the browser fetches those by URL too — so all three
  // need an entry here or the import chain 404s exactly as described above.
  "/js/a11y/modal-autowire.js": "application/javascript; charset=utf-8",
  "/js/a11y/modal.js": "application/javascript; charset=utf-8",
  "/js/a11y/focus-trap.js": "application/javascript; charset=utf-8",
  "/js/a11y/announcer.js": "application/javascript; charset=utf-8",
  "/js/a11y/landmarks.js": "application/javascript; charset=utf-8",
  "/js/a11y/describe-as-table.js": "application/javascript; charset=utf-8",
  "/js/a11y/tooltips.js": "application/javascript; charset=utf-8",
  // The accessibility stylesheet. A missing entry here is worse than a missing script: the page
  // still renders, so the only symptom is that focus rings, the skip link and reduced-motion
  // support are silently gone.
  "/css/a11y.css": "text/css; charset=utf-8",
  // The dashboard's own stylesheet — all 3,224 lines that used to live in fourteen inline <style>
  // blocks (#415). Unlike a11y.css this one fails loudly: the page hides <body> until safe-dom.js
  // is ready, so a 404 here is a blank dashboard rather than an unstyled one.
  "/css/dashboard.css": "text/css; charset=utf-8",
};

/**
 * Register one GET route per whitelisted asset.
 *
 * Called from inside createApp so the routes exist in tests too (startServer calls createApp).
 */
export function registerStaticAssets(app: Express): void {
  for (const [route, type] of Object.entries(STATIC_ASSETS)) {
    app.get(route, async (_req, res) => {
      try {
        const buf = await readPublicAsset(route.slice(1)); // strip leading "/"
        res.type(type).set("Cache-Control", "public, max-age=86400").send(buf);
      } catch {
        res.status(404).end();
      }
    });
  }
}
