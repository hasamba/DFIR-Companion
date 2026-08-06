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
  // The facet filters (source / origin / host / IOC type). Splitting these from the timeline view's
  // other filters is deliberate: four renderers used to MUTATE them mid-render, and that had to
  // stop before any "one commit per user action" API could be built.
  "/js/dashboard-facets.js": "application/javascript; charset=utf-8",
  // The timeline view's composite actions — the last tier-2 owner (#415). Unlike the others this
  // one takes injected painters, so a 404 leaves every filter gesture committing to nothing.
  "/js/dashboard-timeline-view.js": "application/javascript; charset=utf-8",
  // TIER 3 (#415): whole features, each owning its state behind a closure.
  //
  // AS CRITICAL AS EVERYTHING ABOVE, and an earlier version of this comment claimed otherwise —
  // that a 404 would cost one panel rather than the page. It does not: the inline script calls
  // initCustodyButtons() and verifyCustodyOnOpen() unguarded, and registers loadCaseBackups as a
  // listener by name, so a missing file is a ReferenceError that takes out the rest of that
  // initialisation or case-connect flow with it. Treat these exactly like the helpers.
  "/js/dashboard-anomalies.js": "application/javascript; charset=utf-8",
  "/js/dashboard-sessions.js": "application/javascript; charset=utf-8",
  "/js/dashboard-compliance.js": "application/javascript; charset=utf-8",
  "/js/dashboard-d3fend.js": "application/javascript; charset=utf-8",
  "/js/dashboard-geo.js": "application/javascript; charset=utf-8",
  "/js/dashboard-custody.js": "application/javascript; charset=utf-8",
  "/js/dashboard-backup.js": "application/javascript; charset=utf-8",
  "/js/dashboard-collection-plan.js": "application/javascript; charset=utf-8",
  "/js/dashboard-tickets.js": "application/javascript; charset=utf-8",
  // The first whole FEATURE module of #415 tier 3, as opposed to the pure-helper modules above.
  "/js/dashboard-tagger.js": "application/javascript; charset=utf-8",
  "/js/dashboard-kev.js": "application/javascript; charset=utf-8",
  // The Timeline Swimlane canvas chart (#415 tier 3). A 404 here costs the chart and nothing else,
  // but the guarded ENTRY POINT is only half the reason: this module also publishes four names that
  // the page calls bare from the middle of its load-time refresh chains, where a ReferenceError
  // used to take every later refresh in the same statement with it. js/dashboard-facade.js below is
  // what makes the rest of that sentence true.
  "/js/dashboard-swimlane.js": "application/javascript; charset=utf-8",
  // MCP Analysis (#296) — the agent-driven tool runner. Guarded entry point, and every name it
  // calls out to (esc, fileToBase64, mcpJobDuration) is published by a tier-1 helper above, so a
  // 404 here costs this panel and nothing else.
  "/js/dashboard-mcp.js": "application/javascript; charset=utf-8",
  // Hunting Profile (#157) — read-only per-case hunt feedback. No initializer and no state.
  "/js/dashboard-hunt-profile.js": "application/javascript; charset=utf-8",
  // Beacon candidates, evidence gaps, playbook match and ATT&CK mitigations — four read-only
  // panels with identical lifecycles, kept in one file because each is 12-89 lines.
  "/js/dashboard-derived-panels.js": "application/javascript; charset=utf-8",
  // Deep pass (#282) — the lower-confidence re-analysis sweep, run as a background job.
  "/js/dashboard-deep-pass.js": "application/javascript; charset=utf-8",
  // Super timeline (#188) — the paginated, faceted view over every event in the case.
  "/js/dashboard-super-timeline.js": "application/javascript; charset=utf-8",
  // Playbook (#230) — the case task list, its dependency graph and its hunt suggestions.
  "/js/dashboard-playbook.js": "application/javascript; charset=utf-8",
  // Health / Diagnostics (#118) — operator system state under Settings → Diagnostics.
  "/js/dashboard-diagnostics.js": "application/javascript; charset=utf-8",
  // Report versions (#77) — the version list, its review workflow and the side-by-side diff.
  "/js/dashboard-report-versions.js": "application/javascript; charset=utf-8",
  // The no-op facade for every feature name dashboard.html calls bare at load. Registered here like
  // any other module, but note the asymmetry: a 404 on THIS file is not survivable the way a 404 on
  // a feature is, because it is the thing that makes those survivable. Tier-1, same as /js/safe-dom.js.
  "/js/dashboard-facade.js": "application/javascript; charset=utf-8",
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
  // The dashboard's own stylesheet, cut into eight parts (#415) from the single file that had held
  // everything the fourteen inline <style> blocks used to. Unlike a11y.css these fail loudly: the
  // page hides <body> until safe-dom.js is ready, so a 404 is a blank dashboard, not an unstyled
  // one — with one exception worth knowing, because it is the quiet failure this split introduced.
  //
  // THE ORDER OF THESE KEYS IS THE CASCADE ORDER, and it must match the <link> order in
  // public/dashboard.html: the parts are a pure byte split of one file, so a tie that used to be
  // resolved by one rule sitting later in the file is now resolved by it sitting in a later PART.
  //
  // THE EXCEPTION: an @keyframes resolves by NAME across the whole document, not by document order.
  // Drop one of these keys and the eight-way cascade is still perfectly ordered for everything that
  // did load — but any animation whose keyframe lived in the missing part just stops, with no
  // unstyled region to show for it. tests/reports/dashboardCss.test.ts holds that line; the case it
  // was written for is `spin`, defined in dashboard-timeline.css and used only from a
  // data-safe-style attribute in the markup, which no grep over the CSS will ever show you.
  "/css/dashboard-tokens.css": "text/css; charset=utf-8",
  "/css/dashboard-themes-a.css": "text/css; charset=utf-8",
  "/css/dashboard-themes-b.css": "text/css; charset=utf-8",
  "/css/dashboard-layout.css": "text/css; charset=utf-8",
  "/css/dashboard-panels.css": "text/css; charset=utf-8",
  "/css/dashboard-timeline.css": "text/css; charset=utf-8",
  "/css/dashboard-toolbar.css": "text/css; charset=utf-8",
  "/css/dashboard-sections.css": "text/css; charset=utf-8",
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
