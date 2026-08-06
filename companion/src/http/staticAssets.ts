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
  // Settings → Tools, the MCP server registry, and the update check (#127).
  "/js/dashboard-settings-tools.js": "application/javascript; charset=utf-8",
  // Sigma draft export (#89) and the ES|QL / YARA / Suricata hunt modal built from the same context.
  "/js/dashboard-sigma-hunt.js": "application/javascript; charset=utf-8",
  // Push ingest token (#84) — the per-case token an external collector posts evidence with.
  "/js/dashboard-push-token.js": "application/javascript; charset=utf-8",
  // Reproducible analysis runs (#377) — the run history for a case and the diff between two runs.
  "/js/dashboard-analysis-runs.js": "application/javascript; charset=utf-8",
  // Report Templates (#60) — the global branded report layouts and their section lists.
  "/js/dashboard-report-templates.js": "application/javascript; charset=utf-8",
  // Adversary Hints (#46) — whose tradecraft the case resembles, and the hunt for a technique.
  "/js/dashboard-adversary-hints.js": "application/javascript; charset=utf-8",
  // Gap Hypotheses (#96) — what the evidence does not show, and what would settle it.
  "/js/dashboard-gap-hypotheses.js": "application/javascript; charset=utf-8",
  // Narrative Timeline — the AI-written case narrative, its editor and the synthesis metadata.
  "/js/dashboard-narrative.js": "application/javascript; charset=utf-8",
  // Host & Account Ranking (#202) — which hosts and accounts the evidence touches most.
  "/js/dashboard-host-ranking.js": "application/javascript; charset=utf-8",
  // NSRL known-good hashes (#63) — the vendor-shipped allow-list and applying it to a case.
  "/js/dashboard-nsrl.js": "application/javascript; charset=utf-8",
  // Dashboard Views editor (#142) — the panel-layout presets and which sections each shows.
  "/js/dashboard-views-editor.js": "application/javascript; charset=utf-8",
  // Import undo / redo (#76) — roll the whole case back to before the latest import, and forward.
  "/js/dashboard-import-undo.js": "application/javascript; charset=utf-8",
  // Case lifecycle (#119) — open / on hold / closed / archived, and the buttons that move it.
  "/js/dashboard-case-lifecycle.js": "application/javascript; charset=utf-8",
  // Threat-intel enrichment — which providers are on for this case, and the toggle modal.
  "/js/dashboard-enrichment.js": "application/javascript; charset=utf-8",
  // Unified import — one button, the server decides what the file is. Listener wiring only.
  "/js/dashboard-unified-import.js": "application/javascript; charset=utf-8",
  // Asset overrides — rename / add / suppress / link. Listener wiring only.
  "/js/dashboard-asset-overrides.js": "application/javascript; charset=utf-8",
  // Encrypted case archive export — the password-protected archive of a whole case.
  "/js/dashboard-encrypted-export.js": "application/javascript; charset=utf-8",
  // Redacted case export (#54) — the same case with names, hosts and accounts masked.
  "/js/dashboard-redacted-export.js": "application/javascript; charset=utf-8",
  // Explain Event (#141) — the plain-language explanation of one timeline event.
  "/js/dashboard-explain-event.js": "application/javascript; charset=utf-8",
  // Timeline Gaps (#83) — the stretches of time the evidence says nothing about.
  "/js/dashboard-timeline-gaps.js": "application/javascript; charset=utf-8",
  // Unified export menu — one button offering every export the case supports.
  "/js/dashboard-unified-export.js": "application/javascript; charset=utf-8",
  // Manual add — event / IOC / finding typed in by hand.
  "/js/dashboard-manual-add.js": "application/javascript; charset=utf-8",
  // Correlation profile — how tightly the correlator joins events into one activity.
  "/js/dashboard-correlation-profile.js": "application/javascript; charset=utf-8",
  // Settings modal — the Essential / All view toggle and opening on a named tab.
  "/js/dashboard-settings-modal.js": "application/javascript; charset=utf-8",
  // Responsive toolbar — collapse the button row into an overflow menu when it will not fit.
  "/js/dashboard-toolbar-responsive.js": "application/javascript; charset=utf-8",
  // Save as Template — turn the current case's report layout into a reusable template.
  "/js/dashboard-save-template.js": "application/javascript; charset=utf-8",
  // ZIP case archive (unencrypted) — the plain archive of a whole case.
  "/js/dashboard-zip-archive.js": "application/javascript; charset=utf-8",
  // Timeline row display toggles — which columns and badges each timeline row shows.
  "/js/dashboard-timeline-display.js": "application/javascript; charset=utf-8",
  // Setup wizard AI step (#181) — choosing and testing the AI provider during first-run setup.
  "/js/dashboard-wizard-ai-step.js": "application/javascript; charset=utf-8",
  // Disk-space warning (#1) — the banner when the case volume is running out of room.
  "/js/dashboard-disk-warning.js": "application/javascript; charset=utf-8",
  // IOC block-list export — the case's indicators as a firewall or proxy block list.
  "/js/dashboard-ioc-blocklist.js": "application/javascript; charset=utf-8",
  // Per-case report-template picker — which global template this case renders with.
  "/js/dashboard-case-template-picker.js": "application/javascript; charset=utf-8",
  // IOC Whitelist (Phase 2 of #66) — patterns marked never-interesting.
  "/js/dashboard-ioc-whitelist.js": "application/javascript; charset=utf-8",
  // Search bar, time-range filter and scope controls — the largest wiring-only block in the page.
  "/js/dashboard-search-scope.js": "application/javascript; charset=utf-8",
  // Import case — a snapshot archive (#56), an encrypted archive, or a case from DFIR-IRIS.
  "/js/dashboard-import-case.js": "application/javascript; charset=utf-8",
  // Executive summary generator — the short non-technical write-up of a case.
  "/js/dashboard-exec-summary.js": "application/javascript; charset=utf-8",
  // Import minimum-severity preference — the floor below which imported findings are dropped.
  "/js/dashboard-import-severity.js": "application/javascript; charset=utf-8",
  // Generic merge-target picker — which case to merge the current one into.
  "/js/dashboard-merge-picker.js": "application/javascript; charset=utf-8",
  // Startup pre-flight banner — the warning strip when the server's own checks fail.
  "/js/dashboard-preflight-banner.js": "application/javascript; charset=utf-8",
  // data-act dispatch — the delegated handler that lets the server send script-src 'self'.
  "/js/dashboard-data-act.js": "application/javascript; charset=utf-8",
  // Custom tooltip — the hover card shown instead of the browser's own title text.
  "/js/dashboard-tooltip.js": "application/javascript; charset=utf-8",
  // Presentation mode (#17) — the stripped-down view for a projector.
  "/js/dashboard-presentation-mode.js": "application/javascript; charset=utf-8",
  // Finding assignment + workflow status (#87) — per-finding owner and triage state.
  "/js/dashboard-finding-workflow.js": "application/javascript; charset=utf-8",
  // Pinned findings (#220) — the reorderable strip of pinned findings.
  "/js/dashboard-pinned-findings.js": "application/javascript; charset=utf-8",
  // Command palette registry (#238) — the actions the palette offers.
  "/js/dashboard-palette-registry.js": "application/javascript; charset=utf-8",
  // Section order and visibility (#238) — which panels are shown and in what order.
  "/js/dashboard-section-order.js": "application/javascript; charset=utf-8",
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
