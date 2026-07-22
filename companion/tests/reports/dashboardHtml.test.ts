import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

describe("dashboard.html", () => {
  it("lets the analyst dismiss a lateral chain, and review/restore dismissed ones", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Per-row Dismiss, with Restore taking its place once a chain has been dismissed.
    expect(html).toContain("ev-path-dismiss");
    expect(html).toContain("ev-path-restore");
    // The button must say what dismissing does NOT do — the evidence is kept.
    expect(html).toMatch(/ev-path-dismiss[\s\S]{0,300}underlying evidence stays in the case/);
    // Dismissed chains are hidden by default; the toggle re-fetches with includeDismissed=1.
    expect(html).toContain("let evPathsShowDismissed = false");
    expect(html).toContain("evPathsShowDismissed");
    expect(html).toMatch(/function loadLateralPaths\(caseId\)[\s\S]{0,400}includeDismissed=1/);
    // Dismissing POSTs the route's hostIds (the durable anchor), not the positional path id.
    expect(html).toMatch(/lateral-path-dismissals`[\s\S]{0,300}hostIds: path\.hostIds/);
    // Restoring DELETEs by the normalized host-sequence key.
    expect(html).toMatch(/lateral-path-dismissals\/\$\{encodeURIComponent\(key\)\}`, \{ method: "DELETE" \}/);
    // A dismissed row is visibly struck through and carries the analyst's reason.
    expect(html).toContain("line-through");
    expect(html).toContain("dismissalNote");
  });

  it("names who/what carried each lateral chain, not just the hosts", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Read from the hop's STRUCTURED actor field — never parsed back out of the `basis` prose.
    expect(html).toMatch(/p\.hops \|\| \[\]\)\.map\(\(h\) => h\.actor\)/);
    expect(html).toContain("via <b>");
    // De-duplicated: one account carrying every hop is listed once, not once per hop.
    expect(html).toMatch(/new Set\(\(p\.hops \|\| \[\]\)\.map\(\(h\) => h\.actor\)/);
  });

  it("expands Host & Account Ranking rows to show contributing events + IOCs (#237)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("data-hr-key=");
    expect(html).toContain("hostRankingExpanded");
    expect(html).toContain("renderHostRankingDetail");
    expect(html).toContain("hr-detail");
    expect(html).toContain("let lastIocs");
  });

  it("offers a kill-chain colour overlay on the evidence graph with a phase legend (#93)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // The Node colour mode radios (severity default + kill-chain phase) drive evColorMode.
    expect(html).toContain('name="evColorMode"');
    expect(html).toContain('value="killchain"');
    expect(html).toContain("let evColorMode");
    // Nodes recolour by their server-derived tactic; the legend + no-tactic fallback are present.
    expect(html).toContain("evTacticColor");
    expect(html).toContain("EV_KC_ORDER");
    expect(html).toContain("renderEvKcLegend");
    expect(html).toContain('id="evKcLegend"');
    expect(html).toContain("EV_KC_NO_TACTIC");   // nodes with no tactic degrade cleanly
  });

  it("contains websocket wiring and the consolidated import/export controls", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("/ws?caseId=");
    expect(html).toContain('id="findings"');
    expect(html).toContain('id="timeline"');
    expect(html).toContain('id="openThreads"');
    // One Import button (server auto-detects the type) + one Export menu (incl. report generation).
    expect(html).toContain('id="importBtn"');
    expect(html).toContain('id="exportSelect"');
    expect(html).toContain("/import");          // unified import endpoint
    expect(html).toContain("/report");          // report generation via the Export menu
  });

  it("makes the case-ID field a combo box (datalist of existing cases + free text)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('list="caseList"');          // the input is bound to the datalist
    expect(html).toContain('<datalist id="caseList">'); // the dropdown of available cases
    expect(html).toContain("loadCaseList");             // populated from GET /cases
  });

  it("wires the Case Details form (people fields + save) to /report-meta", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="saveReportMeta"');
    expect(html).toContain('id="rm-investigators"');
    expect(html).toContain('id="rm-reviewer"');
    expect(html).toContain('id="rm-incidentManager"');
    expect(html).toContain("/report-meta");
    expect(html).not.toContain('id="rm-investigator"'); // replaced by the plural field
  });

  it("wires the optional company name + logo upload (with preview) for report branding", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="rm-companyName"');
    expect(html).toContain('id="rm-companyLogoFile"');
    expect(html).toContain('id="rm-logoPreview"');
    expect(html).toContain('id="rm-removeLogo"');
    expect(html).toContain("companyLogo:");   // sent in the report-meta PUT body
    expect(html).toContain("readAsDataURL");   // logo is base64-encoded client-side
  });

  it("offers Markdown and HTML export links after generating the report", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="reportLinks"');
    expect(html).toContain("/report/report.html");
    expect(html).toContain("/report/report.md?download=1");
  });

  it("offers a PDF export (print-to-PDF) via the Export menu", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('value="report-pdf"');
    expect(html).toContain("/report/report.html?print=1"); // opens the print-styled view
    expect(html).toContain("Save as PDF");                  // the link/label the user sees
  });

  it("offers an incident-timeline CSV export via the Export menu", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="exportSelect"');
    expect(html).toContain('value="timeline-csv"');
    expect(html).toContain("/incident-timeline.csv");
  });

  it("offers Timesketch export (Forensic Timeline / Super Timeline) via the Export and Push menus", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Export… dropdown: JSONL download links, one per timeline.
    expect(html).toContain('value="timesketch-jsonl"');
    expect(html).toContain('value="timesketch-jsonl-super"');
    expect(html).toContain("/super-timeline.jsonl");
    // Push to… dropdown: both options appear once /timesketch/status reports configured.
    expect(html).toContain('addPushOption("timesketch",');
    expect(html).toContain('addPushOption("timesketch-super",');
    expect(html).toContain("Timesketch export (Forensic Timeline)");
    expect(html).toContain("Timesketch export (Super Timeline)");
  });

  it("wires the compromised-assets section + asset↔IoC graph with type toggles", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="assetGraph"');
    expect(html).toContain('id="assetList"');
    expect(html).toContain('class="asset-type-toggle"');
    expect(html).toContain('value="account"');
    expect(html).toContain("/asset-graph");
  });

  it("offers fullscreen and layout controls for the asset graph (shared cytoscape toolbar)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const mod = await readFile(new URL("../../../public/js/graph-view.js", import.meta.url), "utf8");
    // The asset graph now uses the shared graph-view module: the fullscreen button lives in the
    // toolbar; requestFullscreen is handled once in the module. Layout is chosen via the generic
    // layout radios (spread/dagre/circle/concentric/breadthfirst) — the old bespoke
    // horizontal/vertical/radial SVG layouts were replaced by the shared set.
    expect(html).toContain('id="assetFullscreenBtn"');
    expect(html).toContain('name="assetLayoutRadio"');
    expect(html).toContain('value="dagre"');
    expect(html).toContain('value="circle"');
    expect(mod).toContain("requestFullscreen");
    // Fullscreen must actually grow the cytoscape canvas: the asset/evidence wraps are
    // .asset-graph-wrap and their canvas div is .login-graph, so the sizing rule must target that
    // (a regression guard — the old rule targeted the now-removed .asset-graph class).
    expect(html).toContain(".asset-graph-wrap:fullscreen .login-graph");
    // The absolutely-positioned View/side panels must anchor to their own graph wrap — otherwise
    // they escape to the page and stay floating over other sections when you scroll away.
    expect(html).toMatch(/\.asset-graph-wrap\s*\{[^}]*position:\s*relative/);
  });

  it("toggles the graph View panel closed on a second click (no re-open regression)", async () => {
    const mod = await readFile(new URL("../../../public/js/graph-view.js", import.meta.url), "utf8");
    // The options-panel toggle must read purely off display==="none"; an `|| !p.style.display`
    // fallback misread the open ("") state as hidden and re-opened instead of closing.
    expect(mod).toContain('const show = p.style.display === "none";');
  });

  it("wires the Ask-the-AI panel (ask + add-to-open-questions)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="askInput"');
    expect(html).toContain('id="askBtn"');
    expect(html).toContain('id="askAnswer"');
    expect(html).toContain("/ask");
    expect(html).toContain("/questions");
  });

  it("renders numbered, clickable citation footnotes for a finding's supporting events (#222)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("function citeEvents(");
    // Citations reuse the EXISTING jump-to-event mechanism (ev-jump + data-evid), not a new one.
    expect(html).toMatch(/function citeEvents[\s\S]{0,400}class="ev-jump/);
    expect(html).toContain("Cited events");
    // Findings prefer their own relatedEventIds, falling back to the events that back-link to them
    // (older findings persisted before this field existed).
    expect(html).toMatch(/f\.relatedEventIds[\s\S]{0,200}suppEventsByFinding\[f\.id\]/);
  });

  it("offers per-source enrichment selection (local/external) via a modal", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="enrichOverlay"');
    expect(html).toContain("openEnrichModal");
    expect(html).toContain('class="enrich-cb"');
    expect(html).toContain("OPSEC-safe");
    expect(html).toContain("anyConfigured");
  });

  it("wires investigator comments (chip + modal + author name) to /comments", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("commentChip");
    expect(html).toContain('id="commentOverlay"');
    expect(html).toContain('id="settingsInvestigator"'); // moved to Settings modal
    expect(html).toContain("/comments");
    expect(html).toContain("comments_changed"); // live-sync over the WS
  });

  it("makes sections drag-reorderable (grip + persisted order) with Ask first by default", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("setupReorder");
    expect(html).toContain("drag-grip");
    expect(html).toContain('"dfir.sectionsOrder"');   // unified section-order store (#6 — drag + Settings agree)
    // Ask section comes before Executive Summary in the default markup.
    expect(html.indexOf("Ask the LLM about this case")).toBeLessThan(html.indexOf("Executive Summary"));
    // A section missing from a saved order is inserted at its CANONICAL slot (right after its nearest
    // already-placed sibling) rather than dumped at the end — so the default-first Ask panel still
    // shows first even against an older saved order that predates a section.
    expect(html).toContain("getEffectiveOrder");
    expect(html).not.toContain("new/unknown sections go to the end");
  });

  it("marks the layout Custom on a manual drag reorder, so a page refresh doesn't re-apply the active dashboard-view preset over it", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // applySavedViewForCase() runs on every case connect (including the auto-reconnect on page
    // refresh) and, for any case without an explicit view choice, re-applies a preset's canned
    // section order — clobbering a manual drag unless the drag itself records a Custom choice.
    // Both drag-reorder call sites (the in-page grip, and the Settings section-list drag) must
    // call applyDashboardView(null, ...) right after saveSectionsOrder(...) to persist that choice.
    const markCustom = 'if (typeof applyDashboardView === "function") applyDashboardView(null, { persist: true, rerender: false });';
    expect(html.split(markCustom).length - 1).toBe(2); // exactly the two drag-reorder sites
    const gripDrop = html.indexOf('saveSectionsOrder([...main.querySelectorAll(":scope > section[id]")]');
    const gripMark = html.indexOf(markCustom, gripDrop);
    expect(gripMark).toBeGreaterThan(gripDrop);
    expect(gripMark - gripDrop).toBeLessThan(600); // the very next thing the handler does
    const settingsDrop = html.indexOf('saveSectionsOrder([...container.querySelectorAll(".sec-check")]');
    const settingsMark = html.indexOf(markCustom, settingsDrop);
    expect(settingsMark).toBeGreaterThan(settingsDrop);
    expect(settingsMark - settingsDrop).toBeLessThan(400);
  });

  it("offers a unified multi-file import (images → /captures, data → /import)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="importBtn"');
    expect(html).toContain('id="importFile"');
    expect(html).toContain("multiple");                 // multi-select enabled
    expect(html).toContain('fetch("/captures"');        // images go through the capture ingest path
    expect(html).toContain("readAsDataURL");            // base64-encodes each image
    expect(html).toContain("/import");                  // data files are auto-detected + routed
    // Restored minimum-severity floor: the import prompts once and forwards the chosen floor.
    expect(html).toContain("Minimum severity to import");
    expect(html).toContain("minSeverity");
  });

  it("wires the report-template editor (Settings) and the per-case template picker (#60)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Settings → Report Templates tab + editor controls
    expect(html).toContain('data-stab="reports"');
    expect(html).toContain('id="stab-reports"');
    expect(html).toContain('id="rtPicker"');
    expect(html).toContain('id="rtSections"');
    expect(html).toContain('id="rtSaveBtn"');
    expect(html).toContain("/report-templates");        // CRUD endpoint
    expect(html).toContain("loadReportTemplates");
    // Per-case picker in Case Details, wired to the per-case selection endpoint
    expect(html).toContain('id="rm-reportTemplate"');
    expect(html).toContain("/report-template");
    expect(html).toContain("saveCaseTemplate");
  });

  it("wires the hunting-profile panel + records suggested-hunt deploys via deploy-hunt (#157)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="sec-huntprofile"');
    expect(html).toContain('id="huntProfile"');
    expect(html).toContain("loadHuntProfile");
    expect(html).toContain("/hunt-outcomes");          // GET the per-case profile
    expect(html).toContain("/velociraptor/deploy-hunt"); // suggested-hunt deploys are recorded
    expect(html).toContain("hp-collect");              // pending hunts offer a "Collect now" affordance
    expect(html).toContain("hp-toggle");               // profile rows expand to show the hunt's result rows
    expect(html).toContain("/velociraptor/hunt-rows");  // on-demand results fetch for the profile
    expect(html).toContain("hp-collect-inline");        // live-preview banner offers Collect when not yet imported
    expect(html).toContain("not imported into the case yet");
    expect(html).toContain("vhs-regen");               // fleet hunts offer a per-card Regenerate (like playbook)
    expect(html).toContain("regenVeloHunt");
  });

  it("offers fit and mouse-wheel zoom for the asset graph (shared cytoscape toolbar)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const mod = await readFile(new URL("../../../public/js/graph-view.js", import.meta.url), "utf8");
    // The bespoke zoom in/out/reset buttons were replaced by the toolbar's Fit button plus
    // cytoscape's built-in mouse-wheel zoom (configured via wheelSensitivity in the module).
    expect(html).toContain('id="assetFit"');
    expect(mod).toContain("wheelSensitivity");
  });

  it("has the hypotheses panel (#140) with CRUD wiring and the notebook→hypothesis bridge", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="sec-hypotheses"');
    expect(html).toContain('id="hypList"');
    expect(html).toContain('id="hypAddBtn"');
    expect(html).toContain("loadHypotheses");
    expect(html).toContain("/hypotheses");            // CRUD endpoint
    expect(html).toContain("hypPatch");               // inline status/assignee/notes PATCH
    expect(html).toContain("hypDelete");
    expect(html).toContain("hypotheses_changed");      // WS refresh
    expect(html).toContain("promoteToHypothesis");     // notebook → hypothesis bridge
    // The promote bridge must surface success/failure, never swallow it silently (a stale-server
    // 404 would otherwise look like a dead button).
    expect(html).toContain("promote failed:");
  });

  it("includes the geo panel, loader, leaflet include, and focus hook (#133)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="sec-geomap"');
    expect(html).toContain("function loadGeoMap");
    expect(html).toContain("/vendor/leaflet/leaflet.js");
    expect(html).toContain("function geoFocusIp");
    expect(html).toContain("/geo-map");
  });

  it("wires the mark-false-positive modal (reason/note/candidates/whitelist) (#227)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="fpOverlay"');
    expect(html).toContain('id="fpConfirmBtn"');
    expect(html).toContain('id="fpAskAiBtn"');
    expect(html).toContain("openFalsePositiveModal");
    expect(html).toContain("/false-positive/suggest");
    expect(html).toContain('id="sec-false-positive"');
  });

  it("renders each false-positive marker's reason in the False Positives panel (#227)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("function renderFalsePositives");
    // The reason field must actually be read and rendered, not just captured by the mark-FP modal.
    expect(html).toMatch(/m\.reason[\s\S]{0,200}esc\(m\.reason\)/);
  });

  it("visually distinguishes an already-marked-false-positive IOC in the main IOC list, independent of the Hide FP/no-intel toggle (#227)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // fpVals must be computed unconditionally (not just inside the hideFpNoIntel branch), so a
    // marked-but-visible IOC (toggle off, or it also has enrichment data) can still show its state.
    expect(html).toMatch(/const fpVals = fpIocValueSet\(\);\s*\n\s*if \(hideFpNoIntel\)/);
    expect(html).toContain("const isFp = fpVals.has(");
    // Struck-through value + an inline un-mark affordance, instead of an unmarked-looking row.
    expect(html).toMatch(/isFp[\s\S]{0,200}text-decoration:line-through/);
    expect(html).toMatch(/isFp[\s\S]{0,300}unfp-btn/);
  });

  it("renders an event-density heatmap above the timeline that buckets the full filtered set and zooms on click (#219)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="timelineHeatmap"');
    expect(html).toContain('class="tl-heatmap"');
    expect(html).toContain("function computeTimelineHeatmapBuckets");
    expect(html).toContain("function renderTimelineHeatmap");
    expect(html).toContain("function zoomToTimeWindow");
    // Bucketed from the SAME `visible` array renderTimelineEvents computes (post-filter, pre-pagination
    // slice), not the paginated page or the raw unfiltered `ft` — so density reflects every active filter
    // and the full dataset across all pages, not just the current page.
    expect(html).toMatch(/visible = sortTimelineEvents\(visible\);\s*\n\s*renderTimelineHeatmap\(visible\)/);
    // Click-to-zoom reuses the same filterFrom/filterTo path as the search-bar date filters.
    expect(html).toMatch(/zoomToTimeWindow[\s\S]{0,400}filterFrom = fromIso/);
    expect(html).toMatch(/zoomToTimeWindow\('\$\{from\}','\$\{to\}'\)/);
    // Bars colored by the bucket's worst severity, reusing the existing severity color palette.
    expect(html).toContain("KC_SEV_COLOR[b.maxSeverity]");
    // Mobile: collapses to a thin sparkline instead of the full-height bars.
    expect(html).toMatch(/@media \(max-width: 768px\)[\s\S]{0,80}\.tl-heatmap \{ height: 16px/);
    // A click must open the (possibly collapsed) filter panel — otherwise the Clear button and the
    // populated from/to fields it reveals stay invisible inside that hidden panel, leaving no
    // apparent way to undo the zoom.
    expect(html).toMatch(/function zoomToTimeWindow[\s\S]{0,700}setSearchBarOpen\(true, false\)/);
    // A persistent caption explains what the bars mean (not just a hover-only tooltip), and toggles
    // with the heatmap itself.
    expect(html).toContain('id="timelineHeatmapCaption"');
    expect(html).toMatch(/buckets\.length < 2\)[\s\S]{0,60}caption\.hidden = true/);
    expect(html).toMatch(/caption\.hidden = false/);
  });

  it("renders Ask-the-case and Explain-Event citations as clickable jump-to-event footnotes, not plain text (#222)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toMatch(/const events = citeEvents\(a\.relatedEventIds\)/);
    expect(html).toMatch(/const cited = citeEvents\(result\.relatedEventIds\)/);
    // The old plain esc-and-join rendering must be gone, not just supplemented.
    expect(html).not.toContain('(a.relatedEventIds || []).map(esc).join(", ")');
    expect(html).not.toContain('(result.relatedEventIds || []).map(esc).join(", ")');
  });

  it("makes citation footnotes inside the Explain Event modal clickable, even though #explainOverlay lives outside <main> (#222)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // #explainOverlay must be OUTSIDE <main> (a sibling, not a descendant) — this is what makes the
    // <main>-scoped delegated .ev-jump handler blind to clicks inside it, and is the precondition
    // for needing a dedicated listener here.
    expect(html.indexOf('id="explainOverlay"')).toBeLessThan(html.indexOf("<main>"));
    // A dedicated click listener scoped to #explainOverlay must handle .ev-jump clicks by calling
    // jumpToEvent — mirroring the existing #explainOverlay backdrop-close listener right above it.
    expect(html).toMatch(/document\.getElementById\("explainOverlay"\)\.addEventListener\("click", \(e\) => \{\s*\n\s*const ejump = e\.target\.closest[\s\S]{0,200}jumpToEvent\(ejump\.getAttribute\("data-evid"\)\)/);
  });

  it("cites the triggering finding(s) on each AI-suggested playbook hunt card, clickable (#222)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("function citeFindings(");
    expect(html).toMatch(/function citeFindings[\s\S]{0,400}class="finding-jump/);
    // PlaybookHuntSuggestion (playbookHunt.ts) has NO relatedFindingIds field of its own — unlike
    // huntSuggest.ts's HuntSuggestion. `citeFindings(s.relatedFindingIds)` would always be "" (dead
    // code that only type-checks because JS has no runtime field check). The real citation must be
    // derived from the enclosing task's own (singular) relatedFindingId via playbookTasks.find(...).
    // Scoped to renderTaskHunts specifically — the sibling fleet-hunt panel legitimately DOES call
    // citeFindings(s.relatedFindingIds) (see the next test), so a file-wide assertion would be wrong.
    expect(html).toMatch(/function renderTaskHunts[\s\S]{0,3000}playbookTasks\.find\(t => t\.id === taskId\)/);
    expect(html).toMatch(/function renderTaskHunts[\s\S]{0,3000}_pbhTask\.relatedFindingId/);
    expect(html).toMatch(/function renderTaskHunts[\s\S]{0,3000}citeFindings\(_pbhFindingIds\)/);
    expect(html).not.toMatch(/function renderTaskHunts[\s\S]{0,3000}citeFindings\(s\.relatedFindingIds\)/);
  });

  it("cites the triggering finding(s) on each AI-suggested fleet-hunt card (#222)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Unlike the playbook-hunt suggestions above, HuntSuggestion (huntSuggest.ts) DOES carry a real,
    // AI-populated relatedFindingIds array — so the fleet-hunt panel can cite it directly.
    expect(html).toMatch(/function renderVeloHuntSuggest[\s\S]{0,2000}citeFindings\(s\.relatedFindingIds\)/);
    expect(html).toMatch(/citeFindings\(s\.relatedFindingIds\)[\s\S]{0,1200}class="vhs-card"/);
  });

  it("shows a per-case AI cost breakdown card in Settings → Diagnostics, fetched alongside /diagnostics", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // Helper functions for formatting cost/tokens and rendering the card.
    expect(html).toContain("function diagFmtCost(");
    expect(html).toContain("function diagAiCostBucketRow(");
    expect(html).toContain("function renderAiCostCard(");
    expect(html).toContain('diagCard("AI cost — this case", rows)');
    // loadDiagnostics fetches /cases/:id/ai-cost in parallel with /diagnostics, scoped to the
    // currently-connected case, and passes it into renderDiagnostics for placement.
    expect(html).toMatch(/function loadDiagnostics\(\)[\s\S]{0,600}\/cases\/\$\{encodeURIComponent\(caseId\)\}\/ai-cost/);
    expect(html).toMatch(/function loadDiagnostics\(\)[\s\S]{0,900}Promise\.all\(\[diagFetch, costFetch\]\)/);
    expect(html).toMatch(/renderDiagnostics\(j\.report, cost\)/);
    // Empty caseId must not attempt a fetch to a malformed URL — costFetch resolves to null instead.
    expect(html).toMatch(/const costFetch = caseId\s*\n\s*\? fetch/);
    // The card renders directly after "AI connectivity & config", not at the end of the panel.
    expect(html).toMatch(/function renderDiagnostics\(report, cost\)[\s\S]*aiCard \+ renderAiCostCard\(cost\) \+ importers/);
  });

  it("the bundle run form offers a time scope and a mapping preview", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("velo-timescope");
    expect(html).toContain("time-scope-preview");
    // Every preset the server understands must be offered, and "all time" must be the default.
    for (const p of ["24h", "7d", "30d", "90d"]) expect(html).toContain(`value="${p}"`);
    expect(html).toContain("All time");
  });

  it("the time-scope preview lets a wrong mapping be corrected and saved", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("velo-ts-save");
    expect(html).toContain("time-scope-param-names");
    expect(html).toMatch(/velo-ts-p-start[\s\S]{0,400}velo-ts-p-end/);
  });

  it("the inline correction save seeds its body from the bundle's stored mapping, not from the rendered rows alone", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // The route does a full REPLACE (see its doc comment), and only artifacts with a rendered row in
    // the CURRENT preview get a ".velo-ts-row" — an artifact whose saved correction has no rendered row
    // (e.g. an end-only correction under a relative preset) would silently lose its correction if the
    // save body were built from rows alone. Pin that the function starts from the cached bundle's
    // timeScopeParamNames before it ever touches ".velo-ts-row".
    expect(html).toMatch(/function veloSaveTimeScopeParamNames\(bundleId, out\)[\s\S]{0,300}_veloBundles[\s\S]{0,150}timeScopeParamNames[\s\S]{0,150}velo-ts-row/);
  });

  it("anchors a custom time-scope's datetime-local inputs to UTC, not local wall-clock", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // The datetime-local value has no timezone of its own; the server expects a full ISO instant, so
    // the client must append seconds + the Z offset rather than let Date parsing assume local time.
    expect(html).toMatch(/function veloTimeScopeBody\(form\)[\s\S]{0,600}return \{ start: start \+ ":00Z", \.\.\.\(end \? \{ end: end \+ ":00Z" \} : \{\}\) \};/);
    // The UTC anchoring must not be hover-tooltip-only — an always-visible badge sits beside each input.
    expect(html).toMatch(/class="velo-ts-start"[\s\S]{0,250}>UTC</);
    expect(html).toMatch(/class="velo-ts-end"[\s\S]{0,250}>UTC</);
  });

  it("refuses to launch (and warns) when 'custom range…' is selected with no start date, instead of silently running unscoped", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // veloTimeScopeBody alone can't distinguish "All time" from "custom but unfilled" — both return
    // undefined — so a dedicated check must gate both the preview and the actual launch.
    expect(html).toMatch(/function veloTimeScopeIncomplete\(form\)[\s\S]{0,200}=== "custom" && !form\.querySelector\("\.velo-ts-start"\)\.value/);
    expect(html).toMatch(/function veloTimeScopePreview\(bundleId, form\)[\s\S]{0,200}veloTimeScopeIncomplete\(form\)\)[\s\S]{0,120}enter a start date to apply a custom time scope/);
    expect(html).toMatch(/function veloRunBundle\(bundleId, form\)[\s\S]{0,400}veloTimeScopeIncomplete\(form\)\)[\s\S]{0,120}enter a start date to apply a custom time scope[\s\S]{0,20}return;/);
  });

  it("guards the time-scope preview against out-of-order responses from rapid scope changes", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("let veloTsPreviewSeq = 0;");
    expect(html).toMatch(/function veloTimeScopePreview[\s\S]{0,900}const mySeq = \+\+veloTsPreviewSeq;/);
    // Both the success and error branches must bail out if a newer request has since superseded them.
    expect(html).toMatch(/\.then\(\(\{ ok, j \}\) => \{\s*\n\s*if \(mySeq !== veloTsPreviewSeq\) return;/);
    expect(html).toMatch(/\.catch\(e => \{ if \(mySeq !== veloTsPreviewSeq\) return;/);
  });

  it("renders the hunt job card's degraded time-scope coverage as explicitly unverified, not as zero", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    // A 0-of-N scoped count with degraded:true must read as "we couldn't check", never as "nothing
    // was scoped" — those are forensically different claims about the same collection.
    expect(html).toMatch(/const tsLine = job\.timeScope[\s\S]{0,700}job\.timeScope\.degraded[\s\S]{0,120}coverage unverified \(server reported no parameter metadata\)/);
  });
});

// ── Deep pass (#204) ─────────────────────────────────────────────────────────
// The batched deep pass was API-only. Its floor is case-dependent (prompt rows scale with HOSTS,
// so no default is correct), the run costs many minutes and hundreds of thousands of tokens, and a
// run with failed batches read LESS of the case than its event count suggests. All three are why
// this needs a surface with a pre-flight table, a cancel affordance, and honest result reporting.
//
// NOTE: assert on a BOOLEAN, never `expect(html).toContain(...)` — a failure there prints the whole
// 1.4 MB file into the diff and crashes the vitest reporter before any result is shown.
describe("dashboard.html — deep pass", () => {
  const load = () => readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const has = (html: string, needle: string) => html.includes(needle);
  const matches = (html: string, re: RegExp) => re.test(html);

  it("puts the run behind a pre-flight table of what each floor would cost", async () => {
    const html = await load();
    expect(has(html, '<section id="sec-deep-pass"'), "section exists").toBe(true);
    expect(has(html, "/deep-pass/preview"), "calls the preview endpoint").toBe(true);
    // One row per floor showing the four numbers the analyst decides on.
    expect(matches(html, /function renderDeepPassFloors[\s\S]{0,600}f\.events/), "row shows events").toBe(true);
    expect(matches(html, /function renderDeepPassFloors[\s\S]{0,800}f\.rows/), "row shows prompt rows").toBe(true);
    expect(matches(html, /function renderDeepPassFloors[\s\S]{0,800}f\.batches/), "row shows batches").toBe(true);
    expect(matches(html, /function renderDeepPassFloors[\s\S]{0,900}estimatedInputTokens/), "row shows estimated input").toBe(true);
  });

  it("loads the preview lazily rather than on every state push", async () => {
    const html = await load();
    // AI-free but NOT CPU-free — it groups the whole graded timeline four times, so it is fetched
    // when the analyst opens the section (or asks for a refresh), never on each WS state broadcast.
    expect(matches(html, /#sec-deep-pass h2"\)[\s\S]{0,400}loadDeepPassPreview/), "loads on expand").toBe(true);
    expect(has(html, 'id="deepPassRefresh"'), "has a refresh control").toBe(true);
  });

  it("never runs without an explicit floor", async () => {
    const html = await load();
    // The server refuses an unrecognised floor rather than reading everything; the UI must not
    // paper over that with a default of its own.
    expect(matches(html, /function runDeepPass\(\)[\s\S]{0,1000}minSeverity/), "posts the floor").toBe(true);
    expect(matches(html, /function runDeepPass\(\)[\s\S]{0,600}if \(!cid \|\| !floor\)[\s\S]{0,200}return;/), "no floor → no request").toBe(true);
  });

  it("shows failed batches as partial coverage instead of a clean run", async () => {
    const html = await load();
    expect(matches(html, /function renderDeepPassResult[\s\S]{0,2000}batchesFailed/), "reports batchesFailed").toBe(true);
    expect(matches(html, /function renderDeepPassResult[\s\S]{0,2000}partial coverage/i), "names it partial coverage").toBe(true);
    // A cancelled run wrote nothing — it must not read as a completed pass either.
    expect(matches(html, /function renderDeepPassResult[\s\S]{0,2000}r\.aborted/), "distinguishes a cancelled run").toBe(true);
  });

  it("keeps the last result across a reload, so batchesFailed can't vanish with the response body", async () => {
    const html = await load();
    expect(has(html, "dfir.deepPassResult"), "per-case storage key").toBe(true);
    expect(matches(html, /localStorage\.setItem\(deepPassResultKey\(/), "persists the result").toBe(true);
  });

  it("renders a refusal as guidance, not as a failure", async () => {
    const html = await load();
    // 400 = over the batch ceiling; its message already names a floor that would fit. 423 = the
    // case is closed/archived. Both are analyst-correctable, so neither is an error banner.
    expect(matches(html, /function runDeepPass[\s\S]{0,2000}r\.status === 400 \|\| r\.status === 423/), "handles both refusals").toBe(true);
    expect(matches(html, /function runDeepPass[\s\S]{0,2000}deepPassGuidance/), "routes them to guidance").toBe(true);
  });

  it("disables the run on the SYNTHESIS gate, not the vision one", async () => {
    const html = await load();
    // /health.aiEnabled is hasAiProvider() — the vision gate. The deep-pass route enforces
    // hasSynthesisProvider(), so gating the button on aiEnabled would offer a guaranteed 501.
    expect(has(html, "h.synthesisEnabled"), "reads the synthesis flag from /health").toBe(true);
    expect(has(html, "deepPassSynthesisEnabled"), "gates the run on it").toBe(true);
  });

  it("won't let a deep pass and a re-synthesis overwrite each other", async () => {
    const html = await load();
    // The job registry's `exclusive` flag only cancels jobs of the SAME kind, and the deep pass's
    // own final synthesize() is not registered as a "synthesis" job — so nothing on the server
    // stops a Re-synthesize started mid-run from racing the deep pass's write.
    expect(matches(html, /function applyHeavyAiJobLock[\s\S]{0,200}deepPassBusy\(\)/), "knows a deep pass is running").toBe(true);
    expect(matches(html, /function applyHeavyAiJobLock[\s\S]{0,400}"synthesize"/), "locks the synthesize button").toBe(true);
    expect(matches(html, /function deepPassJob\(\)[\s\S]{0,200}"deep-pass"/), "finds the deep-pass job in the registry").toBe(true);
  });

  it("cancels through the job registry rather than inventing its own control", async () => {
    const html = await load();
    expect(matches(html, /function cancelDeepPass[\s\S]{0,500}cancelJob\(/), "reuses cancelJob").toBe(true);
    expect(has(html, 'id="deepPassCancel"'), "has a cancel button").toBe(true);
  });

  it("carries a toolbar button with a ::before icon so it survives the icons-only collapse", async () => {
    const html = await load();
    expect(has(html, 'id="deepPassBtn"'), "toolbar button").toBe(true);
    expect(has(html, "#deepPassBtn::before"), "icon rule").toBe(true);
    // The icon must be in the shared sizing rule too, or ::before has no box to paint into.
    expect(matches(html, /#deepPassBtn::before[,\s][\s\S]{0,500}background: no-repeat center \/ contain;/), "sized by the shared rule").toBe(true);
  });

  it("registers the section for visibility settings", async () => {
    const html = await load();
    expect(matches(html, /SECTION_DEFS = \[[\s\S]{0,3000}id: "sec-deep-pass"/), "listed in SECTION_DEFS").toBe(true);
  });

  it("says so on the AI pill while it runs, instead of leaving it on 'ready'", async () => {
    const html = await load();
    // The route emits phase "deep-pass"; the pill must render that detail verbatim — and the branch
    // has to sit BEFORE the isIngest fallback, which would otherwise label the longest AI run in the
    // product "deterministic import — not AI" whenever live analysis is paused.
    expect(matches(html, /evt\.phase === "deep-pass"[\s\S]{0,120}setAi\("analyzing"/), "renders the deep-pass phase").toBe(true);
    expect(matches(html, /if \(evt\.phase === "deep-pass"\)[\s\S]{0,400}else if \(evt\.phase === "synthesizing"\)/), "checked before the ingest fallback").toBe(true);
  });
});

describe("dashboard.html — help icon", () => {
  const load = () => readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  it("links to the online user manual from the toolbar", async () => {
    const html = await load();
    expect(html).toMatch(/id="helpBtn"[^>]*href="https:\/\/hasamba\.github\.io\/DFIR-Companion\/manual\/"/);
    // Opens in a new tab without handing the manual a live window.opener reference.
    expect(html).toMatch(/id="helpBtn"[^>]*target="_blank"[^>]*rel="noopener noreferrer"/);
    // Icon-only control, so it needs an accessible name.
    expect(html).toMatch(/id="helpBtn"[^>]*aria-label="User manual"/);
  });

  it("sits immediately left of the settings gear and is styled to match it", async () => {
    const html = await load();
    expect(html).toMatch(/id="helpBtn"[\s\S]{0,1200}?<button id="settingsBtn"/);
    expect(html).toContain("#helpBtn { background: none;");
    expect(html).toContain("#helpBtn:hover");
  });
});
