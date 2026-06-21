import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

describe("dashboard.html", () => {
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

  it("wires the compromised-assets section + asset↔IoC graph with type toggles", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="assetGraph"');
    expect(html).toContain('id="assetList"');
    expect(html).toContain('class="asset-type-toggle"');
    expect(html).toContain('value="account"');
    expect(html).toContain("/asset-graph");
  });

  it("offers fullscreen and layout (horizontal/vertical/radial) controls for the graph", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="assetFullscreen"');
    expect(html).toContain('id="assetLayout"');
    expect(html).toContain('value="vertical"');
    expect(html).toContain('value="radial"');
    expect(html).toContain("requestFullscreen");
  });

  it("wires the Ask-the-AI panel (ask + add-to-open-questions)", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="askInput"');
    expect(html).toContain('id="askBtn"');
    expect(html).toContain('id="askAnswer"');
    expect(html).toContain("/ask");
    expect(html).toContain("/questions");
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
    expect(html).toContain('"dfir.sectionOrder"');
    // Ask section comes before Executive Summary in the default markup.
    expect(html.indexOf("Ask the LLM about this case")).toBeLessThan(html.indexOf("Executive Summary"));
    // A saved order that predates a section keeps that section ANCHORED at its natural HTML
    // slot (so the default-first Ask panel still shows first), instead of dumping it at the end.
    expect(html).toContain("savedExisting");
    expect(html).not.toContain("new/unknown sections go to the end");
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
  });

  it("offers zoom in/out/fit buttons and mouse-wheel zoom for the graph", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="assetZoomIn"');
    expect(html).toContain('id="assetZoomOut"');
    expect(html).toContain('id="assetZoomReset"');
    expect(html).toContain('addEventListener("wheel"');
  });
});
