import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { test, expect, caseIdFor } from "../fixtures/test.js";
import type { Page, TestInfo } from "@playwright/test";

// Covers: US-002, US-013, US-082, US-282
// (US-282 — the last-import summary banner — is asserted in step 3: #importMeta must name the
// imported file and the importer the server picked, from /cases/:id/import-meta.)
// (feature-user-stories.csv) — case creation, unified evidence import and the report artifacts,
// joined into ONE journey driven entirely by the mouse and keyboard.
//
// WHY THIS FILE EXISTS. The rest of the browser suite proves the SERVER is right: it opens the
// dashboard and then calls /import, /report and the rest through page.request (276 API calls
// against 30 clicks across the whole suite). That leaves the analyst's actual path — the buttons,
// the file chooser, the view menu, the download link — almost entirely unasserted. Every control
// on that path could be broken, disabled or missing and the suite would still be green.
//
// So nothing here may take a shortcut:
//   - the case is CREATED in the dialog, never POSTed to /cases;
//   - the evidence arrives through the real file chooser, never page.request.post("/import");
//   - the timeline is reached with the view menu, never by injecting CSS with revealSections();
//   - the report is generated from the Export menu and fetched by CLICKING the download link.
//
// The one deliberate exception is the FINAL assertion, which re-reads the downloaded bytes. That
// is checking the artifact the analyst now holds, not substituting for a step they performed.
//
// Any assertion here that could pass while the UI is broken belongs in another file.

/**
 * THOR JSONL — one finding per line. Shape borrowed from importers.spec.ts, which took it from
 * tests/analysis/thorImport.test.ts.
 *
 * THOR is chosen over CSV on purpose. It is a DETERMINISTIC importer: it parses and grades before
 * it answers, so the events reach the forensic timeline without an AI round-trip. A CSV would be
 * handed to the model, and the e2e stub answers fixed prose rather than the structured JSON the
 * CSV path needs — the import would succeed and the timeline would stay empty, which would look
 * exactly like a broken import button.
 *
 * The values are marked E2E-JOURNEY so a failure downstream can be traced to this fixture rather
 * than to whatever else the case happens to contain. The hostname is deliberately not a real one.
 */
const THOR_EVIDENCE = [
  {
    time: "2026-06-03T09:43:07Z",
    hostname: "E2E-JOURNEY-HOST",
    level: "Alert",
    module: "ProcessCheck",
    message: "Malicious process found",
    pid: 8684,
    process_name: "e2e-journey-evil.exe",
    image_file: "C:\\Tools\\e2e-journey-evil.exe",
    image_sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
    reason_1: "YARA rule Powerkatz_DLL / Detects Mimikatz",
  },
  {
    time: "2026-06-03T09:43:30Z",
    hostname: "E2E-JOURNEY-HOST",
    level: "Warning",
    module: "Filescan",
    message: "Possibly Dangerous file found",
    file: "C:\\Users\\srv\\e2e-journey-Trigona.ps1",
    reason_1: "YARA rule SUSP_PS1 / Suspicious PowerShell",
  },
]
  .map((row) => JSON.stringify(row))
  .join("\n");

/**
 * Write the evidence to a real file on disk.
 *
 * setFiles() accepts an in-memory buffer, which would be quicker. A path is used instead because
 * that is what the browser's file chooser actually hands over, filename and extension included —
 * and the server sniffs the filename when it picks an importer.
 *
 * The filename deliberately does NOT say "thor". The import banner asserted later is matched
 * against /thor/i, and a filename containing "thor" would satisfy that match on its own — the test
 * would pass without the server ever having sniffed the format. Named this way, the only thing that
 * can put "thor" on screen is the importer the server chose.
 *
 * The file goes in testInfo.outputPath(), NOT a mkdtemp() directory. A mkdtemp() dir has to be
 * removed by hand, and a test that fails or is interrupted before its cleanup line never removes
 * it — vitest.config.ts records stranded temp dirs reaching 388,954 (#173), and server-entry.ts
 * carries SIGINT/SIGTERM handlers for the same reason. Playwright owns this directory instead: it
 * clears test-results/ at the start of every run, so there is nothing to leak and no cleanup to
 * forget. It also puts the evidence beside the failure screenshot when this test does fail.
 */
function writeEvidenceFile(testInfo: TestInfo): string {
  const path = testInfo.outputPath("scan-export.jsonl");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, THOR_EVIDENCE, "utf8");
  return path;
}

/**
 * Open the dashboard and wait until it can respond to a click.
 *
 * The toolbar's handlers are bound after the page's startup fetches (/cases, /disk-stats,
 * /dashboard-views). Under a loaded server the buttons paint before their handlers exist, so a
 * click lands on nothing. caseCreate.spec.ts hit exactly this: it passed in isolation and failed
 * with four workers against one server. Waiting for the network to settle fixes the cause; a
 * longer assertion timeout would only have hidden it.
 */
async function openDashboard(page: Page): Promise<void> {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");
  await expect(page.locator("#newCaseBtn")).toBeEnabled();
}

test("an analyst creates a case, imports evidence, reads the timeline and downloads the report — by clicking", async ({
  page,
}, testInfo) => {
  // The default 30s test timeout is too short for a whole journey — import, render, synthesis and
  // report generation all happen inside this one test, and the report assertion below allows 60s
  // on its own, which the default would kill first. Raised deliberately rather than by trimming the
  // per-assertion budgets, which are what keep a slow CI worker from failing an otherwise fine run.
  test.setTimeout(120_000);

  // Built by the shared caseIdFor() helper — workerIndex + retry + untruncated testId. This test
  // CREATES its case through the dialog, so a reused id is not a shared-state nuisance the way it
  // is for a seeded spec: POST /cases answers 409, the dialog stays open on "a case with that id
  // already exists", and the very first assertion fails, burying whatever actually went wrong.
  // The traps that make the helper's shape necessary are documented on the helper itself
  // (fixtures/test.ts) — this file used to carry a hand-rolled copy with two of them intact.
  const caseId = caseIdFor("e2e-journey", testInfo);
  const caseName = "E2E journey — end to end by mouse";
  const evidencePath = writeEvidenceFile(testInfo);

  await openDashboard(page);

  // ── 1. Create the case in the dialog ────────────────────────────────────────
  await page.locator("#newCaseBtn").click();
  const dialog = page.locator("#newCaseOverlay");
  await expect(dialog).toHaveClass(/\bopen\b/);
  // openNewCase() awaits suggestCaseId(), which fetches /api/next-case-id and OVERWRITES #ncCaseId.
  // Typing before that resolves puts the suggestion on top of the typed id, and the rest of the
  // journey then runs against a case this test never named.
  await expect(dialog.locator("#ncCaseId")).not.toHaveValue("");

  await dialog.locator("#ncCaseId").fill(caseId);
  await dialog.locator("#ncName").fill(caseName);
  await dialog.locator("#ncInvestigator").fill("e2e journey");
  await dialog.locator("#ncCreate").click();

  await expect(dialog, "the dialog closes only once the case is created").not.toHaveClass(/\bopen\b/);
  // createNewCase() calls connect() on success, so the dashboard is now attached to the new case.
  // The id lives in an input value, not in body text.
  await expect(page.locator("#caseId")).toHaveValue(caseId);

  // ── 2. Import evidence through the real file chooser ────────────────────────
  // #importFile is display:none and #importBtn clicks it programmatically. The browser still opens
  // a chooser, so this is the genuine article: no test in the suite has ever exercised it —
  // setInputFiles appears zero times across all 41 spec files, and every other import is a POST.
  // Bounded independently of the 120s test budget. A file chooser either opens on the click or it
  // never will — it waits on no server work — so inheriting the test timeout just means a dead
  // Import button burns two minutes before reporting itself. Confirmed: the mutation that empties
  // this handler failed in 2.0m on the inherited budget and in 17s on this one.
  const chooser = page.waitForEvent("filechooser", { timeout: 15_000 });
  await page.locator("#importBtn").click();
  await (await chooser).setFiles(evidencePath);

  // The import asks for a severity floor once per batch. "info" keeps everything, which is what
  // makes the count assertions below mean "every event THOR reported" rather than "whatever
  // survived a filter this test chose".
  const sevDialog = page.locator("#importSevOverlay");
  await expect(sevDialog, "the analyst is asked for a severity floor before anything lands").toHaveClass(
    /\bopen\b/,
  );
  await sevDialog.locator("#importSevSelect").selectOption("info");
  await sevDialog.locator("#importSevOk").click();
  await expect(sevDialog).not.toHaveClass(/\bopen\b/);

  // NOT asserted here: #status. It looks like the obvious check — it is what the analyst watches
  // during an import — but it is a shared, transient line that dashboard-ai-status.js:114 rewrites
  // to "connected (live)" on every websocket tick. Asserting the import summary there passed in a
  // 2.8s local run and lost the race on a slower traced retry, reporting "the import never
  // happened" while the server log showed a clean 202. The durable record is checked in step 3
  // instead, once the analyst has navigated somewhere that shows it.

  // ── 3. Navigate to the timeline with the view menu ──────────────────────────
  // A new case opens in the "Now" view, whose section list is ["sec-now", "sec-host-duplicates"] —
  // the forensic timeline is hidden. That is the whole reason this step exists: reaching the
  // timeline is a real navigation the analyst must perform, and every other spec skips it by
  // injecting CSS with revealSections().
  const timeline = page.locator("#sec-timeline");
  await expect(timeline, "a new case opens in the Now view, which hides the timeline").toBeHidden();

  await page.locator("#dashViewBtn").click();
  const viewMenu = page.locator("#dashViewMenu");
  await expect(viewMenu).toBeVisible();
  await viewMenu.locator('.dv-item[data-view="triage"]').click();

  await expect(timeline, "picking Triage brings the forensic timeline into view").toBeVisible();

  // The import banner is the DURABLE record that the file was understood. It renders from
  // /cases/:id/import-meta, so unlike #status it survives every re-render and every websocket tick.
  const importBanner = page.locator("#importMeta");
  await expect(importBanner, "the import left no record on the timeline panel").toBeVisible({
    timeout: 60_000,
  });
  // It names the file the analyst picked in the chooser...
  await expect(importBanner, "the import banner does not name the imported file").toContainText(
    "scan-export.jsonl",
  );
  // ...and the importer the SERVER chose for it. The filename says nothing about THOR, so this can
  // only pass if the content sniffing ran and routed the file, rather than accepting an opaque blob.
  await expect(importBanner, "the server did not report which importer it picked").toContainText(/thor/i);

  // THE CLAIM OF THIS STEP: the evidence the analyst chose in step 2 is on screen. Asserting the
  // row count alone would pass on a timeline full of something else.
  const rows = page.locator("#sec-timeline .ev-row");
  await expect
    .poll(async () => rows.count(), { timeout: 30_000 })
    .toBeGreaterThanOrEqual(THOR_EVIDENCE.split("\n").length);
  await expect(page.locator("#forensicTimeline")).toContainText("e2e-journey-evil.exe");

  // ── 4. Generate the report from the Export menu ─────────────────────────────
  await page.locator("#exportSelect").selectOption("report");

  // ── 5. Download it by clicking the link ─────────────────────────────────────
  // Waiting on #reportLinks rather than on #status ("report written") for the same reason as the
  // import above: the ticker owns #status and will overwrite it. The links are written in the same
  // callback as that message, and nothing on a timer touches them — so they are the durable half of
  // the same event, and they are what the analyst actually needs in order to continue.
  const links = page.locator("#reportLinks");
  await expect(links.locator("a"), "generating the report produced no download links").not.toHaveCount(0, {
    timeout: 60_000,
  });
  const markdownLink = links.locator("a", { hasText: "Download Markdown" });
  await expect(markdownLink, "the download the analyst is told to use must exist").toHaveCount(1);

  // Bounded for the same reason, with more room: this one does wait on the server streaming the
  // file back, where the chooser above waits on nothing.
  const downloadPromise = page.waitForEvent("download", { timeout: 30_000 });
  await markdownLink.click();
  const download = await downloadPromise;

  // A zero-byte file still "downloads" and then opens empty, so the bytes are read back. This is
  // the artifact the analyst hands over — the only thing in the journey that leaves the building.
  const savedPath = await download.path();
  expect(savedPath, "the download produced no file").toBeTruthy();
  const report = readFileSync(savedPath, "utf8");

  expect(report.length, "the downloaded report is empty").toBeGreaterThan(200);

  // NOT asserted here: the case NAME and the INVESTIGATOR typed into the New case dialog in step 1.
  // Neither appears in the report, and that is the product's current design rather than a defect
  // this test found — src/reports/markdown.ts reads meta.investigators, which is the separate
  // "Case details" report-metadata form (#rm-* fields), so a fresh case reports
  // "_(investigator not set)_" however the dialog was filled in. Pinning caseName here asserted a
  // link that does not exist; the two claims below are the ones the report really makes.

  // The Chain of Custody appendix names the artifact by the filename the analyst chose in the file
  // chooser in step 2. That is the audit trail an investigator is questioned on, and it ties the
  // deliverable to the file that was actually handed over.
  expect(report, "the chain of custody does not name the imported artifact").toContain("scan-export.jsonl");
  // And the evidence itself reached the deliverable. This is the link the whole journey is for:
  // a report that generates and downloads but omits the analyst's evidence is a silent failure,
  // and the one no API-level test in this suite can catch.
  expect(report, "the imported evidence never reached the report").toContain("E2E-JOURNEY-HOST");
});
