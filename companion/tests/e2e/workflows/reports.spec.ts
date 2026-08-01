import { test, expect } from "../fixtures/test.js";

// Covers: US-082, US-084, US-085, US-142
// (feature-user-stories.csv) — the report artifacts an investigator hands over (markdown, HTML,
// DOCX, timeline CSV, ATT&CK Navigator layer), report and case templates, and presentation mode.
//
// THE STORY'S PATHS ARE WRONG, and that is worth knowing before reading these tests. US-082 says
// "GET /cases/:id/report/:file (md/html/docx/csv); report.docx, incident-timeline.csv,
// attack-layer.json" — but /report/:file allows ONLY report.md and report.html
// (src/routes/reportsExport.ts). The other three are separate routes entirely:
//
//   /cases/:id/report.docx            (reportsExport.ts)
//   /cases/:id/incident-timeline.csv  (timeline.ts)
//   /cases/:id/attack-layer.json      (analysisGraph.ts)
//
// The feature is all there; the story describes it as one endpoint when it is four. Asserting the
// real paths, and noting it here rather than filing the difference as a product defect.

/** Generate the report once, so the artifacts exist to fetch. */
async function generateReport(page: import("@playwright/test").Page, caseId: string): Promise<void> {
  const res = await page.request.post(`/cases/${caseId}/report`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
}

test("US-082: every report artifact downloads with the right content type", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await generateReport(page, demoCase);

  const artifacts: ReadonlyArray<{ path: string; type: RegExp; contains?: string }> = [
    { path: `report/report.md`, type: /markdown/, contains: "#" },
    { path: `report/report.html`, type: /html/, contains: "<" },
    { path: `report.docx`, type: /wordprocessingml/ },
    { path: `incident-timeline.csv`, type: /csv/ },
    { path: `attack-layer.json`, type: /json/ },
  ];

  for (const artifact of artifacts) {
    const res = await page.request.get(`/cases/${demoCase}/${artifact.path}`);
    expect(res.status(), `${artifact.path}: ${await res.text()}`).toBe(200);

    // The content type is what makes a browser download rather than render it, and what makes Word
    // open the DOCX. A correct body served as text/plain is still a broken deliverable.
    expect(res.headers()["content-type"], `${artifact.path} content type`).toMatch(artifact.type);

    const body = await res.body();
    // Not just non-empty: a zero-byte DOCX still "downloads" and then fails to open.
    expect(body.byteLength, `${artifact.path} is empty`).toBeGreaterThan(100);
    if (artifact.contains) expect(body.toString("utf8")).toContain(artifact.contains);
  }
});

test("US-082: an unknown report file is refused rather than served", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The allowlist is what stops the :file parameter reading arbitrary paths out of the case.
  const res = await page.request.get(`/cases/${demoCase}/report/../../case.json`);
  expect(res.status(), await res.text()).toBeGreaterThanOrEqual(400);

  const unknown = await page.request.get(`/cases/${demoCase}/report/report.pdf`);
  expect(unknown.status()).toBe(400);
});

test("US-082: the ATT&CK layer is a Navigator-loadable document", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await generateReport(page, demoCase);

  const res = await page.request.get(`/cases/${demoCase}/attack-layer.json`);
  expect(res.status()).toBe(200);
  const layer = (await res.json()) as { techniques?: unknown[]; domain?: string; name?: string };

  // Navigator rejects a layer without its techniques array, so an export that omits it is a file
  // the analyst cannot actually open — the one thing this export exists to produce.
  expect(Array.isArray(layer.techniques), "a layer needs a techniques array").toBe(true);
  expect(layer.techniques?.length, "the seeded case maps 21 techniques").toBeGreaterThan(0);
});

test("US-084: report templates list and bind per case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const listed = await page.request.get("/report-templates");
  expect(listed.status(), await listed.text()).toBe(200);
  const templates = (await listed.json()) as Array<{ id: string; name: string }>;
  expect(templates.length, "the shipped report templates").toBeGreaterThan(0);

  // The binding is per case, which is how two cases in one installation can produce differently
  // shaped reports.
  const bound = await page.request.get(`/cases/${demoCase}/report-template`);
  expect(bound.status()).toBe(200);
  const current = ((await bound.json()) as { templateId: string }).templateId;
  expect(
    templates.map((t) => t.id),
    "the bound template must exist",
  ).toContain(current);
});

test("US-085: case templates list and carry a description", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/templates");
  expect(res.status(), await res.text()).toBe(200);
  const templates = (await res.json()) as Array<{ id: string; name: string; description: string }>;

  expect(templates.length, "the shipped case templates").toBeGreaterThan(0);
  // These are picked in the new-case dialog, where the description is the only thing distinguishing
  // "Ransomware" from "Business Email Compromise" to someone who has not used them.
  for (const t of templates) {
    expect(t.name, `template ${t.id} has no name`).toBeTruthy();
    expect(t.description, `template ${t.id} has no description`).toBeTruthy();
  }
});

test("US-142: presentation mode returns both its data and its rendered view", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const data = await page.request.get(`/cases/${demoCase}/presentation`);
  expect(data.status(), await data.text()).toBe(200);
  const body = (await data.json()) as { caseId: string; caseName: string };
  expect(body.caseId).toBe(demoCase);
  // A deck with no case name is an unlabelled slide in front of a client.
  expect(body.caseName).toBeTruthy();

  // /present is the rendered view an analyst actually projects.
  const view = await page.request.get(`/cases/${demoCase}/present`);
  expect(view.status(), await view.text()).toBe(200);
  expect(view.headers()["content-type"]).toMatch(/html/);
  expect((await view.body()).byteLength, "an empty presentation view").toBeGreaterThan(1000);
});
