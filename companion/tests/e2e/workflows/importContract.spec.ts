import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect } from "../fixtures/test.js";

// Covers: NO USER STORY EXISTS.
// The shared contract every /cases/:id/import* route obeys — reject an unknown case, reject an
// empty payload — is not written down as a story; the Evidence Import stories each describe one
// importer's MAPPING semantics instead. Claiming those ids here would say the mapping is tested
// when only the contract is. importers.spec.ts covers the mapping ones.
//
// This is the regression test for the guard added in #403 (companion/src/routes/importCaseGuard.ts).
// It is table-driven across every route on purpose: the guard is registered once, ahead of all of
// them, so a change that accidentally narrows its scope would otherwise only show up on whichever
// single route someone happened to test.

/** Every import route, with the body field its 400 guard requires. Extracted from src/routes/import.ts. */
const ROUTES: ReadonlyArray<{ route: string; required: string }> = [
  { route: "import", required: "text" },
  { route: "import-file", required: "path" },
  { route: "import-csv", required: "csv" },
  { route: "import-log", required: "text" },
  { route: "import-thor", required: "json" },
  { route: "import-siem", required: "json" },
  { route: "import-chainsaw", required: "json" },
  { route: "import-hayabusa", required: "text" },
  { route: "import-velociraptor", required: "text" },
  { route: "import-network", required: "text" },
  { route: "import-kape", required: "text" },
  { route: "import-cybertriage", required: "text" },
  { route: "import-leapp", required: "text" },
  { route: "import-aws", required: "text" },
  { route: "import-cloud-activity", required: "text" },
  { route: "import-m365", required: "text" },
  { route: "import-plaso", required: "text" },
  { route: "import-sandbox", required: "text" },
  { route: "import-memory", required: "text" },
  { route: "import-email", required: "text" },
  { route: "import-thehive", required: "text" },
  { route: "import-auditd", required: "text" },
  { route: "import-journald", required: "text" },
  { route: "import-sysdig", required: "text" },
  { route: "import-wazuh", required: "text" },
];

test("the table below really is every import route", () => {
  // This spec claims to cover EVERY import route. That claim was false the moment it was written:
  // the table was built with a regex that stopped at the first digit, so /cases/:id/import-m365 was
  // silently absent — a route with no contract coverage, in a file whose whole point is that the
  // guard applies to all of them. Checking the table against the source makes the claim testable
  // instead of aspirational.
  const src = readFileSync(join(import.meta.dirname, "..", "..", "..", "src", "routes", "import.ts"), "utf8");
  const inSource = [...src.matchAll(/app\.post\("\/cases\/:id\/(import[A-Za-z0-9-]*)"/g)]
    .map((m) => m[1])
    .sort();
  const inTable = ROUTES.map((r) => r.route).sort();
  expect(inTable).toEqual(inSource);
});

test("every import route 404s an unknown case instead of conjuring one", async ({ page, demoCase }) => {
  test.setTimeout(120_000);
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const ghost = "no-such-case-contract";
  const wrong: string[] = [];

  for (const { route, required } of ROUTES) {
    const res = await page.request.post(`/cases/${ghost}/${route}`, {
      data: { [required]: "x", filename: "probe.txt" },
    });
    if (res.status() !== 404) wrong.push(`${route} -> ${res.status()}`);
  }

  // Before #403 an import into a typo'd case id created the directory and wrote evidence into it,
  // where the investigator could never see it: GET /cases never listed the case.
  expect(wrong, `routes that did not 404 an unknown case: ${wrong.join(", ")}`).toEqual([]);

  // ...and the rejection must not have created the case as a side effect.
  const listed = await page.request.get("/cases");
  expect(await listed.text()).not.toContain(ghost);
});

test("every import route 400s an empty payload", async ({ page, demoCase }) => {
  test.setTimeout(120_000);
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const wrong: string[] = [];
  for (const { route, required } of ROUTES) {
    const res = await page.request.post(`/cases/${demoCase}/${route}`, {
      data: { [required]: "   ", filename: "empty.txt" },
    });
    // A whitespace-only payload is the shape a mis-wired dashboard upload sends. It must be
    // refused rather than recorded as a zero-event import, which would leave a custody entry
    // claiming evidence was ingested when none was.
    if (res.status() !== 400) wrong.push(`${route} -> ${res.status()}`);
  }

  expect(wrong, `routes that accepted an empty payload: ${wrong.join(", ")}`).toEqual([]);
});
