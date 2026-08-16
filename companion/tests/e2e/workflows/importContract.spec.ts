import { test, expect } from "../fixtures/test.js";
import { EVIDENCE_IMPORT_ROUTES } from "../../../src/routes/importCaseGuard.js";

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

// The body field each route's own 400 guard demands, keyed by route.
//
// This file used to carry its own hand-written copy of the route list and check it with a regex
// over src/routes/import.ts. The copy went stale TWICE while claiming to cover every route: the
// original regex stopped at the first digit and silently dropped import-m365, and #554 added
// import-leapp without adding the row. Both times a route sat with no contract coverage in the one
// file whose whole point is that the guard covers all of them.
//
// So the list is no longer written down here. EVIDENCE_IMPORT_ROUTES is what actually mounts the
// guard, and tests/server/importMissingCase.test.ts walks the LIVE Express router and fails if a
// registered /cases/:id/import* route is missing from it — so the routes below cannot drift from
// the app. Record<> then makes the remaining hand-maintained part self-enforcing: a route added to
// that constant without a required field here is a `npm run typecheck` failure, in seconds, rather
// than a red E2E run minutes later — or, as happened twice, no failure at all.
const REQUIRED_FIELD: Record<(typeof EVIDENCE_IMPORT_ROUTES)[number], string> = {
  import: "text",
  "import-file": "path",
  "import-csv": "csv",
  "import-log": "text",
  "import-thor": "json",
  "import-siem": "json",
  "import-chainsaw": "json",
  "import-hayabusa": "text",
  "import-velociraptor": "text",
  "import-network": "text",
  "import-kape": "text",
  "import-cybertriage": "text",
  "import-m365": "text",
  "import-leapp": "text",
  "import-aws": "text",
  "import-cloud-activity": "text",
  "import-plaso": "text",
  "import-sandbox": "text",
  "import-memory": "text",
  "import-email": "text",
  "import-thehive": "text",
  "import-auditd": "text",
  "import-journald": "text",
  "import-sysdig": "text",
  "import-wazuh": "text",
};

const ROUTES: ReadonlyArray<{ route: string; required: string }> = EVIDENCE_IMPORT_ROUTES.map((route) => ({
  route,
  required: REQUIRED_FIELD[route],
}));

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
  const misnamed: string[] = [];
  for (const { route, required } of ROUTES) {
    const res = await page.request.post(`/cases/${demoCase}/${route}`, {
      data: { [required]: "   ", filename: "empty.txt" },
    });
    // A whitespace-only payload is the shape a mis-wired dashboard upload sends. It must be
    // refused rather than recorded as a zero-event import, which would leave a custody entry
    // claiming evidence was ingested when none was.
    if (res.status() !== 400) {
      wrong.push(`${route} -> ${res.status()}`);
      continue;
    }

    // ...and the 400 must be the BLANK-payload rejection, not an "I never saw that field" one.
    // Those are different behaviours and only the first is what this test claims to check. A wrong
    // REQUIRED_FIELD entry drops the blank into a box the route never reads, so the route rejects
    // an ABSENT field, still answers 400, and the test stays green while silently checking the
    // weaker of the two — the typo is invisible. Every route names the field it wanted in the
    // message ("text is required", "path is required (…)"), so requiring the name back pins
    // REQUIRED_FIELD to what the route actually reads.
    const error = String(((await res.json()) as { error?: unknown }).error ?? "");
    if (!error.includes(required)) misnamed.push(`${route} sent ${required}, answered "${error}"`);
  }

  expect(wrong, `routes that accepted an empty payload: ${wrong.join(", ")}`).toEqual([]);
  expect(
    misnamed,
    `routes whose 400 did not name the field REQUIRED_FIELD sent — the entry is wrong, so the ` +
      `blank never reached the field being tested: ${misnamed.join("; ")}`,
  ).toEqual([]);
});
