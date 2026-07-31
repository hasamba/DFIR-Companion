import { test, expect } from "../fixtures/test.js";

// Covers: US-014
// (feature-user-stories.csv) — POST /cases/:id/import-csv accepting a CSV and refusing malformed input.
//

// Evidence import. The CSV route refuses to run without a synthesis provider (501), so a passing
// 200 here is also the proof that the stub provider in tests/e2e/server-entry.ts is wired.

const CSV = [
  "timestamp,host,user,event",
  "2026-05-18T02:30:00Z,FS01,jsmith,File staged for exfiltration",
  "2026-05-18T02:31:00Z,FS01,jsmith,Archive created",
].join("\n");

test("imports a CSV and records it against the case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/import-csv`, {
    data: { csv: CSV, filename: "e2e.csv" },
  });
  // 202, not 200: the route accepts the CSV and analyses it asynchronously.
  //
  // 501 here would mean the stub provider is not configured — see tests/e2e/server-entry.ts.
  // Asserting the success status rather than tolerating 501 is what keeps a broken stub from
  // silently skipping this path.
  expect(res.status(), await res.text()).toBe(202);
  const body = (await res.json()) as { accepted?: boolean; rows?: number };
  expect(body.accepted).toBe(true);
  expect(body.rows).toBe(2);
});

test("refuses an empty CSV", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const res = await page.request.post(`/cases/${demoCase}/import-csv`, {
    data: { csv: "   ", filename: "empty.csv" },
  });
  expect(res.status()).toBe(400);
});

test("refuses a CSV with a header but no data rows", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const res = await page.request.post(`/cases/${demoCase}/import-csv`, {
    data: { csv: "timestamp,host,user,event", filename: "headeronly.csv" },
  });
  // Accepting this would append an import record claiming zero events — an audit trail entry for
  // something that never happened.
  expect(res.status()).toBe(400);
});

// Importing into a case id that does not exist used to be ACCEPTED (202): the server created the
// case directory on the spot and wrote the evidence, an imports.jsonl entry and a custody.jsonl
// entry into it — but the case never appeared in GET /cases, so the investigator could not see it.
// A typo in a case id silently swallowed an evidence import into an orphaned directory.
//
// registerImportCaseGuard (companion/src/routes/importCaseGuard.ts, #403) now 404s an unknown case
// ahead of all 24 /cases/:id/import* routes, matching GET /cases/:id/custody. This asserted 202 as
// a characterization test until that landed; it is flipped, not re-baselined.
test("an import for a non-existent case is rejected, not orphaned", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const ghost = "no-such-case-e2e";
  const res = await page.request.post(`/cases/${ghost}/import-csv`, {
    data: { csv: CSV, filename: "e2e.csv" },
  });

  expect(res.status(), await res.text()).toBe(404);

  // The case must not have been conjured as a side effect of the rejected import.
  const listed = await page.request.get("/cases");
  expect(await listed.text()).not.toContain(ghost);
});
