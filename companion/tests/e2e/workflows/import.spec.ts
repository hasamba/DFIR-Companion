import { test, expect } from "../fixtures/test.js";

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

// ---------------------------------------------------------------------------------------------
// CHARACTERIZATION TEST — DOCUMENTS A DEFECT, DOES NOT ENDORSE IT.
//
// Importing into a case id that does not exist is ACCEPTED (202). The server creates the case
// directory on the spot and writes the evidence, an imports.jsonl entry and a custody.jsonl entry
// into it — but the case never appears in GET /cases, so the investigator cannot see it. A typo in
// a case id therefore swallows an evidence import into an orphaned directory, silently.
//
// None of the ten import routes (import, import-file, import-csv, import-log, import-thor,
// import-siem, import-chainsaw, import-hayabusa, import-velociraptor, import-network) check
// store.caseExists(), while GET /cases/:id/custody does and correctly answers 404.
//
// This asserts what the server ACTUALLY does today so the suite tells the truth. When the routes
// are fixed to reject an unknown case, this test will fail — that failure is the signal to flip it
// to the 404 assertion below, not to re-baseline it.
// ---------------------------------------------------------------------------------------------
test("KNOWN DEFECT: an import for a non-existent case is accepted and orphaned", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const ghost = "no-such-case-e2e";
  const res = await page.request.post(`/cases/${ghost}/import-csv`, {
    data: { csv: CSV, filename: "e2e.csv" },
  });

  // Desired behavior is 404, as GET /cases/:id/custody already does.
  expect(res.status()).toBe(202);

  // And the damage: the case is not listed, so the evidence just written is invisible.
  const listed = await page.request.get("/cases");
  expect(await listed.text()).not.toContain(ghost);
});
