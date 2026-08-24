import { test, expect } from "../fixtures/test.js";

// Covers: US-276, US-277
// (feature-user-stories.csv) — chain-of-custody logging and the signed custody manifest with
// verification. This file predates both rows: it originally said "the csv has no chain-of-custody
// entry at all" and stayed unmapped on purpose. US-276/US-277 were added to the inventory later,
// so the claim moved here once the tests below actually earned it — the original three tests
// asserted the surface answered, which covers neither story on its own.
//

// Chain of custody. This is the court-facing part of the product: a report whose evidence
// provenance cannot be checked is worthless, so these assert the records actually exist and carry
// integrity data rather than that the endpoint merely answers.

test("a seeded case exposes custody records", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/custody`);
  // 501 means the custody store was not wired into the app under test — that would make every
  // other assertion here vacuous, so it must fail loudly rather than skip.
  expect(res.status(), await res.text()).toBe(200);

  const body = (await res.json()) as { records?: unknown[] };
  expect(Array.isArray(body.records)).toBe(true);
});

test("custody rejects an unknown case rather than inventing an empty chain", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get("/cases/no-such-case-e2e/custody");
  // An empty 200 here would read as "this case has no custody records" for a case that does not
  // exist — the kind of answer that is worse than an error in an evidentiary tool.
  expect(res.status()).toBe(404);
});

test("the custody panel renders for a seeded case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  // The section exists in the page and is named as a region by the landmark wiring from PR 2.
  await expect(page.locator("#sec-custody")).toHaveAttribute("aria-label", /custody/i);
});

test("US-276: importing evidence writes a custody record with hash, actor and time", async ({
  page,
  demoCase,
}) => {
  // The chain starts at the import boundary, so the test does too.
  const imported = await page.request.post(`/cases/${demoCase}/import`, {
    data: {
      filename: "custody-probe.jsonl",
      text: JSON.stringify({
        time: "2026-06-01T09:00:00Z",
        hostname: "CUSTODY-PROBE",
        level: "Warning",
        module: "Filescan",
        message: "custody probe artifact",
        file: "C:\\Temp\\custody-probe.ps1",
        reason_1: "YARA rule SUSP_PS1",
      }),
    },
  });
  expect(imported.status(), await imported.text()).toBe(202);

  // The record is written by the import pipeline, so poll rather than trust the 202.
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/custody`);
        const body = (await res.json()) as { records?: Array<{ artifactPath?: string }> };
        return (body.records ?? []).some((r) => (r.artifactPath ?? "").includes("custody-probe"));
      },
      { timeout: 15_000 },
    )
    .toBe(true);

  const res = await page.request.get(`/cases/${demoCase}/custody`);
  const { records } = (await res.json()) as {
    records: Array<{ artifactPath?: string; sha256?: string; collectedBy?: string; collectedAt?: string }>;
  };
  const record = records.find((r) => (r.artifactPath ?? "").includes("custody-probe"));
  // Who, when, and the hash — the three fields a court asks about. A record missing any of them
  // is a log line, not custody.
  expect(record?.sha256 ?? "", "the artifact must be content-hashed").toMatch(/^[0-9a-f]{64}$/);
  expect(record?.collectedBy ?? "", "the record must name who brought the evidence in").not.toBe("");
  expect(Date.parse(record?.collectedAt ?? ""), "the record must be timestamped").not.toBeNaN();
});

test("US-277: the custody manifest is signed and the case verifies against it", async ({
  page,
  demoCase,
}) => {
  // Give the manifest something to attest — an empty manifest verifies trivially and proves
  // nothing about artifact hashing.
  const imported = await page.request.post(`/cases/${demoCase}/import`, {
    data: {
      filename: "manifest-probe.jsonl",
      text: JSON.stringify({
        time: "2026-06-01T09:30:00Z",
        hostname: "MANIFEST-PROBE",
        level: "Alert",
        module: "ProcessCheck",
        message: "manifest probe artifact",
        process_name: "manifest-probe.exe",
        reason_1: "YARA rule Powerkatz_DLL",
      }),
    },
  });
  expect(imported.status(), await imported.text()).toBe(202);
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/custody/manifest`);
        const body = (await res.json()) as { artifacts?: unknown[] };
        return (body.artifacts ?? []).length;
      },
      { timeout: 15_000 },
    )
    .toBeGreaterThan(0);

  const manifest = await page.request.get(`/cases/${demoCase}/custody/manifest`);
  expect(manifest.status(), await manifest.text()).toBe(200);
  const doc = (await manifest.json()) as {
    caseId: string;
    signature: { algorithm: string; value: string };
    artifacts: unknown[];
  };
  expect(doc.caseId).toBe(demoCase);
  // Unsigned, the manifest is a text file anyone could edit — the signature is what makes
  // "verify later" mean anything.
  expect(doc.signature.algorithm).toBe("HMAC-SHA256");
  expect(doc.signature.value).toMatch(/^[0-9a-f]{16,}$/);

  // And the untampered case must verify clean against its own chain: ok with zero mismatches.
  // (Provoking a tamper means writing into the server's cases root from outside, which this
  // suite cannot do by design — the detection arm is unit-covered in the custody suites.)
  const verify = await page.request.get(`/cases/${demoCase}/custody/verify`);
  expect(verify.status(), await verify.text()).toBe(200);
  const verdict = (await verify.json()) as { ok: boolean; mismatches: unknown[]; chainBreaks: unknown[] };
  expect(verdict.ok, "an untampered case must verify clean").toBe(true);
  expect(verdict.mismatches).toHaveLength(0);
  expect(verdict.chainBreaks).toHaveLength(0);
});
