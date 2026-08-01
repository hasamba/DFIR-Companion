import { readZip } from "../../../src/analysis/zipArchive.js";
import { test, expect } from "../fixtures/test.js";

// Covers: US-086, US-087, US-089, US-128, US-205
// (feature-user-stories.csv) — the export surfaces: STIX bundle, IOC blocklist, the redacted ZIP
// and its hashed manifest, and the password-encrypted case export.
//
// US-088 (JSON snapshot) is NOT claimed, and should probably leave the inventory: its own
// expected_behaviour says "Superseded (issue #56) — the JSON-snapshot export/import was replaced
// by the password-encrypted .dfircase". There is no endpoint to test. It is listed here so the
// empty browser_test column is a decision rather than an oversight.
//
// A BUG FOUND WHILE WRITING THIS, since fixed (PR #432). POST /cases/:id/export/encrypted answered
// 500 for a case created by POST /cases/seed-demo — 3 attempts out of 3 — while a case created
// through POST /cases exported fine. The cause was not the archive walker it first looked like: the
// demo case is named "GlobalTech Industries — BEC & Ransomware Precursor", and Node throws
// ERR_INVALID_CHAR for that em dash in a header VALUE, so the archive built in full and the request
// then died setting Content-Disposition. Any case name outside Latin-1 hit it; the demo case just
// made it reproducible on demand. The export now sends an RFC 6266 filename*, so the
// encrypted-export test below uses the seeded fixture — exporting the demo case IS the regression
// test, and a case created by the test itself would step around the defect that was here.
//
// These are the artifacts that leave the building — handed to a client, a court, or another team —
// so the assertions are about CONTENT, not status codes. An export that returns 200 and a ZIP
// containing nothing useful is the failure that matters.

test("US-086: the STIX export is a well-formed bundle", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/export/stix`);
  expect(res.status(), await res.text()).toBe(200);
  const bundle = (await res.json()) as { type: string; id: string; objects: unknown[] };

  // A consumer (MISP, OpenCTI, a SIEM) rejects anything that is not a real bundle, so the envelope
  // is load-bearing rather than cosmetic.
  expect(bundle.type).toBe("bundle");
  expect(bundle.id, "STIX ids are prefixed by type").toMatch(/^bundle--/);
  expect(bundle.objects.length, "the seeded case has 17 IOCs to export").toBeGreaterThan(0);
});

test("US-087: the IOC blocklist names the case it came from", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/export/ioc-blocklist`);
  expect(res.status(), await res.text()).toBe(200);
  const text = await res.text();

  // This gets pasted into a firewall or proxy. It has to say which case produced it, or nobody can
  // tell later why an address was blocked — or when it is safe to unblock.
  expect(text, "the blocklist is attributable to its case").toMatch(/# Case:/);
  expect(text.split("\n").length, "a blocklist with no entries is not worth exporting").toBeGreaterThan(3);
});

test("US-089, US-205: the redacted ZIP carries a manifest hashing every file it contains", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/export/redacted`);
  expect(res.status(), await res.text()).toBe(200);
  expect(res.headers()["content-type"]).toContain("zip");

  // readZip is the project's own reader (src/analysis/zipArchive.ts), the counterpart to the
  // createZip that built this archive — so the test needs no new dependency and reads the ZIP the
  // same way the product does.
  const entries = readZip(await res.body());
  const names = entries.map((e) => e.path);

  // The report is the point of the export; the redaction notes are what tells the recipient what
  // was removed, which is the difference between a redacted document and a censored one.
  expect(names).toContain("REDACTION-NOTES.txt");
  expect(names).toContain("export-manifest.json");
  expect(
    names.some((n) => n.startsWith("report/")),
    "the report itself",
  ).toBe(true);

  const manifestEntry = entries.find((e) => e.path === "export-manifest.json");
  const manifest = JSON.parse(String(manifestEntry?.data)) as {
    caseId: string;
    files: Array<{ path: string; sha256: string; bytes: number }>;
    totalFiles: number;
  };

  expect(manifest.caseId).toBe(demoCase);
  expect(manifest.files.length, "the manifest lists what was exported").toBeGreaterThan(0);
  expect(manifest.totalFiles).toBe(manifest.files.length);

  // EVERY file must be hashed, and the hash must be a real SHA-256. This is what lets a recipient
  // prove the copy they hold is the copy that was sent — an entry with a blank or short digest
  // would look like integrity coverage while providing none.
  for (const file of manifest.files) {
    expect(file.sha256, `${file.path} has no digest`).toMatch(/^[0-9a-f]{64}$/);
    expect(file.bytes, `${file.path} has no size`).toBeGreaterThanOrEqual(0);
  }

  // ...and the manifest must describe the ZIP it actually shipped in, not some other export. A
  // manifest naming files that are absent is worse than none: it reads as proof of what is there.
  const zipped = new Set(names);
  for (const file of manifest.files) {
    expect(zipped.has(file.path), `manifest lists ${file.path}, which is not in the ZIP`).toBe(true);
  }
});

test("US-128: the encrypted export demands a real password", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // No password at all.
  const none = await page.request.post(`/cases/${demoCase}/export/encrypted`, { data: {} });
  expect(none.status(), await none.text()).toBe(400);

  // A short one. The refusal must name the requirement — an encrypted case file is only as good as
  // the passphrase on it, and silently accepting "abc" would produce a file that looks protected.
  const weak = await page.request.post(`/cases/${demoCase}/export/encrypted`, {
    data: { password: "abc" },
  });
  expect(weak.status(), await weak.text()).toBe(400);
  expect(await weak.text()).toMatch(/8 characters/);
});

test("US-128: a password-protected export produces a non-empty encrypted file", async ({
  page,
  demoCase,
}) => {
  const caseId = demoCase;
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);

  // removeFromList is deliberately NOT set. It takes the case out of the active list, and the
  // export is a copy rather than a move unless explicitly asked.
  const res = await page.request.post(`/cases/${caseId}/export/encrypted`, {
    data: { password: "e2e-correct-horse-battery" },
  });
  expect(res.status(), await res.text()).toBe(200);

  // The seeded case name carries an em dash, which is what broke this endpoint (see the note at the
  // top of the file). A 200 alone would not catch a regression that mangles the name instead.
  expect(res.headers()["content-disposition"], "the analyst's case name must survive the download").toContain(
    "filename*=UTF-8''",
  );

  const body = await res.body();
  expect(body.byteLength, "an encrypted case export with no bytes").toBeGreaterThan(0);

  // AES-256-GCM ciphertext must not read as its plaintext. Finding the case id in the output would
  // mean the archive is not actually encrypted.
  expect(body.toString("utf8").includes(caseId), "case id found in the ciphertext").toBe(false);

  // Still listed: this is a copy, not a move.
  const listed = await page.request.get("/cases");
  expect(await listed.text()).toContain(caseId);
});
