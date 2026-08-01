import { test, expect } from "../fixtures/test.js";

// Covers: US-009, US-011, US-012, US-148
// (feature-user-stories.csv) — the SERVER side of screenshot capture: accepting a capture from the
// extension, the recent-captures feed, the per-case count, and OCR search over captured content.
//
// THE OTHER EIGHT CAPTURE STORIES ARE NOT GAPS. US-010, US-162, US-163, US-164, US-165, US-166,
// US-167 and US-169 live inside the browser extension — the page hook, the IndexedDB offline
// queue, the adapter auto-detection, the draggable button, the popup and the toolbar badge. None
// of it is reachable from a Playwright run against the dashboard; covering it would mean a second
// harness that launches Chromium with the unpacked add-on loaded.
//
// They are already tested, by the extension's own suite in the `extension` CI job:
//
//   US-010  extension/tests/captureController.test.ts
//   US-162  extension/tests/adapters.test.ts
//   US-163  extension/tests/override.test.ts
//   US-165  extension/tests/captureQueue.test.ts, captureQueuePermanentFailure.test.ts
//   US-166  extension/tests/buttonPosition.test.ts
//   US-167  extension/tests/companionClient.test.ts
//   US-169  extension/tests/manifest.test.ts, settings.test.ts
//
// So the browser_test column being empty for those rows means "not covered by THIS suite", not
// "untested". Recorded here so the gap is not re-investigated later.

/** The payload shape the extension actually posts — extension/src/types.ts, CapturePayload. */
function capturePayload(caseId: string, overrides: Record<string, unknown> = {}) {
  return {
    caseId,
    timestamp: "2026-05-16T09:00:00.000Z",
    url: "https://console.example.internal/alerts/8821",
    tabTitle: "Alert 8821 — suspicious PowerShell",
    // One of timer | navigation | tab_switch | click — the enum the extension sends.
    triggerType: "click",
    // A 1x1 PNG. The bytes matter only in that the server must store something it can serve back.
    imageBase64:
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    ...overrides,
  };
}

test("US-009: a capture from the extension is stored and counted", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const before = await page.request.get(`/cases/${demoCase}/captures/count`);
  const beforeCount = Number(((await before.json()) as { count: number }).count);

  const res = await page.request.post("/captures", { data: capturePayload(demoCase) });
  // 201 Created is what the extension's client checks for; anything else makes it queue the
  // capture for retry, so the status is part of the contract rather than incidental.
  expect(res.status(), await res.text()).toBe(201);

  const after = await page.request.get(`/cases/${demoCase}/captures/count`);
  expect(Number(((await after.json()) as { count: number }).count)).toBe(beforeCount + 1);
});

test("US-009: a capture for an unknown case is refused", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The same class of bug the import guard fixed in #403: a typo'd case id must not conjure a
  // directory that the investigator will never see in GET /cases.
  const res = await page.request.post("/captures", {
    data: capturePayload("no-such-case-capture"),
  });
  expect([400, 404], await res.text()).toContain(res.status());

  const listed = await page.request.get("/cases");
  expect(await listed.text()).not.toContain("no-such-case-capture");
});

test("US-009: a capture with a malformed payload is refused", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Missing the image entirely. A capture record with no screenshot is an evidence entry that
  // cannot be reviewed, which is worse than a rejected upload the extension will retry.
  const res = await page.request.post("/captures", {
    data: { caseId: demoCase, timestamp: "2026-05-16T09:00:00.000Z", url: "https://x.example" },
  });
  expect(res.status()).toBe(400);
});

test("US-012: the per-case capture count reflects what was stored", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  for (let i = 0; i < 3; i++) {
    const res = await page.request.post("/captures", {
      data: capturePayload(demoCase, { tabTitle: `Alert ${i}`, timestamp: `2026-05-16T09:0${i}:00.000Z` }),
    });
    expect(res.status()).toBe(201);
  }

  const count = await page.request.get(`/cases/${demoCase}/captures/count`);
  expect(count.status()).toBe(200);
  expect(Number(((await count.json()) as { count: number }).count)).toBeGreaterThanOrEqual(3);
});

test("US-011: the recent-captures feed reports which case last captured, and how long ago", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // /captures/recent is GLOBAL — it reports the most recent capture across every case, not this
  // one. With the suite running four workers, another spec's capture can land between the POST and
  // the GET, so a single post-then-read asserted exclusivity this endpoint never promised. That is
  // what made this fail once the suite grew past ~200 specs.
  //
  // Re-posting inside the poll keeps the claim honest: this case's capture must be able to reach
  // the head of the feed, rather than merely being there on the first look.
  await expect
    .poll(
      async () => {
        const post = await page.request.post("/captures", { data: capturePayload(demoCase) });
        expect(post.status()).toBe(201);
        const recent = await page.request.get("/captures/recent");
        if (!recent.ok()) return "";
        return ((await recent.json()) as { caseId?: string }).caseId ?? "";
      },
      { timeout: 20_000, intervals: [300] },
    )
    .toBe(demoCase);

  // NOT a list of captures despite the story's wording — it is a liveness summary: the case that
  // captured most recently and how stale that is. That is what the dashboard's "extension is
  // attached to case X" indicator reads, so the two fields are the whole contract.
  const body = (await (await page.request.get("/captures/recent")).json()) as { ageMs?: number };
  expect(typeof body.ageMs, "how stale the last capture is").toBe("number");
  // Seconds old, not hours: a stale age here would make the indicator claim the extension is idle.
  expect(body.ageMs).toBeLessThan(120_000);
});

test("US-148: OCR search requires a query and answers one", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // An empty query would otherwise return the whole index, which reads as "everything matched".
  const empty = await page.request.get(`/cases/${demoCase}/ocr-search?q=`);
  expect(empty.status()).toBe(400);

  const res = await page.request.get(`/cases/${demoCase}/ocr-search?q=powershell`);
  // 501 is legitimate: OCR indexing is off by default in this harness (DFIR_OCR_SEARCH=off in the
  // vitest config for the same reason — real OCR downloads language data over the network).
  expect([200, 501], await res.text()).toContain(res.status());
});
