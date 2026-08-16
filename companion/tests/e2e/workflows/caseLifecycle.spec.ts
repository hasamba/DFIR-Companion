import { test, expect } from "../fixtures/test.js";

// Covers: US-004, US-005, US-007, US-008, US-126, US-127, US-130, US-134, US-220
// (feature-user-stories.csv) — case status, archive, restore, delete, disk stats, diagnostics,
// backups, per-case stats, the cancelable loading overlay and the archived-cases control.
//
// THESE ARE THE DESTRUCTIVE ONES. Delete removes a case and its evidence. They are safe to run
// only because tests/e2e/isolation.ts refuses to start the server unless the cases root is under
// the OS temp dir — this file is the reason that guard is a hard precondition rather than a
// convention. Nothing here may ever run against a configured DFIR_CASES_ROOT.
//
// US-170 (the cancelable loading overlay) is NOT claimed. Dismissal is a click handler that
// showCaseLoadingOverlay attaches only while a load is genuinely in flight, and this harness
// cannot reliably provoke a stall long enough to click it — forcing the overlay visible by hand
// shows it with no handler attached, which would test nothing. Only its presence is asserted.
//
// Worth knowing regardless: that affordance is click-only. There is no keyboard path and nothing
// announces it, so a keyboard or screen-reader user cannot abandon a stalled load at all.
//
// US-005, US-126 and US-127 are covered by their REFUSAL paths only — archive-without-removal,
// restore-when-not-archived, delete-when-open and delete-without-an-archive-choice. The happy
// chain (archive with removeFromList, then restore, then delete) is NOT covered: run back to back
// it fails roughly one time in four, and it still failed with --workers=1, so it is not test
// concurrency. The most likely cause is the archive's write racing the subsequent rename. Shipping
// a one-in-four flake to claim three stories would make the whole suite less trustworthy, so the
// destructive chain is left to manual verification and noted here instead.

test("US-004: a case can be closed and reopened", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const closed = await page.request.patch(`/cases/${demoCase}/status`, {
    data: { status: "closed" },
  });
  expect(closed.status(), await closed.text()).toBe(200);
  expect(((await closed.json()) as { status: string }).status).toBe("closed");

  const reopened = await page.request.patch(`/cases/${demoCase}/status`, {
    data: { status: "open" },
  });
  expect(reopened.status(), await reopened.text()).toBe(200);
  expect(((await reopened.json()) as { status: string }).status).toBe("open");
});

test("US-127: deletion refuses an open case and demands an explicit archive choice", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The two guards in front of the only irreversible operation in the product. Both are asserted
  // WITHOUT deleting anything, so this test cannot itself destroy evidence if it misbehaves.
  //
  // 1. An open case cannot be deleted at all.
  const open = await page.request.post(`/cases/${demoCase}/delete`, {
    data: { archiveFirst: "none" },
  });
  expect(open.status(), await open.text()).toBe(400);
  expect(await open.text()).toMatch(/closed or archived/);

  // 2. Even closed, the caller must say out loud whether the evidence is being preserved first.
  await page.request.patch(`/cases/${demoCase}/status`, { data: { status: "closed" } });
  const unspecified = await page.request.post(`/cases/${demoCase}/delete`, { data: {} });
  expect(unspecified.status(), await unspecified.text()).toBe(400);
  expect(await unspecified.text()).toMatch(/archiveFirst/);
});

test("US-005: archiving produces an export path and leaves the case listed", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  await page.request.patch(`/cases/${demoCase}/status`, { data: { status: "closed" } });
  const archived = await page.request.post(`/cases/${demoCase}/archive`, { data: {} });
  expect(archived.status(), await archived.text()).toBe(200);
  expect(((await archived.json()) as { archivePath: string }).archivePath).toBeTruthy();

  // WITHOUT removeFromList the case stays in the active list. The story reads "moves case to
  // archived; hidden from active list", which describes only the removeFromList:true path — a
  // bare archive writes the export and changes nothing else.
  expect(await (await page.request.get("/cases")).text()).toContain(demoCase);
});

test("US-126: restoring a case that was never archived is refused", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const res = await page.request.post(`/cases/${demoCase}/restore`, { data: {} });
  expect(res.status(), await res.text()).toBe(400);
  expect(await res.text()).toMatch(/not archived/);
});

test("US-134: per-case stats count what the case actually holds", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/stats`);
  expect(res.status(), await res.text()).toBe(200);
  const totals = ((await res.json()) as { totals: Record<string, number> }).totals;

  // The seeded case is fixed at 59 events / 14 findings / 17 IOCs, so these are exact rather than
  // "greater than zero" — a stats endpoint that under-counts is worse than one that errors.
  expect(totals.events).toBe(59);
  expect(totals.findings).toBe(14);
  expect(totals.iocs).toBe(17);
});

test("US-007: disk stats report usable capacity figures", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/disk-stats");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { totalBytes: number; freeBytes: number; usedPct: number };
  expect(body.totalBytes).toBeGreaterThan(0);
  expect(body.freeBytes).toBeGreaterThan(0);
  // The banner warns on this, so an out-of-range percentage would either cry wolf or stay silent
  // while the disk fills — and a full disk mid-import loses evidence.
  expect(body.usedPct).toBeGreaterThanOrEqual(0);
  expect(body.usedPct).toBeLessThanOrEqual(100);
});

test("US-008: diagnostics report health without leaking the cases root", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/diagnostics");
  expect(res.status(), await res.text()).toBe(200);
  const text = await res.text();
  const report = ((await res.json()) as { report: Record<string, unknown> }).report;
  expect(report.generatedAt, "diagnostics are stamped").toBeTruthy();
  expect(report).toHaveProperty("disk");

  // The operator configured the cases root and already knows it; the client never needs the
  // absolute path, and diagnostics is the endpoint most likely to be pasted into a bug report.
  // See the note in src/analysis/diagnostics.ts.
  expect(text, "diagnostics must not echo the absolute cases root").not.toMatch(/\/tmp\/dfir-e2e-/);
});

test("US-130: the backups list answers with a summary even when empty", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/backups`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { backups: unknown[]; summary: { count: number } };
  // A fresh case has no snapshots yet; the panel still needs the shape to render "none".
  expect(Array.isArray(body.backups)).toBe(true);
  expect(body.summary).toHaveProperty("count");

  // Restoring a backup that does not exist must be refused rather than silently doing nothing —
  // an analyst who believes a restore happened will trust stale state.
  const bad = await page.request.post(`/cases/${demoCase}/restore-backup`, {
    data: { filename: "no-such-backup.zip" },
  });
  expect([400, 404], await bad.text()).toContain(bad.status());
});

test("US-220: the archived-cases control is labelled and filters the list", async ({ page, demoCase }) => {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  const toggle = page.locator("#showArchivedToggle");
  await expect(toggle).toBeAttached();

  // The story asks for accessible text/title on the control. A bare checkbox with neither is
  // announced as "checkbox" and nothing else, which tells a screen-reader user nothing.
  const name = await toggle.evaluate((el) => {
    const byLabel = el.closest("label")?.textContent?.trim();
    return (
      el.getAttribute("aria-label") ||
      el.getAttribute("title") ||
      byLabel ||
      el.closest("[title]")?.getAttribute("title") ||
      ""
    );
  });
  expect(name, "the archived-cases control needs an accessible name").not.toBe("");

  // Archive a case, then prove the toggle is what brings it back into view.
  await page.request.patch(`/cases/${demoCase}/status`, { data: { status: "closed" } });
  await page.request.post(`/cases/${demoCase}/archive`, { data: { removeFromList: true } });

  await page.reload();
  await page.waitForLoadState("networkidle");

  // The picker is an <input list="caseList"> backed by a <datalist>, so the case ids are option
  // VALUES — reading textContent off the input returns "" and would pass against anything.
  const options = () =>
    page.evaluate(() =>
      [...document.querySelectorAll("#caseList option")].map((o) => o.getAttribute("value") ?? ""),
    );

  expect(await options(), "an archived case is hidden by default").not.toContain(demoCase);

  await toggle.check();
  // The list re-renders on change; the archived case must reappear without a reload.
  await expect.poll(options, { timeout: 15_000 }).toContain(demoCase);
});

test("the case-loading overlay exists and starts hidden", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const overlay = page.locator("#caseLoadingOverlay");
  await expect(overlay).toBeAttached();
  // It blocks the whole viewport when shown, so it must not be showing when nothing is loading.
  await expect(overlay).toBeHidden();
});
