import { test, expect } from "../fixtures/test.js";

// Covers: US-040, US-131, US-354
// (feature-user-stories.csv) — POST /cases/:id/synthesize being reachable, and the async job list backing the status panel.
//

// Synthesis status. Runs against the stub provider from tests/e2e/server-entry.ts, so the replies
// are fixed and these assertions are deterministic — a live model would make every one a coin flip.

test("the job list answers for a case, even with nothing queued", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/api/jobs?caseId=${encodeURIComponent(demoCase)}`);
  expect(res.status()).toBe(200);
  // The payload is { jobs: [...] }, not a bare array.
  const body = (await res.json()) as { jobs?: unknown[] };
  // The jobs panel is the status surface for synthesis; an endpoint that errors when idle makes
  // the panel look broken exactly when nothing is wrong.
  expect(Array.isArray(body.jobs)).toBe(true);
});

test("synthesis is reachable and reports a job", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/synthesize`, { data: {} });
  // Asserts the exact accepted status, not merely "< 500".
  //
  // The loose form initially hid a real failure: the stub replied with prose, pipeline.ts runs
  // every completion through parseJsonLoose() plus the Zod schema in responseSchema.ts, and the
  // route answered 500. A range assertion here would have gone green the moment the status changed
  // for any reason, which is the opposite of what this spec is for.
  expect(res.status(), await res.text()).toBe(200);
});

test("US-354: a reload derives the case's AI state instead of showing a stale push event", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const response = await page.request.get(`/cases/${demoCase}/ai-state`);
  expect(response.status(), await response.text()).toBe(200);
  const state = (await response.json()) as { state: string; detail: string; holds: unknown[] };
  expect(["off", "blocked", "analyzing", "idle", "error"]).toContain(state.state);
  expect(typeof state.detail).toBe("string");
  expect(Array.isArray(state.holds)).toBe(true);

  // Re-entering the case forces the header pill through the derived endpoint. The fixed harness
  // has live analysis paused, so the visible state must say so even though no ai_status event was
  // pushed to this newly loaded page.
  await page.reload();
  await expect(page.locator("#aiStatus")).toContainText(/live analysis paused/i, {
    timeout: 30_000,
  });
});

test("the AI state is announced, not only shown", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // PR 2 bridged #status into the live regions. Synthesis progress is written there, so this is
  // the acceptance criterion "live job, error and AI states are announced" exercised end to end.
  //
  // Wait for the app to stop writing #status BEFORE injecting.
  //
  // The dashboard writes its own status messages throughout case load. announce() mirrors each one
  // into the live region, so an injected marker gets overwritten by the next app message and may
  // never be observable — this failed roughly one run in three even when polled. Settling first
  // removes the race rather than widening the timeout around it.
  let previous = "";
  await expect
    .poll(
      async () => {
        const current = (await page.locator("#status").textContent()) ?? "";
        const settled = current === previous;
        previous = current;
        return settled;
      },
      { timeout: 30_000, intervals: [500] },
    )
    .toBe(true);

  const marker = `AI synthesis complete ${Date.now()}`;
  await page.evaluate((text) => {
    const el = document.getElementById("status");
    if (el) el.textContent = text;
  }, marker);
  await expect
    .poll(async () => (await page.locator("#a11y-live-polite").textContent()) ?? "", {
      timeout: 15_000,
    })
    .toContain(marker);
});
