import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext, Page } from "@playwright/test";

// Covers: US-041, US-044, US-050, US-096, US-129, US-192, US-208
// (feature-user-stories.csv) — analyst-triggered actions: second opinion, explain event, memory
// next steps, notification channels, encrypted case import, hypothesis review, and playbook task
// dependencies.
//
// POST /notifications/test IS NEVER CALLED. /notifications/status reports emailEnabled:true in
// this harness, and a "test notification" is a real message to a real channel. Sending one from a
// test suite is the same class of mistake as pushing case data to a live MISP — see
// integrations.spec.ts. The channel CRUD and status are testable without it.

async function enableAi(request: APIRequestContext, caseId: string): Promise<void> {
  const res = await request.post(`/cases/${caseId}/ai-control`, { data: { enabled: true } });
  expect(res.status(), await res.text()).toBe(200);
}

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
}

test("US-044: explaining an event returns the provider's rationale", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await enableAi(page.request, demoCase);

  const res = await page.request.post(`/cases/${demoCase}/events/e001/explain`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { summary: string };

  // One of the few AI routes whose reply survives as prose, so this is a genuine end-to-end check
  // of the provider call rather than an envelope assertion: the stub's text must come back out.
  expect(body.summary, "the provider's reply must reach the explanation").toContain("Stubbed");
});

test("US-041: second opinion lists and runs against a different model", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await enableAi(page.request, demoCase);

  // Nothing recorded yet — the panel must handle that rather than erroring.
  const listed = await page.request.get(`/cases/${demoCase}/second-opinion`);
  expect(listed.status(), await listed.text()).toBe(200);

  const run = await page.request.post(`/cases/${demoCase}/second-opinion`, { data: {} });
  // 200/202 when it runs, 501 when no second model is configured. Both are honest answers; a 500
  // would not be.
  expect([200, 202, 501], await run.text()).toContain(run.status());
});

test("US-050: memory next steps answers even with no memory evidence", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await enableAi(page.request, demoCase);

  const res = await page.request.post(`/cases/${demoCase}/memory/next-steps`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { suggestions: unknown[] };

  // Empty is correct for the seeded case, which has no memory image imported. The envelope is what
  // the panel binds to — a null here would break its render rather than showing "nothing to suggest".
  expect(Array.isArray(body.suggestions)).toBe(true);
});

test("US-192: hypothesis review returns advisory reviews tied to evidence", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await enableAi(page.request, demoCase);

  const res = await page.request.post(`/cases/${demoCase}/hypothesis-review`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { reviews: unknown[] };

  // Advisory, and bounded: the story's point is that reviews are tied to REAL evidence rather than
  // invented. Against the fixed-prose stub nothing is produced, so the envelope is the claim.
  expect(Array.isArray(body.reviews)).toBe(true);
});

test("US-096: notification channels list and validate", async ({ page }) => {
  await page.goto("/dashboard");

  const listed = await page.request.get("/notifications");
  expect(listed.status(), await listed.text()).toBe(200);
  expect(Array.isArray(await listed.json())).toBe(true);

  const status = await page.request.get("/notifications/status");
  expect(status.status(), await status.text()).toBe(200);
  // The settings panel renders per-channel state from this, so it needs to report configuration
  // rather than error when nothing is set up.
  expect((await status.json()) as Record<string, unknown>).toHaveProperty("configured");

  // A channel with no definition cannot deliver anything; storing it would put a silently broken
  // destination in the operator's list.
  const empty = await page.request.post("/notifications", { data: {} });
  expect(empty.status(), await empty.text()).toBe(400);
});

test("US-129: encrypted case import validates its payload", async ({ page }) => {
  await page.goto("/dashboard");

  const none = await page.request.post("/cases/import/encrypted", { data: {} });
  expect(none.status(), await none.text()).toBe(400);
  expect(await none.text()).toMatch(/data \(base64\) is required/);

  // Wrong password against real-looking data must fail as a decryption error, not a crash — this
  // is the route that receives a colleague's .dfircase file.
  const garbage = await page.request.post("/cases/import/encrypted", {
    data: { data: Buffer.from("not a dfircase").toString("base64"), password: "wrong-password" },
  });
  expect(garbage.status(), await garbage.text()).toBeGreaterThanOrEqual(400);
  expect(garbage.status(), "a malformed archive must not 500").toBeLessThan(500);
});

test("US-208: playbook tasks carry ids and dependency edges", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const res = await page.request.get(`/cases/${demoCase}/playbook`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    tasks: Array<{ id: string; shortId: string; title: string; dependsOn?: string[] }>;
  };

  expect(body.tasks.length, "the seeded case's next steps become tasks").toBeGreaterThan(0);
  for (const task of body.tasks) {
    // shortId is what the analyst types to reference a task ("T001"), so it has to exist and be
    // distinct from the internal id.
    expect(task.id, "a task with no id").toBeTruthy();
    expect(task.shortId, `task ${task.id} has no short id`).toBeTruthy();
    expect(task.title, `task ${task.id} has no title`).toBeTruthy();
  }

  // A dependency on a task that does not exist would leave the graph unsatisfiable — the task
  // could never become ready.
  const ids = new Set(body.tasks.map((t) => t.id));
  for (const task of body.tasks) {
    for (const dep of task.dependsOn ?? []) {
      expect(ids.has(dep), `task ${task.id} depends on unknown task ${dep}`).toBe(true);
    }
  }
});
