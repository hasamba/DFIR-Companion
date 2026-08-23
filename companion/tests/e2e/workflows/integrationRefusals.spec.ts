import { test, expect } from "../fixtures/test.js";

// Covers: NO USER STORY EXISTS.
// Not US-300/US-301/US-302: those stories are the PUSH behaviors — a finding filed in Jira or
// ServiceNow with idempotent re-push, a sandbox submission polled to verdict — and this suite can
// never drive them (a configured push sends case data off-box; COVERAGE.md §4). What is pinned
// here is the boundary those stories share: what each surface does when the external system is
// NOT configured. Claiming the story ids for that would read as "the pushes are tested" when only
// their refusals are; the push logic itself is covered with mocked transports in the unit suites
// (tests/integrations/*).
//
// The refusal contract is analyst-facing behavior, not a technicality. The dashboard decides
// whether to SHOW the push controls from the status endpoints, and when a push fails the error
// message is the only thing telling the analyst which env vars to set. An empty 501 would strand
// them; a 200-shaped lie would swallow a finding they believed was filed.

test("US-300 boundary: Jira reports itself unconfigured, and a push says which variables are missing", async ({
  page,
  demoCase,
}) => {
  const status = await page.request.get("/jira/status");
  expect(status.status(), await status.text()).toBe(200);
  const body = (await status.json()) as { configured: boolean };
  // The harness has no Jira env; if this reads true, the suite's isolation has failed and every
  // later assertion is suspect.
  expect(body.configured, "the e2e harness must never see a configured Jira").toBe(false);

  const push = await page.request.post(`/cases/${demoCase}/push/jira`, {
    data: { findingId: "f001" },
  });
  expect(push.status(), await push.text()).toBe(501);
  const err = ((await push.json()) as { error?: string }).error ?? "";
  // The message must name the fix. "not configured" alone leaves the analyst grepping the manual.
  expect(err, "the refusal names the env vars to set").toContain("DFIR_JIRA_URL");
});

test("US-301 boundary: ServiceNow reports itself unconfigured, and a push refuses with the reason", async ({
  page,
  demoCase,
}) => {
  const status = await page.request.get("/servicenow/status");
  expect(status.status(), await status.text()).toBe(200);
  expect(((await status.json()) as { configured: boolean }).configured).toBe(false);

  const push = await page.request.post(`/cases/${demoCase}/push/servicenow`, {
    data: { findingId: "f001" },
  });
  expect(push.status(), await push.text()).toBe(501);
  expect(((await push.json()) as { error?: string }).error ?? "").toMatch(/servicenow|configured/i);
});

test("US-302 boundary: the SO-CRATES job list answers empty for a case rather than erroring", async ({
  page,
  demoCase,
}) => {
  // Submission itself needs a live sandbox and stays out of this suite (COVERAGE.md §4). What the
  // dashboard needs regardless is the job list: it polls this to render the sandbox panel, and an
  // error here would break the panel for every case, configured or not.
  const res = await page.request.get(`/cases/${demoCase}/socrates/jobs`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { jobs: unknown[] };
  expect(Array.isArray(body.jobs)).toBe(true);
  expect(body.jobs, "a fresh case has no sandbox jobs").toHaveLength(0);

  // And the ghost-case contract, so a stale dashboard tab cannot render an empty panel for a case
  // that no longer exists.
  const ghost = await page.request.get(`/cases/no-such-case-ever/socrates/jobs`);
  expect(ghost.status()).toBe(404);
});
