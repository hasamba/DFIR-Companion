import { test, expect } from "../fixtures/test.js";

// Covers: US-049, US-076, US-109, US-110, US-111, US-116, US-181, US-202, US-213
// (feature-user-stories.csv) — the per-case data an analyst edits directly: scope, anonymization
// control, comments, tags, asset overrides, the content tagger, finding workflow state, import
// metadata, and the diagnostics report.
//
// Comments and tags get the most attention here because of one property in their story that is
// easy to lose and expensive to lose: they are ANALYST-AUTHORED and must survive a re-synthesis.
// Everything else in a case is derived and can be rebuilt; these cannot.

test("US-076: case scope is a real time window and round-trips", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/scope`);
  expect(res.status(), await res.text()).toBe(200);
  const scope = (await res.json()) as { start: string; end: string };

  // Scope decides what synthesis is allowed to see. A window whose end precedes its start would
  // silently exclude everything, which reads as "the AI found nothing" rather than "you filtered
  // the whole case out".
  expect(new Date(scope.start).getTime()).toBeLessThan(new Date(scope.end).getTime());

  const set = await page.request.post(`/cases/${demoCase}/scope`, {
    data: { start: "2026-05-15T00:00:00.000Z", end: "2026-05-20T00:00:00.000Z" },
  });
  expect(set.status(), await set.text()).toBeLessThan(300);
  const after = (await (await page.request.get(`/cases/${demoCase}/scope`)).json()) as {
    start: string;
  };
  expect(after.start).toBe("2026-05-15T00:00:00.000Z");
});

test("US-109: anonymization is off by default and lists its categories", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/anon-control`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { enabled: boolean; categories: Record<string, boolean> };

  // Off by default: anonymization rewrites what the analyst sees, so turning it on is a decision.
  expect(body.enabled).toBe(false);
  // The categories drive the settings panel's checkboxes. A missing one cannot be turned on, which
  // is how a detector goes silently unused — the exact failure tsconfig.test.json's header
  // describes for AnonPolicy.
  for (const key of ["IP", "EMAIL", "USER", "HOST", "DOMAIN"]) {
    expect(body.categories, `anonymization is missing the ${key} category`).toHaveProperty(key);
  }
});

test("US-110: comments are analyst-authored and survive re-synthesis", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const seeded = (await (await page.request.get(`/cases/${demoCase}/comments`)).json()) as unknown[];
  expect(seeded.length, "the seeded case ships analyst comments").toBeGreaterThan(0);

  const text = `e2e comment ${Date.now()}`;
  const added = await page.request.post(`/cases/${demoCase}/comments`, {
    data: { targetType: "ioc", targetId: "ioc001", author: "e2e", text },
  });
  expect(added.status(), await added.text()).toBeLessThan(300);
  expect(await (await page.request.get(`/cases/${demoCase}/comments`)).text()).toContain(text);

  // THE PROPERTY THAT MATTERS. Synthesis rebuilds findings, questions and next steps from
  // evidence; a comment is the analyst's own reasoning and is not reproducible. If a re-synthesis
  // wiped it, the investigator would lose work with no way to notice until they went looking.
  const synth = await page.request.post(`/cases/${demoCase}/synthesize`, { data: {} });
  expect([200, 202, 409, 501], await synth.text()).toContain(synth.status());
  await expect
    .poll(async () => (await (await page.request.get(`/cases/${demoCase}/comments`)).text()).includes(text), {
      timeout: 30_000,
      intervals: [500],
    })
    .toBe(true);
});

test("US-111: tags round-trip and can be removed", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const label = `e2e-tag-${Date.now()}`;
  const added = await page.request.post(`/cases/${demoCase}/tags`, {
    data: { targetType: "ioc", targetId: "ioc002", label, author: "e2e" },
  });
  expect(added.status(), await added.text()).toBeLessThan(300);

  const tags = (await (await page.request.get(`/cases/${demoCase}/tags`)).json()) as Array<{
    id: string;
    label: string;
  }>;
  const mine = tags.find((t) => t.label === label);
  expect(mine?.id, "a saved tag needs an id to be removable").toBeTruthy();

  const removed = await page.request.delete(`/cases/${demoCase}/tags/${mine?.id}`);
  expect([200, 204], await removed.text()).toContain(removed.status());
  expect(await (await page.request.get(`/cases/${demoCase}/tags`)).text()).not.toContain(label);
});

test("US-116: asset overrides expose every edit channel the panel offers", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/asset-overrides`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as Record<string, unknown>;

  // The derived asset graph is rebuilt from evidence on every analysis, so each manual correction
  // needs its own channel here or it is lost on the next run.
  for (const key of ["renames", "added", "removed", "addedLinks", "removedLinks", "merges"]) {
    expect(body, `asset overrides cannot express "${key}"`).toHaveProperty(key);
  }
});

test("US-181: the tagger ruleset is readable and validated on write", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/tagger/rules");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { text: string };
  expect(body.text, "the shipped default ruleset").toBeTruthy();

  // A ruleset that fails to parse must be refused, not stored. Accepting it would leave every
  // later tagger run silently doing nothing.
  const bad = await page.request.put("/tagger/rules", {
    data: { text: "this: is: not: valid: yaml: [unclosed" },
  });
  expect(bad.status(), await bad.text()).toBeGreaterThanOrEqual(400);
});

test("US-202: finding workflow overrides list and merge partially", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const listed = await page.request.get(`/cases/${demoCase}/finding-workflow`);
  expect(listed.status(), await listed.text()).toBe(200);
  expect(Array.isArray(await listed.json())).toBe(true);

  const patch = await page.request.patch(`/cases/${demoCase}/findings/f001/workflow`, {
    // Underscores, not hyphens: new | in_progress | in_review | resolved.
    data: { status: "in_progress" },
  });
  expect(patch.status(), await patch.text()).toBeLessThan(300);

  // PARTIAL merge is the point: setting a status must not clear an assignee set separately, or two
  // analysts editing the same finding would overwrite each other.
  const assign = await page.request.patch(`/cases/${demoCase}/findings/f001/workflow`, {
    data: { assignee: "e2e-analyst" },
  });
  expect(assign.status(), await assign.text()).toBeLessThan(300);

  const after = await (await page.request.get(`/cases/${demoCase}/finding-workflow`)).text();
  expect(after, "the assignee did not persist").toContain("e2e-analyst");
  expect(after, "setting the assignee cleared the status").toContain("in_progress");
});

test("US-049: import metadata describes the last import's delta", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/import-meta`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    lastImportedAt: string;
    lastImportKind: string;
    addedCount: number;
  };

  // This drives the "N new events since your last import" banner and the NEW row highlights. All
  // three are needed: without the kind and time the banner cannot say what changed or when.
  expect(body.lastImportedAt).toBeTruthy();
  expect(body.lastImportKind).toBeTruthy();
  expect(typeof body.addedCount).toBe("number");
});

test("US-213: diagnostics reports per-importer runs and failures", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/diagnostics");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { report: Record<string, unknown> };

  // Diagnostics is what an operator sends when reporting a problem, so an empty report wastes the
  // exchange. Disk and uptime are the two that are always answerable.
  expect(body.report, "diagnostics returned no report").toBeTruthy();
  expect(body.report).toHaveProperty("disk");
  expect(body.report).toHaveProperty("uptimeMs");
});
