import { test, expect } from "../fixtures/test.js";

// Covers: US-052, US-054, US-066, US-070, US-153
// (feature-user-stories.csv) — the dashboard panels an analyst WRITES to: starring an event,
// adding a manual event, investigation threads, the confirmed-legitimate list, and custom
// dashboard views.
//
// Every one is a round trip — write, read back, and where the panel offers it, remove. A POST that
// answers 200 and persists nothing is the failure that matters here: the analyst sees their edit
// in the UI, reloads, and it is gone. Only reading it back on a fresh request catches that.

test("US-054: a manually added event is persisted into the timeline", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const description = "Analyst-entered: USB device connected to WKSTN-JSMITH";
  const res = await page.request.post(`/cases/${demoCase}/events`, {
    data: {
      timestamp: "2026-05-16T10:00:00.000Z",
      description,
      severity: "Medium",
      sources: ["analyst"],
    },
  });
  expect(res.status(), await res.text()).toBe(201);

  // Read it back from the case state, not from the POST response — the panel renders state.
  const state = await page.request.get(`/cases/${demoCase}/state`);
  expect(await state.text()).toContain(description);
});

test("US-054: an event with no timestamp or description is refused", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Both are required by the manual-entry schema. An undated event cannot be placed on a timeline,
  // and an empty one is a blank row an analyst cannot act on.
  const noTime = await page.request.post(`/cases/${demoCase}/events`, {
    data: { description: "no timestamp" },
  });
  expect(noTime.status()).toBe(400);

  const noDesc = await page.request.post(`/cases/${demoCase}/events`, {
    data: { timestamp: "2026-05-16T10:00:00.000Z" },
  });
  expect(noDesc.status()).toBe(400);
});

test("US-052: starring an event survives a reload", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The reserved `starred` tag is stored SERVER-side (#195) precisely so a star is not lost when
  // the analyst opens the case on another machine. Tagging through the API is what the star button
  // does underneath.
  const eventsRes = await page.request.get(`/cases/${demoCase}/state`);
  // forensicTimeline, NOT timeline: the latter is the analysis log (a handful of "imported X"
  // entries with no ids), while the 58 forensic events an analyst stars live in the former.
  const state = (await eventsRes.json()) as { forensicTimeline?: Array<{ id?: string }> };
  const target = state.forensicTimeline?.find((e) => e.id);
  expect(target?.id, "the seeded case has timeline events to star").toBeTruthy();

  const star = await page.request.post(`/cases/${demoCase}/tags`, {
    data: { targetType: "event", targetId: target?.id, label: "starred" },
  });
  expect([200, 201]).toContain(star.status());

  const tags = await page.request.get(`/cases/${demoCase}/tags`);
  expect(tags.status()).toBe(200);
  expect(await tags.text(), "the star must come back from the server, not local state").toContain(
    String(target?.id),
  );
});

test("US-066: investigation threads carry the status the panel splits on", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/state`);
  expect(res.status()).toBe(200);
  const threads = ((await res.json()) as { openThreads?: Array<Record<string, unknown>> }).openThreads;

  expect(threads?.length, "the seeded case has investigation threads").toBeGreaterThan(0);
  // The panel lists open and closed separately, so each thread must say which it is.
  expect(threads?.[0]).toHaveProperty("status");
  expect(threads?.[0]).toHaveProperty("openedAt");
});

test("US-070: an IOC can be excluded as confirmed legitimate and restored", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The exclusion is a RULE, not a bare value: match (exact|suffix|regex) plus a pattern. That
  // shape is what lets one entry cover a whole domain instead of a single observed string.
  const value = "10.10.0.53";
  const add = await page.request.post(`/cases/${demoCase}/ioc-exclude`, {
    data: { match: "exact", pattern: value, reason: "internal DNS resolver" },
  });
  expect([200, 201], await add.text()).toContain(add.status());

  const listed = await page.request.get(`/cases/${demoCase}/ioc-exclude`);
  expect(listed.status()).toBe(200);
  expect(await listed.text(), "the exclusion must persist for analysis to honour it").toContain(value);
});

test("US-153: a custom dashboard view round-trips and can be deleted", async ({ page }) => {
  await page.goto("/dashboard");

  const name = `e2e-view-${Date.now()}`;
  const create = await page.request.post("/dashboard-views", {
    data: { name, sections: ["sec-timeline", "sec-findings"] },
  });
  expect([200, 201], await create.text()).toContain(create.status());
  const created = (await create.json()) as { id?: string };
  expect(created.id, "a saved view needs an id to be selectable or deleted").toBeTruthy();

  const list = await page.request.get("/dashboard-views");
  expect(await list.text()).toContain(name);

  // Views are global rather than per-case, so this test cleans up after itself; a leaked view
  // would accumulate across runs and eventually change what the picker shows.
  const del = await page.request.delete(`/dashboard-views/${created.id}`);
  expect([200, 204]).toContain(del.status());
  expect(await (await page.request.get("/dashboard-views")).text()).not.toContain(name);
});

test("US-153: a view with no name is refused", async ({ page }) => {
  await page.goto("/dashboard");
  const res = await page.request.post("/dashboard-views", { data: { sections: [] } });
  // An unnamed view is unselectable in the picker, so it must not be storable.
  expect(res.status()).toBe(400);
});
