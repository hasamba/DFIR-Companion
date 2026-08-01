import { test, expect } from "../fixtures/test.js";

// Covers: US-173, US-177, US-195, US-215, US-216
// (feature-user-stories.csv) — the last API- and UI-backed surfaces: collect directives, the
// false-positive cascade, server-backed starred events, the deep-pass batch plan, and the
// contextual manual link.
//
// US-203 (Sigma draft) is NOT claimed. There is no server route: the draft is built and downloaded
// in the browser from a finding's structured evidence, so nothing here can assert what it emits
// without reimplementing the generator in the test. Recorded so the empty column is a decision.

test("US-215: the deep-pass preview reports its batch plan before spending anything", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/deep-pass/preview`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    cap: number;
    floors: Array<{ floor: string; events: number; batches: number }>;
  };

  // The whole point of a preview is that an analyst sees the cost BEFORE committing: a deep pass
  // over a large case is many model calls. A preview that reported no plan would leave them
  // choosing blind.
  expect(body.cap, "the event cap").toBeGreaterThan(0);
  expect(body.floors.length, "a plan per severity floor").toBeGreaterThan(0);
  for (const floor of body.floors) {
    expect(floor.floor, "a floor with no severity").toBeTruthy();
    expect(typeof floor.events, `${floor.floor} does not say how many events`).toBe("number");
    expect(typeof floor.batches, `${floor.floor} does not say how many batches`).toBe("number");
  }
});

test("US-177: marking a false positive requires a reference and a reason", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const bare = await page.request.post(`/cases/${demoCase}/false-positive`, { data: {} });
  expect(bare.status(), await bare.text()).toBe(400);
  expect(await bare.text()).toMatch(/ref is required/);

  // "other" without a note is an unexplained dismissal. Months later nobody can say why an event
  // was set aside, which is exactly the audit question a false-positive list has to answer.
  const otherNoNote = await page.request.post(`/cases/${demoCase}/false-positive`, {
    data: { ref: "10.10.0.99", kind: "ioc", reason: "other" },
  });
  expect(otherNoNote.status(), await otherNoNote.text()).toBe(400);

  const good = await page.request.post(`/cases/${demoCase}/false-positive`, {
    data: { ref: "10.10.0.99", kind: "ioc", reason: "known-good-tool", note: "e2e" },
  });
  expect(good.status(), await good.text()).toBeLessThan(300);

  const listed = await page.request.get(`/cases/${demoCase}/false-positive`);
  expect(await listed.text(), "the dismissal was not recorded").toContain("10.10.0.99");
});

test("US-195: starred state is server-backed rather than browser-local", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Starring is stored as a reserved tag on the server. That is the migration the story describes:
  // a star kept in localStorage vanishes when the analyst opens the case on another machine, which
  // for a shared investigation is lost work.
  const label = "starred";
  const star = await page.request.post(`/cases/${demoCase}/tags`, {
    data: { targetType: "event", targetId: "e001", label, author: "e2e" },
  });
  expect(star.status(), await star.text()).toBeLessThan(300);

  // A fresh browser context has no local state at all, so anything it can see is server-side.
  const fresh = await page.context().newPage();
  const seen = await fresh.request.get(`/cases/${demoCase}/tags`);
  expect(await seen.text(), "the star did not survive a new browser context").toContain(label);
  await fresh.close();

  const report = await page.request.get(`/cases/${demoCase}/starred-report`);
  // 404 with nothing saved and 501 without the store are both honest; a 500 would not be.
  expect([200, 404, 501], await report.text()).toContain(report.status());
});

test("US-173: a collect directive refuses cleanly without Velociraptor", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/velociraptor/collect-directive`, {
    data: {},
  });
  // Directives become playbook tasks and report entries, but issuing one needs a server to issue
  // it to. 501 naming the setting, not a 500 — see velociraptor.spec.ts for the same contract.
  expect(res.status(), await res.text()).toBe(501);
  expect(await res.text()).toMatch(/DFIR_VELOCIRAPTOR_API_CONFIG/);
});

test("US-216: the manual link is keyboard-reachable and explains itself", async ({ page }) => {
  await page.goto("/dashboard");

  const help = page.locator("#helpBtn");
  await expect(help).toHaveCount(1);

  // An icon-only link with no accessible name announces as "link" and nothing else. This is the
  // same defect class the data-tip work fixed across 23 controls.
  const name = await help.evaluate(
    (el) => el.getAttribute("aria-label") || el.getAttribute("title") || el.textContent?.trim() || "",
  );
  expect(name.length, "the help control has no accessible name").toBeGreaterThan(1);

  // It must be focusable: a mouse-only help link is unreachable for the keyboard users most likely
  // to need the manual.
  await help.focus();
  await expect(help).toBeFocused();

  // ...and it must open in a new tab, so clicking help never discards an open case.
  await expect(help).toHaveAttribute("target", "_blank");
  await expect(help).toHaveAttribute("rel", /noopener|noreferrer/);
});
