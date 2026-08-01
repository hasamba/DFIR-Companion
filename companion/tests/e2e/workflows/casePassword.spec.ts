import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext, Page } from "@playwright/test";

// Covers: US-121, US-122, US-123, US-124, US-125
// (feature-user-stories.csv) — per-case password: lock status, unlock, set/change, clear, and
// locking this browser only.
//
// EVERY TEST HERE USES ITS OWN CASE, never the shared demoCase fixture. Setting a password locks
// the case, and a locked fixture would break every other spec that touches it — the failure would
// surface far away from the cause, in whichever spec happened to run next.
//
// This is the one feature in the product where a test passing for the wrong reason is dangerous:
// "unlock succeeded" is only meaningful if a WRONG password also fails. Each test asserts both
// directions.
//
// NOTE THE FIELD NAMES, which differ between the two routes: POST /password takes `newPassword`,
// POST /unlock takes `password`. Sending the wrong one to /password silently sets nothing, and
// /unlock then answers 200 "nothing to unlock" for a case with no password — which reads exactly
// like a wrong password being ACCEPTED. That is what the first version of this file appeared to
// find, and it was a bug in the test, not a hole in the product.

/** Create a case this test owns outright. */
async function freshCase(page: Page, label: string): Promise<string> {
  const caseId = `pw-${label}-${Date.now()}-${Math.floor(process.hrtime()[1] / 1000)}`;
  const res = await page.request.post("/cases", {
    data: { caseId, name: `Password ${label}`, investigator: "e2e" },
  });
  expect(res.status(), await res.text()).toBeLessThan(300);
  return caseId;
}

async function lockStatus(
  request: APIRequestContext,
  caseId: string,
): Promise<{ hasPassword: boolean; unlocked: boolean }> {
  const res = await request.get(`/cases/${caseId}/lock-status`);
  expect(res.status(), await res.text()).toBe(200);
  return (await res.json()) as { hasPassword: boolean; unlocked: boolean };
}

test("US-121: a case with no password reports itself open", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "status");

  const status = await lockStatus(page.request, caseId);
  // Both flags matter: hasPassword false AND unlocked true. A case that claimed to be locked
  // without a password set would be unopenable with no way to unlock it.
  expect(status.hasPassword).toBe(false);
  expect(status.unlocked).toBe(true);
});

test("US-123: setting a password requires a real one and takes effect", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "set");

  // Too short. A case password protects evidence, so a two-character one being accepted would be
  // worse than none — it looks protected.
  const short = await page.request.post(`/cases/${caseId}/password`, { data: { newPassword: "abc" } });
  expect(short.status(), await short.text()).toBe(400);
  expect(await short.text(), "the refusal should name the minimum").toMatch(/6 characters/);

  const set = await page.request.post(`/cases/${caseId}/password`, {
    data: { newPassword: "e2e-strong-password" },
  });
  expect(set.status(), await set.text()).toBeLessThan(300);

  expect((await lockStatus(page.request, caseId)).hasPassword, "the password did not stick").toBe(true);
});

test("US-122: unlock accepts the right password and refuses a wrong one", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "unlock");
  const password = "e2e-strong-password";

  await page.request.post(`/cases/${caseId}/password`, { data: { newPassword: password } });

  // WRONG FIRST, deliberately. If this test only ever tried the correct password it would pass
  // against an unlock that accepts anything — which is the failure that actually matters here.
  const wrong = await page.request.post(`/cases/${caseId}/unlock`, {
    data: { password: "not-the-password" },
  });
  expect(wrong.status(), "a wrong password must not unlock the case").toBeGreaterThanOrEqual(400);

  const right = await page.request.post(`/cases/${caseId}/unlock`, { data: { password } });
  expect(right.status(), await right.text()).toBeLessThan(300);
  expect((await lockStatus(page.request, caseId)).unlocked).toBe(true);
});

test("US-125: locking clears this browser's unlock without removing the password", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "lock");
  const password = "e2e-strong-password";

  await page.request.post(`/cases/${caseId}/password`, { data: { newPassword: password } });
  await page.request.post(`/cases/${caseId}/unlock`, { data: { password } });
  expect((await lockStatus(page.request, caseId)).unlocked).toBe(true);

  const lock = await page.request.post(`/cases/${caseId}/lock`, { data: {} });
  expect(lock.status(), await lock.text()).toBeLessThan(300);

  const after = await lockStatus(page.request, caseId);
  // Locking is a "step away from the screen" action, not a "remove protection" one: the password
  // must survive it, or an analyst locking their session would silently disarm the case.
  expect(after.unlocked, "lock did not clear the local unlock").toBe(false);
  expect(after.hasPassword, "lock must not remove the password").toBe(true);
});

test("US-124: clearing the password reopens the case", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "clear");
  const password = "e2e-strong-password";

  await page.request.post(`/cases/${caseId}/password`, { data: { newPassword: password } });
  await page.request.post(`/cases/${caseId}/unlock`, { data: { password } });

  const cleared = await page.request.delete(`/cases/${caseId}/password`);
  expect(cleared.status(), await cleared.text()).toBeLessThan(300);

  const after = await lockStatus(page.request, caseId);
  expect(after.hasPassword, "the password survived being cleared").toBe(false);
  // ...and the case must be usable again, not left in a state where it has no password but still
  // reports itself locked.
  expect(after.unlocked).toBe(true);
});

test("US-122: repeated wrong passwords trigger a brute-force lockout", async ({ page }) => {
  await page.goto("/dashboard");
  const caseId = await freshCase(page, "lockout");
  await page.request.post(`/cases/${caseId}/password`, { data: { newPassword: "e2e-strong-password" } });

  // The limiter allows five failures per case, then backs off with a Retry-After. Without it a
  // case password is only as strong as the attacker's patience, since the endpoint is local and
  // unauthenticated by design.
  let sawLockout = false;
  for (let attempt = 1; attempt <= 8 && !sawLockout; attempt++) {
    const res = await page.request.post(`/cases/${caseId}/unlock`, {
      data: { password: `wrong-${attempt}` },
    });
    if (res.status() === 429) {
      sawLockout = true;
      // Retry-After is what tells a client how long to wait; without it the lockout is invisible.
      expect(res.headers()["retry-after"], "a 429 with no Retry-After").toBeTruthy();
    } else {
      expect(res.status(), "a wrong password must never unlock").toBeGreaterThanOrEqual(400);
    }
  }
  expect(sawLockout, "eight wrong passwords produced no lockout").toBe(true);
});
