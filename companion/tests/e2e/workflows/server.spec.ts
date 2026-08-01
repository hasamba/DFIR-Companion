import { test, expect } from "../fixtures/test.js";

// Covers: US-117, US-118, US-119, US-120, US-152
// (feature-user-stories.csv) — the server's own surfaces: health, the dashboard and mobile views,
// the PWA manifest and service worker, and the diagnostics preflight.
//
// These are the things that break silently. A malformed manifest or a 404 service worker does not
// error anywhere an operator would see — the app simply stops being installable, and nobody
// notices until someone tries.

test("US-117: health reports service status flags", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/health");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as Record<string, unknown>;

  // Health is what a container orchestrator polls, so it must be JSON with real content rather
  // than a bare 200 — an empty body would satisfy a naive liveness probe while telling nobody
  // anything.
  expect(Object.keys(body).length, "health with no flags is not health").toBeGreaterThan(0);
});

test("US-118: the dashboard is served as HTML", async ({ page }) => {
  const res = await page.request.get("/dashboard");
  expect(res.status()).toBe(200);
  expect(res.headers()["content-type"]).toMatch(/html/);

  const html = await res.text();
  // The single-file dashboard is ~1.7MB. A truncated or half-written response would still be
  // "200 text/html" while rendering nothing.
  expect(html.length, "the dashboard came back suspiciously small").toBeGreaterThan(100_000);
  expect(html).toContain("</html>");
});

test("US-119: the mobile view is served and is not the desktop dashboard", async ({ page }) => {
  const res = await page.request.get("/mobile");
  expect(res.status(), await res.text()).toBe(200);
  expect(res.headers()["content-type"]).toMatch(/html/);

  const html = await res.text();
  expect(html).toContain("</html>");
  // The point of the mobile view is that it is LIGHT. If this ever starts serving the full
  // dashboard, the route still "works" while being unusable on a phone.
  expect(html.length, "the mobile view should be far smaller than the dashboard").toBeLessThan(200_000);
});

test("US-120: the PWA manifest and service worker are both installable", async ({ page }) => {
  const manifest = await page.request.get("/manifest.webmanifest");
  expect(manifest.status(), await manifest.text()).toBe(200);
  // The browser ignores a manifest served as text/plain, so the type is the feature.
  expect(manifest.headers()["content-type"]).toMatch(/manifest\+json/);

  const parsed = (await manifest.json()) as { name?: string; icons?: unknown[]; start_url?: string };
  // Without a name, icons and a start_url there is nothing to install — the browser silently
  // declines rather than reporting an error.
  expect(parsed.name, "an installable app needs a name").toBeTruthy();
  expect(parsed.start_url, "an installable app needs a start_url").toBeTruthy();
  expect(Array.isArray(parsed.icons) && parsed.icons.length, "icons").toBeTruthy();

  const sw = await page.request.get("/sw.js");
  expect(sw.status(), await sw.text()).toBe(200);
  // A service worker served with the wrong type is refused by the browser at registration.
  expect(sw.headers()["content-type"]).toMatch(/javascript/);
  expect((await sw.text()).length, "an empty service worker registers but does nothing").toBeGreaterThan(100);
});

test("US-152: the diagnostics preflight reports environment checks", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/diagnostics/preflight");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as Record<string, unknown>;

  // This is what an operator runs when something is wrong, so it has to say something. A preflight
  // that returns an empty object reads as "everything is fine" when it means "nothing was checked".
  expect(Object.keys(body).length, "a preflight with no checks").toBeGreaterThan(0);
});
