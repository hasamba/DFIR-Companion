import { test, expect } from "../fixtures/test.js";

// Covers: US-077, US-078, US-079, US-080
// (feature-user-stories.csv) — IOC enrichment: routing to providers, bulk enrichment, the
// local-only-by-default control, and provider health.
//
// THE DEFAULT IS THE FEATURE. Enriching an indicator TELLS A THIRD PARTY you are investigating it:
// submitting an attacker's C2 domain to a public service can tip off the adversary that they have
// been found. So the property worth pinning is not that enrichment works — it is that nothing
// leaves the building until an investigator explicitly opts in, per case.
//
// These tests are also the reason this whole suite can safely touch enrichment at all: they assert
// the no-call path rather than exercising a provider. Nothing here may cause an outbound request.

test("US-079: external providers are opt-in per case, not on by default", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/enrich-control`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    anyConfigured: boolean;
    providers: Array<{ name: string; scope: string; enabled: boolean }>;
  };

  expect(body.providers.length, "the enrichment panel renders from this list").toBeGreaterThan(0);

  // The one that matters: no EXTERNAL provider may be enabled without the investigator saying so.
  // A default-on external provider would send indicators off-box the first time a case is opened.
  const externalOn = body.providers.filter((p) => p.scope === "external" && p.enabled);
  expect(
    externalOn.map((p) => p.name),
    "external providers enabled without opt-in",
  ).toEqual([]);
});

test("US-077: with nothing enabled, enrichment refuses instead of calling out", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const started = Date.now();
  const res = await page.request.post(`/cases/${demoCase}/enrich`, { data: {} });
  const elapsed = Date.now() - started;

  // 422, not 200-with-nothing-done: the analyst asked for enrichment and must be told it did not
  // happen, or they will read an un-enriched IOC list as "nothing known about these".
  expect(res.status(), await res.text()).toBe(422);
  expect(await res.text()).toMatch(/no enrichment providers enabled/);

  // And it must refuse WITHOUT reaching for the network. A refusal that first tried a provider
  // would already have leaked the indicator, whatever it answered afterwards.
  expect(elapsed, "the refusal took long enough to have made a network call").toBeLessThan(2000);
});

test("US-078: bulk enrichment validates its input", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const empty = await page.request.post(`/cases/${demoCase}/iocs/bulk-enrich`, { data: {} });
  expect(empty.status(), await empty.text()).toBe(400);
  expect(await empty.text()).toMatch(/iocIds must be a non-empty array/);

  // An empty array is the shape a "select all" with nothing selected sends. Treating it as
  // "enrich everything" would be the worst possible interpretation for a privacy-sensitive action.
  const emptyArray = await page.request.post(`/cases/${demoCase}/iocs/bulk-enrich`, {
    data: { iocIds: [] },
  });
  expect(emptyArray.status(), await emptyArray.text()).toBe(400);
});

test("US-080: provider health reports without probing unconfigured providers", async ({ page }) => {
  await page.goto("/dashboard");

  const started = Date.now();
  const res = await page.request.get("/enrich-health");
  const elapsed = Date.now() - started;

  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    providers: Array<{ name: string; scope: string; probed: boolean; ok: boolean }>;
  };

  expect(body.providers.length, "the health panel renders from this list").toBeGreaterThan(0);

  // Every provider must report its scope, since "local" and "external" are what tell an analyst
  // whether consulting it is OPSEC-safe.
  for (const p of body.providers) {
    expect(p.name, "a provider with no name").toBeTruthy();
    expect(["local", "external"], `${p.name} has scope "${p.scope}"`).toContain(p.scope);
    expect(typeof p.probed, `${p.name} does not say whether it was probed`).toBe("boolean");
  }

  // Nothing configured here, so nothing should have been reached for. `probed` is the endpoint's
  // own admission of whether it made a call — asserting it false is what keeps this suite from
  // quietly pinging third parties on every run.
  expect(
    body.providers.filter((p) => p.probed).map((p) => p.name),
    "providers were probed over the network",
  ).toEqual([]);
  expect(elapsed, "health took long enough to have probed something").toBeLessThan(3000);
});
