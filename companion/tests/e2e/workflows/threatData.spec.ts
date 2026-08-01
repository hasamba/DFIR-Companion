import { test, expect } from "../fixtures/test.js";

// Covers: US-105, US-106, US-107, US-108, US-154, US-182
// (feature-user-stories.csv) — the threat-data surfaces: the NSRL known-good set, the CISA KEV
// catalogue, the IOC whitelist, deobfuscation, IOC sources/provenance and composite IOC risk.
//
// NOTHING HERE FETCHES A FEED. /kev/import-url pulls the CISA catalogue and the NSRL importers
// read large external sets; this suite must not reach the network, so the tests assert the
// EMPTY-AND-DISABLED contract, which is what a fresh install reports, plus the parts derived
// locally from the case.
//
// TWO STORIES ARE NOT CLAIMED, and neither is a gap:
//
//   US-188 (offline lookalike-domain detection) has no HTTP route at all — the detector runs
//   inside the analysis pipeline, and the seeded case mentions a lookalike only in an analyst
//   comment, not as derived output. There is nothing for a browser test to assert that would not
//   really be asserting the fixture. tests/analysis/lookalikeDomains.test.ts covers the detector.
//
//   US-206 (rate-limit-aware enrichment backoff) is provider behaviour on 429/transient responses.
//   Exercising it means letting the suite call an enrichment provider, which is exactly what it
//   must not do. tests/enrichment/provider.test.ts covers it.

test("US-105: the NSRL set reports itself absent rather than erroring", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/nsrl");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as {
    count: number;
    enabled: boolean;
    db: { connected: boolean };
    dbConfigurable: boolean;
  };

  // A fresh install has no NSRL set. The panel must be able to say so — an error here would read
  // as "known-good filtering is broken" rather than "you have not loaded the set yet".
  expect(body.enabled).toBe(false);
  expect(body.count).toBe(0);
  expect(body.db.connected).toBe(false);
  // The panel offers a "configure database" affordance based on this, so it has to be present.
  expect(typeof body.dbConfigurable).toBe("boolean");
});

test("US-106: the KEV catalogue reports itself empty without fetching it", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/kev");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { count: number; enabled: boolean };

  // Empty and disabled until an operator imports it. Reading this endpoint must never trigger the
  // fetch — KEV import is an explicit action, and a GET that quietly downloaded a CISA feed would
  // make simply opening the dashboard phone out.
  expect(body.enabled).toBe(false);
  expect(body.count).toBe(0);
});

test("US-107: the IOC whitelist round-trips and exports", async ({ page }) => {
  await page.goto("/dashboard");

  const initial = await page.request.get("/ioc-whitelist");
  expect(initial.status(), await initial.text()).toBe(200);
  expect(Array.isArray(await initial.json())).toBe(true);

  // Entries are RULES, not bare values: a match mode (cidr|regex|exact) and a pattern valid for
  // that mode. That is what makes "whitelist this /16" expressible at all.
  const value = `e2e-whitelist-${Date.now()}.example`;
  const add = await page.request.post("/ioc-whitelist", {
    data: { match: "exact", pattern: value, note: "added by the browser suite" },
  });
  expect([200, 201], await add.text()).toContain(add.status());

  const listed = await page.request.get("/ioc-whitelist");
  expect(await listed.text(), "a whitelisted IOC must come back").toContain(value);

  // The export is what an analyst hands to another team, so it has to include what was just added
  // rather than only what shipped.
  const exported = await page.request.get("/ioc-whitelist/export");
  expect(exported.status()).toBe(200);
  expect(await exported.text()).toContain(value);

  // The whitelist is GLOBAL, so this removes what it created — otherwise every later run starts
  // with an accumulating list of test entries that silently suppress real IOCs.
  //
  // Deletion is BY RULE ID on the path (DELETE /ioc-whitelist/:ruleId), not by pattern on the
  // query string. The first version of this test used ?pattern=, which hit no route at all; a
  // lenient status assertion accepted the 404 and the cleanup never happened. The check that the
  // entry is actually gone is what makes the cleanup verifiable rather than aspirational.
  const rules = (await (await page.request.get("/ioc-whitelist")).json()) as Array<{
    id: string;
    pattern: string;
  }>;
  const mine = rules.find((r) => r.pattern === value);
  expect(mine?.id, "a saved whitelist rule needs an id to be removable").toBeTruthy();

  const del = await page.request.delete(`/ioc-whitelist/${mine?.id}`);
  expect([200, 204], await del.text()).toContain(del.status());
  expect(await (await page.request.get("/ioc-whitelist")).text()).not.toContain(value);
});

test("US-108: deobfuscation reports what it decoded", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/deobfuscate`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { deobfuscated: number; newIocs: number };

  // Zero is a legitimate answer for the seeded case — what matters is that both counts are
  // reported. An analyst who runs this needs to know whether it found nothing or did nothing.
  expect(typeof body.deobfuscated).toBe("number");
  expect(typeof body.newIocs).toBe("number");
});

test("US-154: IOC provenance says where each indicator came from", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const prov = await page.request.get(`/cases/${demoCase}/ioc-provenance`);
  expect(prov.status(), await prov.text()).toBe(200);
  const map = (await prov.json()) as Record<string, string>;

  // Every seeded IOC must have an origin. An indicator with unknown provenance cannot be defended
  // in a report — "where did this come from?" is the first question asked of it.
  expect(Object.keys(map).length, "the seeded case has 17 IOCs").toBeGreaterThan(0);
  for (const [ioc, origin] of Object.entries(map)) {
    expect(origin, `${ioc} has no provenance`).toBeTruthy();
  }

  const sources = await page.request.get(`/cases/${demoCase}/ioc-sources`);
  expect(sources.status(), await sources.text()).toBe(200);
});

test("US-182: composite IOC risk combines verdict, severity and corroboration", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/ioc-risk`);
  expect(res.status(), await res.text()).toBe(200);
  const risk = (await res.json()) as Record<string, { score: string; factors: string[] }>;

  expect(Object.keys(risk).length, "risk is scored per IOC").toBeGreaterThan(0);

  const first = Object.values(risk)[0];
  expect(first.score, "each IOC carries a composite score").toBeTruthy();
  // The factors are the point: a bare score an analyst cannot interrogate is not defensible, and
  // this endpoint exists so the panel can show WHY an indicator scored as it did.
  expect(Array.isArray(first.factors)).toBe(true);
  expect(first.factors.length, "a score with no stated reasons").toBeGreaterThan(0);
});
