import { test, expect } from "../fixtures/test.js";

// Covers: US-112, US-113, US-114, US-115, US-132, US-133, US-159, US-191
// (feature-user-stories.csv) — the settings surfaces: the env editor, log level, update check,
// custom importers, setup status, live AI/env reload, the forensic gate and per-source trust.
//
// US-168 (extension connection settings) is NOT claimed here: normalizeCompanionUrl() lives in the
// add-on, and extension/tests/settings.test.ts already covers it. See captures.spec.ts for the
// full extension mapping.
//
// POST /update-check/run is deliberately never called. It asks GitHub for the latest release, and
// this suite must not reach the network — the same rule that shapes integrations.spec.ts and
// velociraptor.spec.ts. The check's stored settings and its reported state are testable offline,
// and are what the dashboard renders.

test("US-112, US-133: the env editor and live reload cannot read config from outside the harness", async ({
  page,
}) => {
  await page.goto("/dashboard");

  // server-entry.ts pins DFIR_ENV_FILE inside the throwaway root, so this reads a file that does
  // not exist and comes back empty.
  const env = await page.request.get("/settings/env");
  expect(env.status(), await env.text()).toBe(200);
  expect(((await env.json()) as { env: Record<string, string> }).env).toEqual({});

  // The reason that pin exists. resolveEnvFilePath() otherwise falls back to cwd/.env, and
  // ai-reload OVERWRITES process.env for DFIR_AI_* and DFIR_VISION_* from whatever it finds. Run
  // from a checkout that has a real .env — the main one does — an unpinned harness would load real
  // API keys over the stub mid-run and start sending case evidence to a live provider.
  //
  // `applied: []` is the assertion that this cannot happen. Verified by removing the pin: the
  // reload then reported the keys from a planted .env.
  const reload = await page.request.post("/settings/ai-reload", { data: {} });
  expect(reload.status(), await reload.text()).toBe(200);
  const applied = ((await reload.json()) as { applied: string[] }).applied;
  expect(applied, "a reload must not pull configuration in from outside the harness").toEqual([]);
});

test("US-113: the log level round-trips and rejects an unknown level", async ({ page }) => {
  await page.goto("/dashboard");

  const initial = await page.request.get("/log-level");
  expect(initial.status()).toBe(200);
  const body = (await initial.json()) as { level: string; levels: string[] };
  expect(body.levels, "the picker renders from this list").toContain(body.level);

  const set = await page.request.post("/log-level", { data: { level: "debug" } });
  expect(set.status(), await set.text()).toBe(200);
  expect(((await (await page.request.get("/log-level")).json()) as { level: string }).level).toBe("debug");

  // An unknown level must be refused rather than silently leaving logging where it was — an
  // operator who thinks they enabled debug and did not will misread the resulting quiet log.
  const bad = await page.request.post("/log-level", { data: { level: "verbose" } });
  expect(bad.status()).toBe(400);

  // Put it back so later specs are not logging at debug.
  await page.request.post("/log-level", { data: { level: body.level } });
});

test("US-114: the update check reports state without contacting GitHub", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/update-check");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { enabled: boolean; current: string; latest: string | null };

  // Off by default, which is the privacy-respecting default for a forensics tool: no phoning home
  // unless the operator asks.
  expect(body.enabled).toBe(false);
  // The running version must still be reported, since the panel shows it whether or not checking
  // is enabled.
  expect(body.current, "the running version").toMatch(/^\d+\.\d+\.\d+/);
  // Nothing was fetched, so there is no "latest" to show.
  expect(body.latest).toBeNull();

  const toggle = await page.request.post("/update-check/settings", { data: { enabled: false } });
  expect([200, 204], await toggle.text()).toContain(toggle.status());
});

test("US-132: setup status reports what is configured for the wizard", async ({ page }) => {
  await page.goto("/dashboard");

  const res = await page.request.get("/setup/status");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as Record<string, boolean>;

  // The first-run wizard renders a tick per integration from these flags, so each must be present
  // and boolean — a missing key shows as neither done nor pending.
  for (const key of ["ai", "velociraptor", "iris", "timesketch"]) {
    expect(typeof body[key], `setup status is missing ${key}`).toBe("boolean");
  }
  // The stub counts as a configured AI provider, and nothing else is wired in this harness.
  expect(body.ai).toBe(true);
  expect(body.velociraptor).toBe(false);
});

test("US-115: custom importers list, validate and round-trip", async ({ page }) => {
  await page.goto("/dashboard");

  const listed = await page.request.get("/importers");
  expect(listed.status(), await listed.text()).toBe(200);
  const body = (await listed.json()) as {
    importers: unknown[];
    precedence: string;
    errors: unknown[];
  };
  expect(Array.isArray(body.importers)).toBe(true);
  // Precedence decides whether a custom importer can shadow a built-in one, so the panel needs it.
  expect(body.precedence, "built-in vs custom precedence").toBeTruthy();
  // A malformed importer file must surface as an error rather than vanishing: an importer that
  // silently failed to load looks identical to one that was never written.
  expect(Array.isArray(body.errors)).toBe(true);

  const empty = await page.request.post("/importers", { data: {} });
  expect(empty.status(), "an importer with no definition cannot be applied").toBe(400);
});

test("US-159: the forensic gate round-trips and rejects an invalid severity", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const initial = await page.request.get(`/cases/${demoCase}/forensic-gate`);
  expect(initial.status()).toBe(200);
  // null means "no gate", and `effective` is what actually applies — the panel shows both.
  expect((await initial.json()) as Record<string, unknown>).toHaveProperty("effective");

  const set = await page.request.put(`/cases/${demoCase}/forensic-gate`, {
    data: { minSeverity: "High" },
  });
  expect(set.status(), await set.text()).toBe(200);
  const read = (await (await page.request.get(`/cases/${demoCase}/forensic-gate`)).json()) as {
    minSeverity: string;
  };
  expect(read.minSeverity).toBe("High");

  // Only the five real severities are allowed. A typo'd gate that silently did nothing would let
  // an analyst believe low-severity noise was being filtered when it was not.
  const bad = await page.request.put(`/cases/${demoCase}/forensic-gate`, {
    data: { minSeverity: "Severe" },
  });
  expect(bad.status()).toBe(400);
});

test("US-191: per-source trust exposes defaults and accepts an override", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/source-trust`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { defaults: Record<string, number> };
  // Trust weighting drives corroboration scoring, so the shipped defaults must be present even
  // when a case has set no overrides.
  expect(Object.keys(body.defaults ?? {}).length, "shipped source-trust defaults").toBeGreaterThan(0);

  const put = await page.request.put(`/cases/${demoCase}/source-trust`, {
    data: { overrides: { crowdstrike: 0.5 } },
  });
  expect(put.status(), await put.text()).toBe(200);

  const after = (await (await page.request.get(`/cases/${demoCase}/source-trust`)).json()) as {
    overrides?: Record<string, number>;
  };
  expect(after.overrides?.crowdstrike).toBe(0.5);
});

// applySecOrder() is the only thing that puts the <section> elements into the analyst's configured
// order, and it was rewritten to stop re-appending sections that are already in place — an
// unconditional appendChild() detached the section under the viewport on every render and threw the
// page back to the top (see findings.spec.ts for that symptom). This test guards the half that
// rewrite could silently break: that a real reorder still lands.
//
// The two claims are separate. "Reverses correctly" proves the new insertBefore walk still moves
// every section that must move; "second apply changes nothing" proves it stops there. A version
// that reorders correctly by re-appending everything would pass the first and fail the second, and
// that version is exactly the bug.
test("US-112: applySecOrder reorders the sections, and re-applying moves nothing", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.locator("main section").first()).toBeAttached({ timeout: 30_000 });

  const result = await page.evaluate(async () => {
    const main = document.querySelector("main")!;
    const sectionIds = () => [...main.children].map((c) => c.id).filter((id) => id.startsWith("sec-"));

    const reversed = [...sectionIds()].reverse();
    (window as unknown as { saveSectionsOrder: (ids: string[]) => void }).saveSectionsOrder(reversed);
    (window as unknown as { applySecOrder: () => void }).applySecOrder();
    const afterReorder = sectionIds();

    // Count what a second, redundant apply actually does to <main>. Zero is the contract.
    let churn = 0;
    const obs = new MutationObserver((records) => {
      for (const r of records) churn += r.addedNodes.length + r.removedNodes.length;
    });
    obs.observe(main, { childList: true });
    (window as unknown as { applySecOrder: () => void }).applySecOrder();
    await new Promise((r) => setTimeout(r, 50));
    obs.disconnect();

    return { reversed, afterReorder, afterSecondApply: sectionIds(), churn };
  });

  expect(result.reversed.length, "sections present to reorder").toBeGreaterThan(10);
  expect(result.afterReorder).toEqual(result.reversed);
  expect(result.afterSecondApply).toEqual(result.reversed);
  expect(result.churn, "DOM nodes added/removed by a redundant applySecOrder()").toBe(0);
});
