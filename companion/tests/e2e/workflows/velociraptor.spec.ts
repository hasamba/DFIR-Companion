import { test, expect } from "../fixtures/test.js";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-097, US-098, US-099, US-100, US-101, US-102, US-103, US-104, US-160, US-214, US-362
// (feature-user-stories.csv) — VQL execution, clients, hunt deploy, collection, monitors, triage
// bundles, hunt suggestions, status/diagnostics, external VQL import, bundle time scoping, and the
// live-snapshot choice on an AI-suggested hunt (US-362).
//
// TWO ADDITIONS PAST THE ORIGINAL SUITE, both post-dating a fresh Sigma → hunt baseline (#801):
//
//   #843/#853 — a bundle's per-artifact WHERE filter is inlined as `WHERE (${filter})`, so a filter
//   able to close that parenthesis or carry a `;`/comment could smuggle a second statement into the
//   read. The SAVE-time refusal (POST /bundles) is local — no server needed — so it is testable
//   here; the matching refusal at hunt/collection READ time needs a configured Velociraptor client
//   and is covered instead by tests/analysis/artifactBundleStore.test.ts.
//
//   #809 — an AI-suggested fleet/playbook hunt now carries a "live snapshot (empty ≠ miss)"
//   checkbox beside Deploy. The renderer, the reader and the ctx-builder are pure functions already
//   proven by tests/dashboard/huntSnapshotToggle.test.ts against a FAKE container, which is exactly
//   what leaves a gap: whether they are wired together correctly in the real page. The real
//   suggestion flow needs the AI to return structured VQL, which the stub cannot do (see US-103
//   above), so this drives the real renderer (window.renderVeloHuntSuggest) with synthetic
//   suggestions instead of a live suggestion call — the same "seed data directly, skip the
//   non-deterministic AI" approach the rest of this suite already uses for synthesis.
// No Velociraptor server is configured here, and none may be: this endpoint family runs VQL on
// real endpoints and deploys hunts across a fleet, so a test suite that reached a live server
// would be executing code on someone's estate. What is asserted is the UNCONFIGURED contract —
// which is also what an operator sees before they wire up an API config — plus the parts that are
// genuinely local.
//
// Two shapes, and the difference matters to the dashboard:
//   * status and clients answer 200 with an empty/false payload, because their panels render on
//     every page load and must not error merely because the integration is absent.
//   * everything that would TALK to Velociraptor answers 501 naming DFIR_VELOCIRAPTOR_API_CONFIG.
//
// NOTED WHILE WRITING THIS, not a test failure: /cases/:id/velociraptor/import-external is gated
// on the API config too. Importing results that were collected ELSEWHERE is the one operation in
// this family that needs no live server, so an analyst handed an offline collection cannot ingest
// it without also configuring an API they are not going to call. Worth a look; the test asserts
// today's behaviour rather than the behaviour I would expect.

/** Everything that would reach a Velociraptor server. All must refuse identically. */
const NEEDS_SERVER: ReadonlyArray<{ story: string; method: "get" | "post"; path: string }> = [
  { story: "US-097", method: "post", path: "/velociraptor/run" },
  { story: "US-099", method: "post", path: "/cases/CASE/velociraptor/deploy-hunt" },
  { story: "US-100", method: "post", path: "/cases/CASE/velociraptor/collect" },
  { story: "US-101", method: "post", path: "/cases/CASE/velociraptor/monitors/auto" },
  { story: "US-104", method: "get", path: "/velociraptor/diag" },
  { story: "US-104", method: "get", path: "/velociraptor/artifacts" },
  { story: "US-160", method: "post", path: "/cases/CASE/velociraptor/import-external" },
  { story: "US-214", method: "post", path: "/velociraptor/bundles/best-practice/time-scope-preview" },
];

for (const { story, method, path } of NEEDS_SERVER) {
  test(`${story}: ${method.toUpperCase()} ${path} refuses without an API config`, async ({
    page,
    demoCase,
  }) => {
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
    const url = path.replace("CASE", demoCase);

    const res = method === "get" ? await page.request.get(url) : await page.request.post(url, { data: {} });

    // 501, not 500: nothing is broken, the integration is simply not set up. And the message must
    // name the setting, or an operator has to read the source to discover what is missing.
    expect(res.status(), await res.text()).toBe(501);
    expect(await res.text()).toMatch(/DFIR_VELOCIRAPTOR_API_CONFIG/);
  });
}

test("US-103: hunt suggestions are produced without a Velociraptor server", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Unlike the rest of this family, suggest-hunts never talks to Velociraptor: it asks the MODEL
  // to propose fleet VQL from the case's findings, so it works before any server is wired up —
  // which is the point, since you suggest hunts in order to decide whether to deploy them.
  const res = await page.request.post(`/cases/${demoCase}/velociraptor/suggest-hunts`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { suggestions: unknown[] };
  // Empty against the fixed-prose stub, which cannot produce structured VQL. The envelope is what
  // the panel binds to, so that is what is asserted.
  expect(Array.isArray(body.suggestions)).toBe(true);
});

test("US-104: status answers without a server so the panel can render", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get("/velociraptor/status");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { configured: boolean; clients: number };
  // Deliberately NOT a 501: this drives an always-visible panel, so it reports absence as data.
  expect(body.configured).toBe(false);
  expect(body.clients).toBe(0);
});

test("US-098: the client list answers empty rather than erroring", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get("/velociraptor/clients");
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { clients: unknown[] };
  // The list is served from cache, so it must come back as an empty array — a null here would
  // break the panel's render rather than showing "no clients".
  expect(Array.isArray(body.clients)).toBe(true);
  expect(body.clients).toHaveLength(0);
});

test("US-102: triage bundles ship built-ins and accept a custom one", async ({ page }) => {
  await page.goto("/dashboard");

  const listed = await page.request.get("/bundles");
  expect(listed.status(), await listed.text()).toBe(200);
  const bundles = (await listed.json()) as Array<{ id: string; builtIn?: boolean }>;
  // Bundles are local — they describe WHICH artifacts to collect, so they exist without a server.
  expect(bundles.length, "the bundled triage presets").toBeGreaterThan(0);
  expect(
    bundles.some((b) => b.builtIn),
    "at least one built-in preset",
  ).toBe(true);

  const empty = await page.request.post("/bundles", { data: {} });
  expect(empty.status(), "an unnamed bundle is unselectable").toBe(400);

  const name = `e2e-bundle-${Date.now()}`;
  const create = await page.request.post("/bundles", {
    data: { name, description: "created by the browser suite", artifacts: ["Windows.KapeFiles.Targets"] },
  });
  expect([200, 201], await create.text()).toContain(create.status());

  const after = (await (await page.request.get("/bundles")).json()) as Array<{
    id: string;
    name: string;
  }>;
  const mine = after.find((b) => b.name === name);
  expect(mine?.id, "a saved bundle needs an id to be run or deleted").toBeTruthy();

  // Bundles are global, so this removes what it created rather than leaving it in every later run.
  const del = await page.request.delete(`/bundles/${mine?.id}`);
  expect([200, 204], await del.text()).toContain(del.status());
  expect(await (await page.request.get("/bundles")).text()).not.toContain(name);
});

test("US-102: a built-in bundle cannot be deleted", async ({ page }) => {
  await page.goto("/dashboard");

  const bundles = (await (await page.request.get("/bundles")).json()) as Array<{
    id: string;
    builtIn?: boolean;
  }>;
  const builtIn = bundles.find((b) => b.builtIn);
  expect(builtIn?.id).toBeTruthy();

  // Deleting a shipped preset would leave the operator unable to get it back without reinstalling.
  // The route does not refuse — it answers 204 — but it does NOT remove the built-in, so the
  // no-op is the contract worth pinning, not the status code.
  const del = await page.request.delete(`/bundles/${builtIn?.id}`);
  expect([200, 204], await del.text()).toContain(del.status());

  const after = await page.request.get("/bundles");
  expect(await after.text(), "the built-in survived the delete attempt").toContain(String(builtIn?.id));
});

test("US-102: a bundle's WHERE filter must be one contained boolean expression (#843)", async ({ page }) => {
  await page.goto("/dashboard");

  const name = `e2e-bundle-filter-${Date.now()}`;
  // Straight from the source comment (vqlInput.ts) describing the attack this closes: closes the
  // wrapper's own `(`, then a `;` starts a second statement — either alone is enough to refuse.
  const malicious = "x) LIMIT 1; SELECT * FROM execve(argv=['sh', '-c', 'id']) WHERE (1=1";
  const refused = await page.request.post("/bundles", {
    data: {
      name,
      artifacts: ["Windows.KapeFiles.Targets"],
      filters: { "Windows.KapeFiles.Targets": malicious },
    },
  });
  expect(refused.status(), await refused.text()).toBe(400);
  const refusedBody = await refused.text();
  // Named by the artifact it applies to — the analyst has to know which of several filters broke it.
  expect(refusedBody).toMatch(/invalid WHERE filter/i);
  expect(refusedBody).toContain("Windows.KapeFiles.Targets");

  // Refused, not accepted-then-silently-dropped: the bundle must never have been saved at all.
  expect(await (await page.request.get("/bundles")).text()).not.toContain(name);

  // A real filter — one contained boolean expression — still saves normally, so the check refuses
  // the shape of an escape attempt rather than filters in general.
  const clean = await page.request.post("/bundles", {
    data: {
      name,
      artifacts: ["Windows.KapeFiles.Targets"],
      filters: { "Windows.KapeFiles.Targets": "Size > 100 AND (Name =~ 'a' OR Name =~ 'b')" },
    },
  });
  expect(clean.status(), await clean.text()).toBe(201);
  const saved = (await clean.json()) as { id: string };

  const after = (await (await page.request.get("/bundles")).json()) as Array<{ name: string }>;
  expect(
    after.some((b) => b.name === name),
    "the well-formed filter must have been saved",
  ).toBe(true);

  await page.request.delete(`/bundles/${saved.id}`);
});

test("US-362: an AI-suggested hunt's live-snapshot checkbox reflects its VQL and rides the deploy request (#809)", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await revealSections(page, "sec-velohunts");

  type SnapshotCtx = Record<string, unknown>;
  type Win = {
    renderVeloHuntSuggest: (
      s: Array<{ title: string; vql: string; severity: string; mitreTechniques: string[] }>,
    ) => void;
    huntSnapshotCtx: (container: Element | null, cls: string, idx: number) => SnapshotCtx;
  };

  // Bypasses the AI suggestion call entirely (the stub cannot return structured VQL — see US-103
  // above) and drives the real production renderer with one live-state query and one event-backed
  // one, exactly the distinction huntSnapshotToggleHtml is meant to draw.
  const defaults = await page.evaluate(() => {
    (window as unknown as Win).renderVeloHuntSuggest([
      {
        title: "live pslist sweep",
        vql: "SELECT Name, CommandLine FROM pslist() WHERE Name =~ 'x'",
        severity: "High",
        mitreTechniques: [],
      },
      {
        title: "evtx logon sweep",
        vql: "SELECT * FROM parse_evtx(filename='C:/x.evtx')",
        severity: "Medium",
        mitreTechniques: [],
      },
    ]);
    const container = document.getElementById("veloHuntSuggest");
    return {
      live: (window as unknown as Win).huntSnapshotCtx(container, "vhs-snapshot", 0),
      event: (window as unknown as Win).huntSnapshotCtx(container, "vhs-snapshot", 1),
    };
  });
  // huntSnapshotCtx read the REAL rendered checkbox, not a mock — the wiring the module unit test
  // (huntSnapshotToggle.test.ts) cannot prove because it hands the reader a fake container.
  expect(defaults.live, "a live-state-only query is ticked by default").toEqual({ coverage: "snapshot" });
  expect(defaults.event, "an event-backed query is not").toEqual({});

  const liveBox = page.locator('.vhs-snapshot[data-idx="0"]');
  const eventBox = page.locator('.vhs-snapshot[data-idx="1"]');
  await expect(liveBox).toBeChecked();
  await expect(eventBox).not.toBeChecked();
  await expect(page.locator(".vhs-card").first()).toContainText(/empty ≠ miss/);

  // The analyst can override either way; the deploy handler reads whatever is on the page, not the
  // VQL-derived default, at the moment Deploy is clicked.
  await liveBox.uncheck();
  await eventBox.check();

  const afterToggle = await page.evaluate(() => {
    const container = document.getElementById("veloHuntSuggest");
    return {
      live: (window as unknown as Win).huntSnapshotCtx(container, "vhs-snapshot", 0),
      event: (window as unknown as Win).huntSnapshotCtx(container, "vhs-snapshot", 1),
    };
  });
  expect(afterToggle.live, "unticking drops the coverage flag").toEqual({});
  expect(afterToggle.event, "ticking adds it").toEqual({ coverage: "snapshot" });
});
