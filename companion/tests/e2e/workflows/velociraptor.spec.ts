import { test, expect } from "../fixtures/test.js";

// Covers: US-097, US-098, US-099, US-100, US-101, US-102, US-103, US-104, US-160, US-214
// (feature-user-stories.csv) — VQL execution, clients, hunt deploy, collection, monitors, triage
// bundles, hunt suggestions, status/diagnostics, external VQL import and bundle time scoping.
//
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
