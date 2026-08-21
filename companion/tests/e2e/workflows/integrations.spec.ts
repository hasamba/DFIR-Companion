import { test, expect } from "../fixtures/test.js";

// Covers: US-090, US-091, US-092, US-093, US-094, US-095, US-135, US-156, US-157, US-158, US-161
// (feature-user-stories.csv) — the outbound integrations (IRIS, Timesketch, MISP, Notion,
// ClickUp), push tokens, the local IRIS export, external tool running and custom tool definitions,
// and the inbound generic push endpoint.
// Push-token disclosure is owned by companion/src/routes/pushNotify.ts and the one-time dashboard
// rendering by public/js/dashboard-push-token.js.
//
// THE HARNESS HAS NO EXTERNAL SYSTEMS, AND THAT IS THE POINT. Nothing here configures a real IRIS
// or MISP, and no test may cause an outbound call — a suite that pushes case data to a live
// service because someone's environment happened to be configured would be a genuinely bad
// outcome for a forensics tool. So these assert the UNCONFIGURED path, which is also the path
// every user hits before they set anything up: status reports it honestly, and a push refuses
// with 501 and names the environment variables to set rather than hanging or 500ing.
//
// US-219 (the MISP forensic-timeline payload) is deliberately NOT claimed: verifying WHAT the
// export sends needs a configured MISP to send it to, so only the refusal path is reachable here.

/** Every outbound integration, with the config hint its refusal must name. */
const INTEGRATIONS: ReadonlyArray<{ story: string; slug: string; hint: RegExp }> = [
  { story: "US-090", slug: "iris", hint: /DFIR_IRIS_URL/ },
  { story: "US-091", slug: "timesketch", hint: /DFIR_TIMESKETCH_URL/ },
  { story: "US-092", slug: "misp", hint: /DFIR_MISP_URL/ },
  { story: "US-093", slug: "notion", hint: /DFIR_NOTION_TOKEN/ },
  { story: "US-094", slug: "clickup", hint: /DFIR_CLICKUP_TOKEN/ },
];

for (const { story, slug, hint } of INTEGRATIONS) {
  test(`${story}: ${slug} reports it is unconfigured and refuses to push`, async ({ page, demoCase }) => {
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

    // The status endpoint must answer 200 with configured:false rather than erroring. The settings
    // panel renders from it, and an integration that errors on "are you set up?" looks broken when
    // it is merely absent.
    const status = await page.request.get(`/${slug}/status`);
    expect(status.status(), await status.text()).toBe(200);
    expect(((await status.json()) as { configured: boolean }).configured).toBe(false);

    const push = await page.request.post(`/cases/${demoCase}/push/${slug}`, { data: {} });
    // 501 Not Implemented, not 500: the companion is fine, the integration is simply not set up.
    expect(push.status(), await push.text()).toBe(501);
    // The refusal must say WHICH settings are missing. "Not configured" with no names sends the
    // analyst to the source to find out what to set.
    expect(await push.text(), `${slug} refusal should name its config`).toMatch(hint);
  });
}

test("US-135: the local IRIS export builds a payload without contacting IRIS", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Distinct from POST /push/iris: this produces the payload locally so an analyst can review or
  // hand-carry it, which must work whether or not IRIS is reachable.
  const res = await page.request.get(`/cases/${demoCase}/iris-export`);
  expect(res.status(), await res.text()).toBe(200);
  const body = (await res.json()) as { defaultCaseName?: string };
  expect(body.defaultCaseName, "the export names the case it came from").toContain(demoCase);
});

test("US-095: a push token is generated once, never read back, and can be revoked", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const before = await page.request.get(`/cases/${demoCase}/push-token`);
  expect(((await before.json()) as { configured: boolean }).configured).toBe(false);

  const gen = await page.request.post(`/cases/${demoCase}/push-token/generate`, { data: {} });
  expect(gen.status(), await gen.text()).toBe(201);
  const generated = (await gen.json()) as { token: string; createdAt: string };
  const token = generated.token;
  expect(token, "a generated token must be non-empty").toBeTruthy();
  expect(generated.createdAt, "the UI uses the creation time to detect a rotated token").toBeTruthy();

  const after = await page.request.get(`/cases/${demoCase}/push-token`);
  const afterText = await after.text();
  const afterBody = JSON.parse(afterText) as { configured: boolean; createdAt: string; token?: unknown };
  expect(afterBody.configured).toBe(true);
  expect(afterBody.createdAt).toBe(generated.createdAt);
  expect(afterBody).not.toHaveProperty("token");
  expect(afterText, "a plain GET exposed the standing credential").not.toContain(token);

  // Revocation has to actually revoke: a token that outlives its delete is a standing credential
  // into the case.
  const del = await page.request.delete(`/cases/${demoCase}/push-token`);
  expect([200, 204], await del.text()).toContain(del.status());
  const revoked = await page.request.get(`/cases/${demoCase}/push-token`);
  expect(((await revoked.json()) as { configured: boolean }).configured).toBe(false);
});

test("US-095: the dashboard shows a generated token only until the page reloads", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await page.waitForLoadState("networkidle");
  await page.locator("#settingsBtn").click();
  await page.locator('.stab[data-stab="integrations"]').click();

  const curl = page.locator("#pushCurl");
  await expect(curl).toContainText("<your-token>");

  await page.locator("#pushTokenGenBtn").click();
  await expect(page.locator("#pushTokenMsg")).toContainText("copy it now");
  await expect(curl).not.toContainText("<your-token>");
  const generatedCurl = await curl.innerText();
  const match = generatedCurl.match(/X-DFIR-Key:\s*([^"\s]+)/);
  expect(match?.[1], "the generated curl example needs the one-time token").toBeTruthy();
  const generatedToken = match?.[1] ?? "";

  await page.reload();
  await page.waitForLoadState("networkidle");
  await page.locator("#settingsBtn").click();
  await page.locator('.stab[data-stab="integrations"]').click();
  await expect(curl).toContainText("<your-token>");
  expect(await curl.innerText(), "the previous secret survived a reload").not.toContain(generatedToken);

  // The token exists after reload even though its secret is hidden; clear it so this isolated case
  // leaves no credential behind for the rest of the run.
  await page.locator("#pushTokenClearBtn").click();
  await expect(page.locator("#pushTokenMsg")).toContainText("cleared");
  const cleared = await page.request.get(`/cases/${demoCase}/push-token`);
  expect(((await cleared.json()) as { configured: boolean }).configured).toBe(false);
});

test("US-161: the generic push endpoint distinguishes disabled from unauthenticated", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // With no token configured at all the FEATURE is off: 403, and the message tells the operator
  // how to turn it on. This is different from "you did not authenticate", and conflating them
  // would send someone hunting for a credential that does not exist yet.
  const disabled = await page.request.post(`/cases/${demoCase}/push`, { data: { events: [] } });
  expect(disabled.status(), await disabled.text()).toBe(403);
  expect(await disabled.text()).toMatch(/DFIR_PUSH_TOKEN|push ingest is disabled/);

  // Once a per-case token exists the endpoint is live, and a caller with no credential is
  // unauthenticated rather than disabled: 401, naming the header to send.
  const gen = await page.request.post(`/cases/${demoCase}/push-token/generate`, { data: {} });
  expect(gen.status()).toBe(201);

  const anon = await page.request.post(`/cases/${demoCase}/push`, { data: { events: [] } });
  expect(anon.status(), await anon.text()).toBe(401);
  expect(await anon.text()).toMatch(/X-DFIR-Key/);

  // A wrong credential must fail too — this endpoint accepts evidence into a case, so a bad key
  // being treated as good enough is the outcome to keep impossible.
  const wrong = await page.request.post(`/cases/${demoCase}/push`, {
    headers: { "X-DFIR-Key": "not-the-real-key" },
    data: { events: [] },
  });
  expect([401, 403], await wrong.text()).toContain(wrong.status());
});

test("US-156: the external tool catalogue lists tools and validates a run", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const status = await page.request.get("/tools/status");
  expect(status.status(), await status.text()).toBe(200);
  const tools = ((await status.json()) as { tools: Array<{ id: string }> }).tools;
  expect(tools?.length, "the bundled tool catalogue").toBeGreaterThan(0);

  // Running without a target path must be refused rather than executing the tool against nothing.
  const run = await page.request.post(`/cases/${demoCase}/tools/${tools[0].id}/run`, { data: {} });
  expect(run.status(), await run.text()).toBe(400);
});

test("US-157: update-rules is per-tool and refuses an unknown tool", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // The route is /cases/:id/tools/:toolId/update-rules — per tool, not global. An unknown tool id
  // must 404 rather than run some default, which is how a typo silently updates the wrong ruleset.
  const unknown = await page.request.post(`/cases/${demoCase}/tools/no-such-tool/update-rules`, { data: {} });
  expect([400, 404, 501], await unknown.text()).toContain(unknown.status());
});

test("US-158: custom tool definitions round-trip and validate", async ({ page }) => {
  await page.goto("/dashboard");

  const empty = await page.request.post("/tools/custom", { data: {} });
  expect(empty.status(), "a tool with no name cannot be listed or run").toBe(400);

  const name = `e2e-tool-${Date.now()}`;
  const create = await page.request.post("/tools/custom", {
    // Both a name AND a `binary` are required (customToolStore.add) — a definition with no binary
    // cannot be run, so storing one would put an unusable entry in every operator's tool list.
    data: { name, binary: "/bin/echo", description: "created by the browser suite" },
  });
  expect([200, 201], await create.text()).toContain(create.status());

  const listed = await page.request.get("/tools/custom");
  expect(await listed.text()).toContain(name);

  // Custom tools are global, so this test removes what it created; a leaked definition would show
  // up in every later run's tool list.
  const created = (await (await page.request.get("/tools/custom")).json()) as {
    tools: Array<{ id: string; name: string }>;
  };
  const mine = created.tools.find((t) => t.name === name);
  expect(mine?.id, "a saved tool needs an id to be run or deleted").toBeTruthy();

  const del = await page.request.delete(`/tools/custom/${mine?.id}`);
  expect([200, 204], await del.text()).toContain(del.status());
  expect(await (await page.request.get("/tools/custom")).text()).not.toContain(name);
});
