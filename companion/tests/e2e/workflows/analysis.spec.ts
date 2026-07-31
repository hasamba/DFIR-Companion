import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext } from "@playwright/test";

// Covers: US-042, US-043, US-045, US-046, US-047, US-048, US-136, US-137, US-138, US-139
// Covers: US-140, US-143, US-144, US-145, US-147
// (feature-user-stories.csv) — the analysis surfaces: ask, translate-query, executive summary,
// narrative, synth meta, correlation profile, AI control, remediation plan, AI cost, hypotheses,
// confidence control, anomalies, host ranking, D3FEND and dwell windows.
//
// US-196 (view-summary) is deliberately NOT covered. That endpoint requires the model to return
// structured JSON, and the fixed-prose stub cannot satisfy its schema: the route retries four
// times and answers 500. Testing it would need a prompt-aware stub, which would be mocking the
// product rather than standing in for a provider. See the note in tests/e2e/aiStub.ts.
//
// WHAT AN AI ASSERTION CAN HONESTLY CLAIM HERE. The suite runs against the fixed-reply stub in
// tests/e2e/server-entry.ts, so a live model never answers. Where the stub's prose survives into
// the response — the executive summary does — the test asserts that round trip, because it proves
// the provider call, the plumbing and the store all worked. Where the endpoint parses the reply
// into a structure the stub's plain text cannot satisfy (ask, narrative, remediation plan), the
// test asserts the CONTRACT instead and says so. Asserting text there would be asserting the stub.

/** Turn AI on for the case. It is off by default, and several routes are gated on it. */
async function enableAi(request: APIRequestContext, caseId: string): Promise<void> {
  const res = await request.post(`/cases/${caseId}/ai-control`, { data: { enabled: true } });
  expect(res.status(), await res.text()).toBe(200);
  expect(((await res.json()) as { enabled: boolean }).enabled).toBe(true);
}

interface ReadCase {
  story: string;
  path: string;
  check: (body: unknown) => void;
}

const rec = (b: unknown): Record<string, unknown> => b as Record<string, unknown>;

const READS: readonly ReadCase[] = [
  {
    story: "US-047",
    path: "synth-meta",
    check: (b) => {
      // The "changed since last synthesis" banner is driven by these; without them the dashboard
      // cannot tell the analyst their findings are stale.
      expect(rec(b).lastSynthesizedAt, "when synthesis last ran").toBeTruthy();
      expect(rec(b)).toHaveProperty("lastDiff");
    },
  },
  {
    story: "US-048",
    path: "correlation-profile",
    check: (b) => {
      expect(rec(b).profileName, "correlation profile name").toBeTruthy();
      expect(Number(rec(b).windowSeconds), "correlation window").toBeGreaterThan(0);
    },
  },
  {
    story: "US-138",
    path: "ai-cost",
    check: (b) => {
      // Zero cost is correct here — the stub is free. The panel still needs the accumulator shape,
      // and a missing one renders a blank cost widget rather than "0".
      const vision = rec(rec(b).vision ?? {});
      for (const k of ["totalCalls", "totalCostUSD", "totalInputTokens"]) {
        expect(vision, `vision usage is missing ${k}`).toHaveProperty(k);
      }
    },
  },
  {
    story: "US-140",
    path: "confidence-control",
    check: (b) => {
      // null means "no floor set", which is a legitimate value the control must round-trip.
      expect(rec(b)).toHaveProperty("minConfidence");
    },
  },
  {
    story: "US-143",
    path: "anomalies",
    check: (b) => {
      const rows = rec(b).anomalies as unknown[];
      expect(rows?.length, "the seeded case has burst anomalies").toBeGreaterThan(0);
      // Each candidate must name the asset and window, or the analyst cannot pivot to it.
      expect(JSON.stringify(rows)).toContain("asset");
      expect(JSON.stringify(rows)).toContain("bucketStart");
    },
  },
  {
    story: "US-144",
    path: "host-ranking",
    check: (b) => {
      const ranks = rec(b).ranks as Array<Record<string, unknown>>;
      expect(ranks?.length, "hosts ranked by involvement").toBeGreaterThan(0);
      expect(Number(ranks[0].score), "the top host has a score").toBeGreaterThan(0);
      // Ranking is the point: the first entry must not score below the second.
      if (ranks.length > 1) {
        expect(Number(ranks[0].score)).toBeGreaterThanOrEqual(Number(ranks[1].score));
      }
    },
  },
  {
    story: "US-145",
    path: "d3fend-countermeasures",
    check: (b) => {
      // The bundled D3FEND dataset must load offline; without it the panel is silently empty.
      expect(rec(b).d3fendVersion, "bundled D3FEND dataset version").toBeTruthy();
    },
  },
  {
    story: "US-139",
    path: "hypotheses",
    check: (b) => {
      const rows = b as Array<Record<string, unknown>>;
      expect(rows?.length, "the seeded case ships investigation hypotheses").toBeGreaterThan(0);
      expect(rows[0]).toHaveProperty("title");
    },
  },
];

for (const r of READS) {
  test(`${r.story}: /${r.path} returns usable analysis data`, async ({ page, demoCase }) => {
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
    const res = await page.request.get(`/cases/${demoCase}/${r.path}`);
    expect(res.status(), await res.text()).toBe(200);
    r.check(await res.json());
  });
}

test("US-136: AI can be paused and resumed per case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Off by default — an investigator must opt in before anything is sent to a model.
  const initial = await page.request.get(`/cases/${demoCase}/ai-control`);
  expect(((await initial.json()) as { enabled: boolean }).enabled).toBe(false);

  await enableAi(page.request, demoCase);

  const off = await page.request.post(`/cases/${demoCase}/ai-control`, { data: { enabled: false } });
  expect(((await off.json()) as { enabled: boolean }).enabled).toBe(false);

  // The pause has to persist, or a paused case quietly resumes sending evidence to a provider.
  const after = await page.request.get(`/cases/${demoCase}/ai-control`);
  expect(((await after.json()) as { enabled: boolean }).enabled).toBe(false);
});

test("US-140: the confidence floor round-trips and rejects out-of-range values", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const set = await page.request.put(`/cases/${demoCase}/confidence-control`, {
    data: { minConfidence: 70 },
  });
  expect(set.status(), await set.text()).toBe(200);
  const read = await page.request.get(`/cases/${demoCase}/confidence-control`);
  expect(((await read.json()) as { minConfidence: number }).minConfidence).toBe(70);

  // Out of range must be refused: a floor above 100 hides every finding, which looks like the case
  // has none rather than like a bad setting.
  const bad = await page.request.put(`/cases/${demoCase}/confidence-control`, {
    data: { minConfidence: 500 },
  });
  expect(bad.status()).toBe(400);
});

test("US-147: a dwell window can be created and is listed", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const create = await page.request.post(`/cases/${demoCase}/dwell-windows`, {
    data: {
      label: "e2e dwell window",
      start: "2026-05-15T08:00:00.000Z",
      end: "2026-05-19T23:00:00.000Z",
    },
  });
  expect([200, 201], await create.text()).toContain(create.status());

  const listed = await page.request.get(`/cases/${demoCase}/dwell-windows`);
  expect(await listed.text()).toContain("e2e dwell window");
});

test("US-045: the executive summary carries the provider's answer through to the report", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await enableAi(page.request, demoCase);

  const res = await page.request.post(`/cases/${demoCase}/executive-summary`, { data: {} });
  expect(res.status(), await res.text()).toBe(200);
  const summary = ((await res.json()) as { summary: string }).summary;

  // The one AI route whose reply survives as prose, so this is a genuine end-to-end check of the
  // provider call rather than a shape assertion: the stub's text has to come back out.
  expect(summary, "the provider's reply must reach the summary").toContain("Stubbed");
});

test("US-042: ask answers with a grounded-answer envelope", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await enableAi(page.request, demoCase);

  const res = await page.request.post(`/cases/${demoCase}/ask`, {
    data: { question: "How did the attacker first get in?" },
  });
  expect(res.status(), await res.text()).toBe(200);

  // Contract, not content: the stub's plain prose cannot satisfy the grounded-answer parser, so
  // `answer` is legitimately empty here. What must hold is that every answer arrives with its
  // provenance fields — an answer with no pointer or related events is an ungrounded claim, which
  // is the thing this endpoint exists not to produce.
  const body = rec(await res.json());
  for (const k of ["answer", "status", "pointer", "relatedEventIds"]) {
    expect(body, `a grounded answer must carry ${k}`).toHaveProperty(k);
  }
});

test("US-043: translate-query refuses an empty request and answers a real one", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await enableAi(page.request, demoCase);

  const empty = await page.request.post(`/cases/${demoCase}/translate-query`, { data: {} });
  expect(empty.status(), "an empty request cannot be translated").toBe(400);

  const res = await page.request.post(`/cases/${demoCase}/translate-query`, {
    data: { request: "failed logons on DC01 in the last 24 hours" },
  });
  expect(res.status(), await res.text()).toBe(200);
});

test("US-046, US-137: narrative and remediation plan answer with their envelopes", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await enableAi(page.request, demoCase);

  // Contract only, same reason as ask: both parse the reply into a structure the stub's fixed
  // prose does not produce. The envelope is still what the panel binds to.
  const narrative = await page.request.post(`/cases/${demoCase}/narrative`, { data: {} });
  expect(narrative.status(), await narrative.text()).toBe(200);
  expect(rec(await narrative.json())).toHaveProperty("narrativeTimeline");

  const plan = await page.request.post(`/cases/${demoCase}/remediation-plan`, { data: {} });
  expect(plan.status(), await plan.text()).toBe(200);
  expect(rec(await plan.json())).toHaveProperty("plan");
});
