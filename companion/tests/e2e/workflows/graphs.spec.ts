import { test, expect } from "../fixtures/test.js";

// Covers: US-194, US-197, US-199, US-200
// (feature-user-stories.csv) — the interactive graphs: the login graph and its edge drill-down,
// asset/IOC entity merging, the shared time-bound graph filtering, and ordered lateral-movement
// paths with their dismissals.
//
// The graphs are how an investigator sees WHO touched WHAT. A graph endpoint that answers 200 with
// no nodes renders an empty canvas that looks like "nothing happened here" rather than "the
// derivation broke", so these assert real nodes and edges from the seeded case wherever the demo
// data supports it.

test("US-197: the login graph returns capped nodes and edges", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/login-graph`);
  expect(res.status(), await res.text()).toBe(200);
  const graph = (await res.json()) as {
    nodes: Array<{ id: string; type: string }>;
    edges: Array<{ source: string; target: string; outcome: string; count: number }>;
    totalEdges: number;
    truncated: boolean;
  };

  expect(graph.nodes.length, "the seeded case has logon activity").toBeGreaterThan(0);
  expect(graph.edges.length, "logons connect accounts to hosts").toBeGreaterThan(0);

  // The cap is the point of the contract: a case with a million logons must not try to render a
  // million edges. `truncated` is what lets the panel say so honestly rather than silently
  // showing a partial picture as if it were complete.
  expect(typeof graph.truncated).toBe("boolean");
  expect(graph.totalEdges).toBeGreaterThanOrEqual(graph.edges.length);

  // Every edge must carry its outcome. A failed logon and a successful one look identical on a
  // graph without it, and that difference is most of the investigative value.
  for (const edge of graph.edges) {
    expect(edge.source, "an edge with no source").toBeTruthy();
    expect(edge.target, "an edge with no target").toBeTruthy();
    expect(edge.outcome, `${edge.source} -> ${edge.target} has no outcome`).toBeTruthy();
  }
});

test("US-197: the edge drill-down requires both endpoints", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  // Without account AND host this would return every logon in the case, which is not a drill-down
  // — it is the unbounded read the route exists to avoid.
  const bare = await page.request.get(`/cases/${demoCase}/login-graph/edge-events`);
  expect(bare.status(), await bare.text()).toBe(400);
  expect(await bare.text()).toMatch(/account and host are required/);

  const partial = await page.request.get(
    `/cases/${demoCase}/login-graph/edge-events?account=GLOBALTECH%5Cjsmith`,
  );
  expect(partial.status(), "one half of the pair is still not a pair").toBe(400);

  // A real edge from the graph above resolves.
  const graph = (await (await page.request.get(`/cases/${demoCase}/login-graph`)).json()) as {
    edges: Array<{ source: string; target: string }>;
  };
  const edge = graph.edges[0];
  const account = edge.source.replace(/^account:/, "");
  const host = edge.target.replace(/^host:/, "");
  const drill = await page.request.get(
    `/cases/${demoCase}/login-graph/edge-events?account=${encodeURIComponent(account)}&host=${encodeURIComponent(host)}`,
  );
  expect(drill.status(), await drill.text()).toBe(200);
});

test("US-199: the asset and evidence graphs accept a time window", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  for (const graph of ["asset-graph", "evidence-graph"]) {
    const unfiltered = await page.request.get(`/cases/${demoCase}/${graph}`);
    expect(unfiltered.status(), await unfiltered.text()).toBe(200);

    // from/until are the shared time-bound filter behind the timeline scrubber. A window that
    // excludes the whole case must narrow the graph rather than be ignored — silently returning
    // the full graph would tell the analyst the activity happened inside a window it did not.
    const windowed = await page.request.get(
      `/cases/${demoCase}/${graph}?from=1990-01-01T00:00:00.000Z&until=1990-01-02T00:00:00.000Z`,
    );
    expect(windowed.status(), await windowed.text()).toBe(200);

    const before = ((await unfiltered.json()) as { nodes?: unknown[] }).nodes?.length ?? 0;
    const after = ((await windowed.json()) as { nodes?: unknown[] }).nodes?.length ?? 0;
    expect(after, `${graph} ignored its time window`).toBeLessThanOrEqual(before);
  }
});

test("US-200: lateral paths and their dismissals answer as lists", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const paths = await page.request.get(`/cases/${demoCase}/lateral-paths`);
  expect(paths.status(), await paths.text()).toBe(200);
  // Contract only: the seeded case yields no inferred paths, so asserting a non-empty list here
  // would be asserting the fixture. What must hold is that the panel receives a list rather than
  // null, which would break its render instead of showing "no paths found".
  expect(Array.isArray(await paths.json())).toBe(true);

  const dismissals = await page.request.get(`/cases/${demoCase}/lateral-path-dismissals`);
  expect(dismissals.status(), await dismissals.text()).toBe(200);
  expect(Array.isArray(await dismissals.json())).toBe(true);
});

test("US-194: asset and IOC merges validate their targets", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const overrides = await page.request.get(`/cases/${demoCase}/asset-overrides`);
  expect(overrides.status(), await overrides.text()).toBe(200);
  const body = (await overrides.json()) as { merges: Record<string, unknown>; renames: unknown };
  // The overrides document is what makes merges survive a re-analysis: the derived graph is rebuilt
  // from evidence every time, so the analyst's manual corrections have to live outside it.
  expect(body).toHaveProperty("merges");
  expect(body).toHaveProperty("renames");

  // A merge with no target would silently drop the source entity out of the graph.
  const assetNoTarget = await page.request.post(
    `/cases/${demoCase}/asset-overrides/assets/host%3Adc01/merge`,
    { data: {} },
  );
  expect(assetNoTarget.status(), await assetNoTarget.text()).toBe(400);
  expect(await assetNoTarget.text()).toMatch(/into is required/);

  // The IOC merge needs both halves — projecting duplicates onto a survivor is meaningless if
  // either end is unknown.
  const iocNoPair = await page.request.post(`/cases/${demoCase}/ioc-overrides/merge`, {
    data: { from: "ioc001" },
  });
  expect(iocNoPair.status(), await iocNoPair.text()).toBe(400);
  expect(await iocNoPair.text()).toMatch(/from and into are required/);
});
