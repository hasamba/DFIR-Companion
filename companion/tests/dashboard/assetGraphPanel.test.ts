import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The generation-token race guard (commit 8f10ebd3). When an analyst switches cases fast, a stale
// request's late response — success OR failure — must not overwrite the newer case's graph, and
// the LATEST load's failure must clear the cached graph instead of leaving the previous case's
// assets on screen with hasAssetGraph() wrongly true. Both failure arms matter: an HTTP error
// takes the fulfilled branch, but a network-level rejection (the companion restarting mid-switch)
// or a malformed 2xx body REJECTS, and a bare `.catch(() => {})` there restored the stale
// cross-case graph the token exists to prevent.

interface AssetGraphApi {
  loadAssetGraph(id: string): void;
  hasAssetGraph(): boolean;
  assetGraphAssets(): Array<{ name: string }>;
}

interface PendingFetch {
  url: string;
  resolve(response: unknown): void;
  reject(reason: unknown): void;
}

// A fetch stub whose responses are settled BY THE TEST, in the order the test chooses — the whole
// point is answering request A after request B.
function deferredFetch() {
  const pending: PendingFetch[] = [];
  const fetch = (url: string) =>
    new Promise((resolve, reject) => {
      pending.push({ url, resolve, reject });
    });
  return { pending, fetch };
}

// One macrotask turn, so every already-settled promise chain runs to completion.
const drain = () => new Promise((r) => setImmediate(r));

function graphPanel(fetchStub: unknown) {
  return loadDashboardModule<AssetGraphApi>("dashboard-asset-graph.js", ["dashboard-escape.js"], {
    fetch: fetchStub,
    // The renderers write into whatever element they find; the module must stay load-clean and
    // render-safe against a bare stub — no DfirGraphView means the "library not loaded" text path.
    document: {
      getElementById: () => ({ innerHTML: "", textContent: "", style: {} }),
      querySelectorAll: () => [],
    },
    DfirTimelineView: { timeQuery: () => "" },
  });
}

function graphFor(name: string) {
  return {
    assets: [{ id: `host:${name}`, name, type: "host", compromised: false }],
    iocs: [],
    edges: [],
  };
}

function okGraph(name: string) {
  return { ok: true, json: async () => graphFor(name) };
}

describe("asset graph case-switch race (generation token)", () => {
  it("ignores a stale load's late success — the newer case's graph survives", async () => {
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    p.loadAssetGraph("case-b");
    pending[1].resolve(okGraph("b-host"));
    await drain();
    expect(p.hasAssetGraph()).toBe(true);
    pending[0].resolve(okGraph("a-host"));
    await drain();
    expect(p.assetGraphAssets().map((a) => a.name)).toEqual(["b-host"]);
    expect(p.hasAssetGraph()).toBe(true);
  });

  it("ignores a stale load's late HTTP failure — the newer case's graph survives", async () => {
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    p.loadAssetGraph("case-b");
    pending[1].resolve(okGraph("b-host"));
    await drain();
    pending[0].resolve({ ok: false, status: 500, json: async () => ({ error: "boom" }) });
    await drain();
    expect(p.assetGraphAssets().map((a) => a.name)).toEqual(["b-host"]);
  });

  it("ignores a stale load's late network rejection — the newer case's graph survives", async () => {
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    p.loadAssetGraph("case-b");
    pending[1].resolve(okGraph("b-host"));
    await drain();
    pending[0].reject(new Error("network down"));
    await drain();
    expect(p.assetGraphAssets().map((a) => a.name)).toEqual(["b-host"]);
    expect(p.hasAssetGraph()).toBe(true);
  });

  it("clears the previous case's graph when the latest load fails with an HTTP error", async () => {
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    pending[0].resolve(okGraph("a-host"));
    await drain();
    expect(p.hasAssetGraph()).toBe(true);
    p.loadAssetGraph("case-b");
    // The error body must never be cached as graph data — hasAssetGraph() trusts the cache.
    pending[1].resolve({ ok: false, status: 500, json: async () => ({ error: "boom" }) });
    await drain();
    expect(p.hasAssetGraph()).toBe(false);
    expect(p.assetGraphAssets()).toEqual([]);
  });

  it("clears the previous case's graph when the latest load REJECTS at the network level", async () => {
    // The arm the bare `.catch(() => {})` used to skip: a rejected fetch never reaches the
    // fulfilled branch, so without seq-guarded clearing in the catch, case A's assets stayed
    // rendered under case B and hasAssetGraph() kept answering true.
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    pending[0].resolve(okGraph("a-host"));
    await drain();
    expect(p.hasAssetGraph()).toBe(true);
    p.loadAssetGraph("case-b");
    pending[1].reject(new Error("ECONNREFUSED"));
    await drain();
    expect(p.hasAssetGraph()).toBe(false);
    expect(p.assetGraphAssets()).toEqual([]);
  });

  it("clears when the latest load's 2xx body is malformed (json() rejects)", async () => {
    const { pending, fetch } = deferredFetch();
    const p = graphPanel(fetch);
    p.loadAssetGraph("case-a");
    pending[0].resolve(okGraph("a-host"));
    await drain();
    p.loadAssetGraph("case-b");
    pending[1].resolve({
      ok: true,
      json: async () => {
        throw new Error("unexpected end of JSON input");
      },
    });
    await drain();
    expect(p.hasAssetGraph()).toBe(false);
    expect(p.assetGraphAssets()).toEqual([]);
  });
});
