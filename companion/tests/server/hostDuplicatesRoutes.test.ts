import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import express from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { registerHostDuplicateRoutes } from "../../src/routes/hostDuplicates.js";
import type { RouteContext } from "../../src/routes/context.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";

let app: ReturnType<typeof createApp>;
let assetOverridesStore: AssetOverridesStore;

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-routes-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);
  assetOverridesStore = new AssetOverridesStore(cases);
  app = createApp(cases, {
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
  });
});

describe("/cases/:id/host-duplicates", () => {
  it("lists the unresolved pair", async () => {
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.status).toBe(200);
    expect(res.body.pending).toHaveLength(1);
    expect(res.body.pending[0].canonical).toBe("win11.windomain.local");
  });

  it("merging clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("merges the short name INTO the fqdn, not the reverse", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const overrides = await assetOverridesStore.load("c1");
    // fromId (the duplicate being folded away) -> intoId (the surviving canonical id). A reversed
    // call would instead fold the FQDN into the short name and record the opposite key/value.
    expect(overrides.merges).toEqual({ "host:win11": "host:win11.windomain.local" });
  });

  it("dismissing clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("a dismissal persists across requests", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.body.pending).toEqual([]);
  });

  it("rejects a request missing a host", async () => {
    const res = await request(app).post("/cases/c1/host-duplicates/merge").send({ canonical: "a.corp" });
    expect(res.status).toBe(400);
  });

  it("rejects a merge of a host into itself", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11", other: "win11" });
    expect(res.status).toBe(400);
  });
});

describe("/cases/:id/host-duplicates/dismissed — per-pair undo (#1170)", () => {
  it("lists an empty dismissed set before anything is dismissed", async () => {
    const res = await request(app).get("/cases/c1/host-duplicates/dismissed");
    expect(res.status).toBe(200);
    expect(res.body.dismissed).toEqual([]);
  });

  it("lists a dismissal after dismissing, then undoing it removes exactly that one", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const listed = await request(app).get("/cases/c1/host-duplicates/dismissed");
    expect(listed.body.dismissed).toHaveLength(1);
    expect(listed.body.dismissed[0]).toMatchObject({ canonical: "win11.windomain.local", other: "win11" });

    const undo = await request(app)
      .delete("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(undo.status).toBe(200);
    expect(undo.body.dismissed).toEqual([]);
    // The pair is eligible again — the pending list is derived, never cached.
    expect(undo.body.pending).toHaveLength(1);
    expect(undo.body.pending[0]).toMatchObject({ canonical: "win11.windomain.local", other: "win11" });
  });

  it("undoing one dismissal never touches a different pair's own dismissal", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-undo-two-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.windomain.local"),
      ev("c", "DC01"),
      ev("d", "DC01.corp.local"),
    );
    await stateStore.save(s);
    const twoPairApp = createApp(cases, {
      stateStore,
      assetOverridesStore: new AssetOverridesStore(cases),
      hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
    });
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "dc01.corp.local", other: "dc01" });

    const undo = await request(twoPairApp)
      .delete("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(undo.body.dismissed).toHaveLength(1);
    expect(undo.body.dismissed[0]).toMatchObject({ canonical: "dc01.corp.local", other: "dc01" });
  });

  it("returns 404, not 200, for a pair that was never dismissed", async () => {
    const res = await request(app)
      .delete("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(404);
  });

  it("rejects a malformed undo request the same way dismiss does", async () => {
    const res = await request(app).delete("/cases/c1/host-duplicates/dismiss").send({ canonical: "a.corp" });
    expect(res.status).toBe(400);
  });

  it("never kicks a resynthesis on undo — re-arming the gate is the correct outcome, not a resume", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-undo-kick-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
    await stateStore.save(s);
    const dismissals = new HostDuplicateDismissalStore(cases);
    const kick = vi.fn();
    const kickApp = express();
    kickApp.use(express.json());
    registerHostDuplicateRoutes(kickApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: dismissals,
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);
    await request(kickApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    kick.mockClear(); // the dismiss above already kicked once, legitimately (the gate cleared)
    await request(kickApp)
      .delete("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(kick).not.toHaveBeenCalled();
  });
});

function logonEvent(id: string, sessionHost: string, clientName: string, ip: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-10T12:00:00Z",
    description: `Windows Security logon @ ${sessionHost}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: sessionHost,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: sessionHost },
      authentication: { logonType: 3 },
      session: { terminal: clientName },
      network: { source: { address: ip, provenance: "edge-observed" } }, // #1292: the stamp every real 4624 writer carries
      time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
      evidence: { rawRecords: [{ source: "test", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("/cases/:id/host-duplicates — network-identity candidates (#1163)", () => {
  it("lists an IP-named host alongside a name-spelling pair, and merge/dismiss both work", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-netid-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.windomain.local"),
      ev("c", "10.0.0.5"),
      logonEvent("d", "fs-01", "ws-042", "10.0.0.5"),
    );
    await stateStore.save(s);
    const netIdApp = createApp(cases, {
      stateStore,
      assetOverridesStore: new AssetOverridesStore(cases),
      hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
    });

    const list = await request(netIdApp).get("/cases/c1/host-duplicates");
    expect(list.status).toBe(200);
    const reasons = list.body.pending.map((p: { reason: string }) => p.reason).sort();
    expect(reasons).toEqual(["network-identity", "shortname-fqdn"]);
    const netId = list.body.pending.find((p: { reason: string }) => p.reason === "network-identity");
    expect(netId).toMatchObject({ canonical: "ws-042", other: "10.0.0.5" });
    expect(netId.sampleTime).toBe("2026-06-10T12:00:00Z");

    const merge = await request(netIdApp)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "ws-042", other: "10.0.0.5" });
    expect(merge.status).toBe(200);
    expect(merge.body.pending).toHaveLength(1); // the unrelated shortname-fqdn pair remains
    expect(merge.body.pending[0].reason).toBe("shortname-fqdn");

    const dismiss = await request(netIdApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(dismiss.status).toBe(200);
    expect(dismiss.body.pending).toEqual([]);
  });
});

describe("auto-run on last resolve", () => {
  let twoPairApp: express.Express;
  let kick: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-kick-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.corp.local"),
      ev("c", "DC01"),
      ev("d", "DC01.corp.local"),
    );
    await stateStore.save(s);
    kick = vi.fn();
    twoPairApp = express();
    twoPairApp.use(express.json());
    registerHostDuplicateRoutes(twoPairApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);
  });

  it("does not kick synthesis while a pair is still unresolved", async () => {
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.corp.local", other: "win11" });
    expect(kick).not.toHaveBeenCalled();
  });

  it("kicks synthesis exactly once, when the last pair resolves", async () => {
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.corp.local", other: "win11" });
    await request(twoPairApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "dc01.corp.local", other: "dc01" });
    expect(kick).toHaveBeenCalledWith("c1");
    expect(kick).toHaveBeenCalledTimes(1);
  });
});

// #1599: the list must BECOME empty. A retried resolve changes nothing and must not buy a run.
describe("auto-run fires on a transition, not on an empty list", () => {
  it("does not kick again when the resolve that emptied the list is retried", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-retry-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a", "WS01"), ev("b", "WS01.example.com"));
    await stateStore.save(s);
    const kick = vi.fn();
    const retryApp = express();
    retryApp.use(express.json());
    registerHostDuplicateRoutes(retryApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);
    const pair = { canonical: "ws01.example.com", other: "ws01" };
    await request(retryApp).post("/cases/c1/host-duplicates/dismiss").send(pair);
    expect(kick).toHaveBeenCalledTimes(1);
    await request(retryApp).post("/cases/c1/host-duplicates/dismiss").send(pair);
    await request(retryApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "fs01.example.com", other: "fs01" });
    expect(kick).toHaveBeenCalledTimes(1);
  });
});

// #1167: a non-blocking network-identity candidate must not delay the kick that resolving the
// LAST BLOCKING (shortname-fqdn) pair earns — synthesis was never held on network-identity rows
// in the first place (hostDuplicateGate.ts's own pendingNearDuplicates never reads them).
describe("auto-run ignores non-blocking network-identity candidates (#1167)", () => {
  it("kicks synthesis once the only blocking pair resolves, even with a network-identity candidate still pending", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-kick-netid-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.windomain.local"),
      ev("c", "10.0.0.5"),
      logonEvent("d", "fs-01", "ws-042", "10.0.0.5"),
    );
    await stateStore.save(s);
    const kick = vi.fn();
    const mixedApp = express();
    mixedApp.use(express.json());
    registerHostDuplicateRoutes(mixedApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);

    const list = await request(mixedApp).get("/cases/c1/host-duplicates");
    expect(list.body.pending.map((p: { reason: string }) => p.reason).sort()).toEqual([
      "network-identity",
      "shortname-fqdn",
    ]);

    const resolve = await request(mixedApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(resolve.status).toBe(200);
    expect(resolve.body.pending).toHaveLength(1);
    expect(resolve.body.pending[0].reason).toBe("network-identity");
    expect(kick).toHaveBeenCalledWith("c1");
    expect(kick).toHaveBeenCalledTimes(1);
  });

  it("does not kick synthesis while a blocking pair is still unresolved, network-identity candidate aside", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-kick-netid2-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.windomain.local"),
      ev("c", "DC01"),
      ev("d", "DC01.corp.local"),
      ev("e", "10.0.0.5"),
      logonEvent("f", "fs-01", "ws-042", "10.0.0.5"),
    );
    await stateStore.save(s);
    const kick = vi.fn();
    const mixedApp = express();
    mixedApp.use(express.json());
    registerHostDuplicateRoutes(mixedApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);

    const resolve = await request(mixedApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(resolve.status).toBe(200);
    const reasons = resolve.body.pending.map((p: { reason: string }) => p.reason).sort();
    expect(reasons).toEqual(["network-identity", "shortname-fqdn"]);
    expect(kick).not.toHaveBeenCalled();
  });

  it("does not re-kick synthesis for each network-identity candidate resolved after the blocking pair already cleared", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-kick-netid3-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline.push(
      ev("a", "WIN11"),
      ev("b", "WIN11.windomain.local"),
      ev("c", "10.0.0.5"),
      logonEvent("d", "fs-01", "ws-042", "10.0.0.5"),
      ev("e", "10.0.0.6"),
      logonEvent("f", "fs-02", "ws-043", "10.0.0.6"),
    );
    await stateStore.save(s);
    const kick = vi.fn();
    const mixedApp = express();
    mixedApp.use(express.json());
    registerHostDuplicateRoutes(mixedApp, {
      store: cases,
      options: {
        stateStore,
        assetOverridesStore: new AssetOverridesStore(cases),
        hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
      },
      resynthesizeInBackground: kick,
    } as unknown as RouteContext);

    const list = await request(mixedApp).get("/cases/c1/host-duplicates");
    expect(list.body.pending).toHaveLength(3); // 1 blocking pair + 2 network-identity candidates

    // Resolving the blocking pair is the one real transition — exactly one kick.
    const first = await request(mixedApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(first.body.pending).toHaveLength(2);
    expect(kick).toHaveBeenCalledTimes(1);

    // Resolving one of the two remaining network-identity candidates must NOT re-kick: synthesis
    // was already unblocked by the previous step, and one network-identity row still remains.
    const second = await request(mixedApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "ws-042", other: "10.0.0.5" });
    expect(second.body.pending).toHaveLength(1);
    expect(kick).toHaveBeenCalledTimes(1);

    // Resolving the LAST candidate of any kind still kicks once more (the list going fully empty
    // is its own trigger, preserving this route's original, pre-#1167 behavior) — total 2, not 3.
    const third = await request(mixedApp)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "ws-043", other: "10.0.0.6" });
    expect(third.body.pending).toEqual([]);
    expect(kick).toHaveBeenCalledTimes(2);
  });
});
