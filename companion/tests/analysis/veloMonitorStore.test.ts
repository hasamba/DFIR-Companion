import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VeloMonitorStore, monitorId, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";

function mon(over: Partial<VeloMonitor> = {}): VeloMonitor {
  return {
    id: monitorId("C.111", "Windows.Events.ProcessCreation"),
    clientId: "C.111",
    artifact: "Windows.Events.ProcessCreation",
    pollSeconds: 30,
    cursor: 1_700_000_000,
    status: "active",
    createdAt: "2026-06-13T00:00:00.000Z",
    ...over,
  };
}

describe("VeloMonitorStore", () => {
  let store: VeloMonitorStore;
  let cases: CaseStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velomon-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new VeloMonitorStore(cases);
  });

  it("monitorId is stable for a (client, artifact) pair", () => {
    expect(monitorId("C.1", "A.B")).toBe("C.1__A.B");
  });

  it("returns an empty list when none exist", async () => {
    expect(await store.list("c1")).toEqual([]);
    expect(await store.get("c1", "nope")).toBeNull();
  });

  it("upserts and reads a monitor round-trip", async () => {
    const m = mon();
    await store.upsert("c1", m);
    expect(await store.list("c1")).toEqual([m]);
    expect(await store.get("c1", m.id)).toEqual(m);
  });

  it("keeps multiple monitors and updates in place by id", async () => {
    const a = mon({ id: "a", clientId: "C.A" });
    const b = mon({ id: "b", clientId: "C.B" });
    await store.upsert("c1", a);
    await store.upsert("c1", b);
    await store.upsert("c1", { ...a, cursor: 999, addedEvents: 5 });
    const list = await store.list("c1");
    expect(list.map((m) => m.id)).toEqual(["a", "b"]); // order preserved
    expect((await store.get("c1", "a"))!.cursor).toBe(999);
    expect((await store.get("c1", "a"))!.addedEvents).toBe(5);
  });

  it("remove() deletes a monitor", async () => {
    await store.upsert("c1", mon({ id: "a" }));
    await store.upsert("c1", mon({ id: "b" }));
    await store.remove("c1", "a");
    expect((await store.list("c1")).map((m) => m.id)).toEqual(["b"]);
  });
});

describe("VeloMonitorStore.update (#2403)", () => {
  let store: VeloMonitorStore;
  beforeEach(async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-velomon-upd-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new VeloMonitorStore(cases);
  });

  it("applies the change to the row as stored now", async () => {
    await store.upsert("c1", mon());
    const out = await store.update("c1", mon().id, (cur) => ({ ...cur, status: "stopped" }));
    expect(out?.status).toBe("stopped");
    expect((await store.get("c1", mon().id))?.status).toBe("stopped");
  });

  it("never re-creates a deleted row, and a null result leaves the file alone", async () => {
    expect(await store.update("c1", "gone", (cur) => cur)).toBeNull();
    expect(await store.list("c1")).toEqual([]);
    await store.upsert("c1", mon({ polls: 4 }));
    expect((await store.update("c1", mon().id, () => null))?.polls).toBe(4);
  });
});
