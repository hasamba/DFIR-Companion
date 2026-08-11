import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CollectionPlanStore } from "../../src/analysis/collectionPlanStore.js";

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cplan-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { cases, store: new CollectionPlanStore(cases) };
}

describe("CollectionPlanStore", () => {
  it("returns no overrides for a case that has never set one", async () => {
    const { store } = await makeStore();
    expect(await store.load("c1")).toEqual({});
  });

  it("round-trips an override", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "no EDR in this estate" });
    expect(await store.load("c1")).toEqual({ edr: { state: "na", reason: "no EDR in this estate" } });
  });

  it("keeps overrides for other steps when setting one", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "a" });
    const after = await store.set("c1", "network", { state: "collected", reason: "b" });
    expect(Object.keys(after).sort()).toEqual(["edr", "network"]);
  });

  it("clears one override without touching the others", async () => {
    const { store } = await makeStore();
    await store.set("c1", "edr", { state: "na", reason: "a" });
    await store.set("c1", "network", { state: "collected", reason: "b" });
    expect(await store.clear("c1", "edr")).toEqual({ network: { state: "collected", reason: "b" } });
  });

  it("clearing an override that was never set is a no-op, not an error", async () => {
    const { store } = await makeStore();
    expect(await store.clear("c1", "edr")).toEqual({});
  });

  // A corrupt file must not block the panel — the analyst can re-assert an override, but they
  // cannot recover a case whose every read throws.
  it("returns no overrides when the file is corrupt", async () => {
    const { cases, store } = await makeStore();
    const dir = cases.stateDir("c1");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "collection-plan.json"), "{ not json", "utf8");
    expect(await store.load("c1")).toEqual({});
  });

  it("drops a malformed override rather than trusting it", async () => {
    const { cases, store } = await makeStore();
    const dir = cases.stateDir("c1");
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, "collection-plan.json"),
      JSON.stringify({
        overrides: { edr: { state: "banana", reason: "x" }, network: { state: "na", reason: "ok" } },
      }),
      "utf8",
    );
    expect(await store.load("c1")).toEqual({ network: { state: "na", reason: "ok" } });
  });
});
