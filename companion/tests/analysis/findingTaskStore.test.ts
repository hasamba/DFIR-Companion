import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { FindingTaskStore } from "../../src/analysis/findingTaskStore.js";

const NOW = "2026-06-10T00:00:00.000Z";
const task = (title: string) => ({
  title,
  steps: ["step"],
  doneWhen: "done",
  sourceHash: "h1",
  writtenAt: NOW,
  engine: "ai" as const,
});

describe("FindingTaskStore", () => {
  let store: FindingTaskStore;
  let cases: CaseStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-finding-tasks-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new FindingTaskStore(cases);
  });

  it("loads an empty map when no file exists", async () => {
    expect(await store.load("c1")).toEqual({});
  });

  it("merges new tasks over existing ones and reloads them", async () => {
    await store.upsert("c1", { f1: task("one") }, ["f1", "f2"]);
    await store.upsert("c1", { f2: task("two") }, ["f1", "f2"]);
    const all = await store.load("c1");
    expect(Object.keys(all).sort()).toEqual(["f1", "f2"]);
    expect(all.f1.title).toBe("one");
  });

  it("prunes tasks whose finding no longer exists", async () => {
    await store.upsert("c1", { f1: task("one"), f2: task("two") }, ["f1", "f2"]);
    const kept = await store.upsert("c1", {}, ["f2"]);
    expect(Object.keys(kept)).toEqual(["f2"]);
    expect(Object.keys(await store.load("c1"))).toEqual(["f2"]);
  });

  it("treats a corrupt file as empty instead of throwing", async () => {
    await writeFile(join(cases.stateDir("c1"), "finding-tasks.json"), "{not json", "utf8");
    expect(await store.load("c1")).toEqual({});
  });

  it("drops a malformed entry on load but keeps the valid ones", async () => {
    await writeFile(
      join(cases.stateDir("c1"), "finding-tasks.json"),
      JSON.stringify({ version: 1, tasks: { f1: task("ok"), f2: { title: 3 } } }),
      "utf8",
    );
    expect(Object.keys(await store.load("c1"))).toEqual(["f1"]);
  });

  it("writes a versioned file", async () => {
    await store.upsert("c1", { f1: task("one") }, ["f1"]);
    const raw = JSON.parse(await readFile(join(cases.stateDir("c1"), "finding-tasks.json"), "utf8"));
    expect(raw.version).toBe(1);
    expect(raw.tasks.f1.engine).toBe("ai");
  });
});
