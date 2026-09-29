import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { atomicWrite } from "../../src/storage/atomicWrite.js";
import {
  LEGACY_GENERATION,
  beginCaseWrite,
  capturedGeneration,
  isCaseWriteRefused,
  runInCaseScope,
  setCaseWriteRefusalReporter,
  type CaseWriteRefusedError,
} from "../../src/storage/caseIncarnation.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { CustodyStore } from "../../src/analysis/custody.js";

let root: string;
let store: CaseStore;
let refused: CaseWriteRefusedError[];

const create = (caseId = "c1") =>
  store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
const caseJson = async (caseId = "c1") => JSON.parse(await readFile(join(root, caseId, "case.json"), "utf8"));
const sidecar = (caseId = "c1") => join(root, caseId, "state", "sidecar.json");

/**
 * A late write from old work: the generation is captured now (as the work starts), and every later
 * call runs inside a scope holding that captured generation.
 */
async function oldWork(caseId = "c1"): Promise<<T>(fn: () => Promise<T>) => Promise<T>> {
  const gen = runInCaseScope(root, caseId, () => capturedGeneration(root, caseId));
  return <T>(fn: () => Promise<T>) => (gen === null ? fn() : runInCaseScope(root, caseId, fn, gen));
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-incarnation-"));
  store = new CaseStore(root);
  refused = [];
  setCaseWriteRefusalReporter((err) => refused.push(err));
});
afterEach(() => setCaseWriteRefusalReporter(null));

describe("case generation in case.json (#1855)", () => {
  it("createCase stamps a random generation, different for each incarnation", async () => {
    await create();
    const first = (await caseJson()).generation;
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    await store.updateCaseMeta("c1", { status: "closed" });
    await store.deleteCaseFolder("c1");
    await create();
    expect((await caseJson()).generation).not.toBe(first);
  });

  it("updateCaseMeta keeps the generation and cannot overwrite or erase it", async () => {
    await create();
    const gen = (await caseJson()).generation;
    await store.updateCaseMeta("c1", { name: "x", generation: "forged" });
    await store.updateCaseMeta("c1", { generation: undefined });
    expect((await caseJson()).generation).toBe(gen);
  });

  it("a legacy case.json without the field reads as the legacy generation and is not rewritten", async () => {
    await mkdir(join(root, "old", "state"), { recursive: true });
    await writeFile(join(root, "old", "case.json"), JSON.stringify({ caseId: "old", name: "o" }), "utf8");
    runInCaseScope(root, "old", () => expect(capturedGeneration(root, "old")).toBe(LEGACY_GENERATION));
    const late = await oldWork("old");
    await late(() => atomicWrite(sidecar("old"), "{}"));
    await store.updateCaseMeta("old", { status: "closed" });
    expect((await caseJson("old")).generation).toBeUndefined();
    await late(() => atomicWrite(sidecar("old"), "{}")); // still the same incarnation
    expect(refused).toEqual([]);
  });
});

describe("a late write after the case is deleted (#1855)", () => {
  async function deleteCase(caseId = "c1") {
    await store.updateCaseMeta(caseId, { status: "closed" });
    await store.deleteCaseFolder(caseId);
    expect(existsSync(join(root, caseId))).toBe(false);
  }

  it("scoped work: recreates no folder, at any choke point", async () => {
    await create();
    const late = await oldWork();
    await deleteCase();
    const attempts: [string, () => Promise<unknown>][] = [
      ["atomicWrite", () => atomicWrite(sidecar(), "{}")],
      ["state save", () => new StateStore(store).save(emptyState("c1"))],
      ["saveImport", () => store.saveImport("c1", "a.csv", "x")],
      ["saveScreenshot", () => store.saveScreenshot("c1", "a.png", Buffer.from("x"))],
      ["appendImport", () => store.appendImport("c1", {} as never)],
      ["appendCapture", () => store.appendCapture("c1", {} as never)],
      ["putOcrEntry", () => store.putOcrEntry("c1", { screenshotFile: "a.png" } as never)],
      ["mkdirInCase", () => store.mkdirInCase(store.reportsDir("c1"))],
      [
        "activity log",
        () => new ActivityLogStore(store).add("c1", { category: "case", action: "x", detail: "" } as never),
      ],
    ];
    for (const [what, attempt] of attempts) {
      const err = await late(attempt).catch((e: unknown) => e);
      expect(isCaseWriteRefused(err), what).toBe(true);
      expect(existsSync(join(root, "c1")), what).toBe(false);
    }
    expect(refused.every((r) => r.reason === "deleted")).toBe(true);
  });

  it("unscoped work: never recreates the deleted folder either", async () => {
    await create();
    await deleteCase();
    for (const attempt of [
      () => atomicWrite(sidecar(), "{}"),
      () => new StateStore(store).save(emptyState("c1")),
      () => store.appendImport("c1", {} as never),
      () => store.mkdirInCase(store.metadataDir("c1")),
      () => new CustodyStore(store).record("c1", { artifactPath: "x", sha256: "0", caseId: "c1" } as never),
    ]) {
      expect(isCaseWriteRefused(await attempt().catch((e: unknown) => e))).toBe(true);
    }
    expect(existsSync(join(root, "c1"))).toBe(false);
    // …and the id can be created again: the leftover-folder check has nothing to refuse.
    await create();
    expect(existsSync(join(root, "c1", "case.json"))).toBe(true);
  });

  it("scoped work: after delete + re-create, the new case is untouched", async () => {
    await create();
    const late = await oldWork();
    await deleteCase();
    await create();
    const before = await readdir(join(root, "c1"), { recursive: true });
    for (const attempt of [
      () => atomicWrite(sidecar(), "{}"),
      () => new StateStore(store).save(emptyState("c1")),
      (): Promise<unknown> => store.saveImport("c1", "a.csv", "x"),
      () => store.appendImport("c1", {} as never),
      () => new ActivityLogStore(store).add("c1", { category: "case", action: "x", detail: "" } as never),
    ]) {
      const err = await late(attempt).catch((e: unknown) => e);
      expect(isCaseWriteRefused(err)).toBe(true);
    }
    expect(await readdir(join(root, "c1"), { recursive: true })).toEqual(before);
    expect(refused.every((r) => r.reason === "replaced")).toBe(true);
    // The new case's own work — scoped or not — writes normally.
    await runInCaseScope(root, "c1", () => atomicWrite(sidecar(), "{}"));
    await atomicWrite(sidecar(), "{}");
    await new StateStore(store).save(emptyState("c1"));
  });

  it("work that starts after the delete captures 'gone' and stays refused after a re-create", async () => {
    await create();
    await deleteCase();
    const late = await oldWork();
    await create();
    const err = await late(() => atomicWrite(sidecar(), "{}")).catch((e: unknown) => e);
    expect(isCaseWriteRefused(err)).toBe(true);
  });
});

describe("live cases are unaffected (#1855)", () => {
  it("scoped and unscoped writes succeed on a live case", async () => {
    await create();
    await runInCaseScope(root, "c1", async () => {
      await atomicWrite(sidecar(), "{}");
      await new StateStore(store).save(emptyState("c1"));
      await store.saveImport("c1", "a.csv", "x");
    });
    await atomicWrite(sidecar(), "{}");
    await store.appendImport("c1", {} as never);
    expect(refused).toEqual([]);
  });

  it("a never-created case keeps the old behavior (no scope, no tombstone)", async () => {
    await new StateStore(store).save(emptyState("fresh"));
    expect(existsSync(join(root, "fresh", "state"))).toBe(true);
  });

  it("first capture wins, and a timer started in the scope keeps it", async () => {
    await create();
    const gen = (await caseJson()).generation;
    const seen = await runInCaseScope(root, "c1", async () => {
      await store.updateCaseMeta("c1", { status: "closed" });
      await store.deleteCaseFolder("c1");
      await create();
      const inner = runInCaseScope(root, "c1", () => capturedGeneration(root, "c1"));
      const timed = await new Promise((ok) => setTimeout(() => ok(capturedGeneration(root, "c1")), 1));
      return [inner, timed];
    });
    expect(seen).toEqual([gen, gen]);
  });
});

describe("archive and restore bind writes to the current folder (#1855)", () => {
  it("a late write to the old active path after archive is refused and recreates nothing", async () => {
    await create();
    await store.updateCaseMeta("c1", { status: "closed" });
    const activeState = store.stateDir("c1");
    await store.archiveCaseFolder("c1", "archived");
    for (const attempt of [
      () => runInCaseScope(root, "c1", () => atomicWrite(join(activeState, "x.json"), "{}")),
      () => store.mkdirInCase(activeState),
    ]) {
      const err = await attempt().catch((e: unknown) => e);
      expect(isCaseWriteRefused(err)).toBe(true);
    }
    expect(existsSync(join(root, "c1"))).toBe(false);
    // Writes that follow the case to its new place still work.
    await atomicWrite(join(store.stateDir("c1"), "x.json"), "{}");
    await store.restoreCaseFolder("c1", "closed");
    await atomicWrite(join(store.stateDir("c1"), "y.json"), "{}");
    expect(existsSync(join(root, "c1", "state", "y.json"))).toBe(true);
  });
});

describe("the delete waits for writes already admitted (#1855)", () => {
  it("refuses new writes while closing and removes the folder only after the admitted write ends", async () => {
    await create();
    await store.updateCaseMeta("c1", { status: "closed" });
    const release = beginCaseWrite(sidecar());
    let deleted = false;
    const pending = store.deleteCaseFolder("c1").then(() => (deleted = true));
    await new Promise((ok) => setTimeout(ok, 20));
    expect(deleted).toBe(false);
    expect(existsSync(join(root, "c1", "case.json"))).toBe(true);
    expect(() => beginCaseWrite(sidecar())).toThrow(/deleted/);
    release();
    await pending;
    expect(existsSync(join(root, "c1"))).toBe(false);
  });

  it("refuses the delete (409) when an admitted write outlasts the wait, and reopens the folder", async () => {
    await create();
    await store.updateCaseMeta("c1", { status: "closed" });
    const release = beginCaseWrite(sidecar());
    const quick = new CaseStore(root, { writeQuiesceMs: 30 });
    const err = await quick.deleteCaseFolder("c1").catch((e: unknown) => e);
    expect((err as { httpStatus?: number }).httpStatus).toBe(409);
    expect(existsSync(join(root, "c1", "case.json"))).toBe(true);
    release();
    beginCaseWrite(sidecar())(); // open again
  });
});
