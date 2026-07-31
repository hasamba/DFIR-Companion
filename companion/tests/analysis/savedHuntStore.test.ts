import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { SavedHuntStore } from "../../src/analysis/savedHuntStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";

let store: SavedHuntStore;
let cases: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-saved-hunts-"));
  cases = new CaseStore(root);
  await cases.createCase({
    caseId: "c1",
    name: "n",
    investigator: "i",
    aiProvider: null,
  });
  store = new SavedHuntStore(cases, { maxHistory: 3 });
});

describe("SavedHuntStore", () => {
  it("persists query text, dataset, author and typed parameters", async () => {
    const saved = await store.create("c1", {
      name: "Failed logons",
      query: "event.category=authentication AND user.name=$account",
      dataset: "forensic",
      author: "analyst",
      parameters: { account: "jdoe", threshold: 3, includeService: false },
    });

    expect(await new SavedHuntStore(cases).list("c1")).toEqual([
      expect.objectContaining({
        id: saved.id,
        name: "Failed logons",
        dataset: "forensic",
        author: "analyst",
        parameters: {
          account: "jdoe",
          threshold: 3,
          includeService: false,
        },
        history: [],
      }),
    ]);
  });

  it("records bounded execution history newest first", async () => {
    const saved = await store.create("c1", {
      name: "Hunt",
      query: "severity=High",
      dataset: "super",
      author: "analyst",
      parameters: {},
    });
    for (let index = 0; index < 5; index++) {
      await store.recordExecution("c1", saved.id, {
        executedBy: "user",
        status: "completed",
        matched: index,
        scanned: index + 10,
        durationMs: index + 20,
        parameters: {},
      });
    }

    const [loaded] = await store.list("c1");
    expect(loaded.history).toHaveLength(3);
    expect(loaded.history.map((entry) => entry.matched)).toEqual([4, 3, 2]);
  });

  it("updates immutably and removes a hunt", async () => {
    const saved = await store.create("c1", {
      name: "Old",
      query: "severity=Low",
      dataset: "forensic",
      author: "a",
      parameters: {},
    });
    const updated = await store.update("c1", saved.id, {
      name: "New",
      query: "severity=High",
      dataset: "super",
      author: "b",
      parameters: { host: "DC01" },
    });
    expect(updated).toMatchObject({
      name: "New",
      query: "severity=High",
      dataset: "super",
      author: "b",
    });
    expect(saved.name).toBe("Old");
    expect(await store.remove("c1", saved.id)).toBe(true);
    expect(await store.list("c1")).toEqual([]);
  });
});
