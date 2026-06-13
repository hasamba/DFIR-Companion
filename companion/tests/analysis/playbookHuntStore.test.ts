import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PlaybookHuntStore } from "../../src/analysis/playbookHuntStore.js";
import type { PersistedPlaybookHunts } from "../../src/analysis/playbookHunt.js";

const data: PersistedPlaybookHunts = {
  generatedAt: "2026-06-13T00:00:00.000Z",
  suggestions: [{ taskId: "finding:f1", title: "Hunt", rationale: "r", vql: "SELECT * FROM pslist()", severity: "High", mitreTechniques: ["T1059"], mode: "collection", targetHost: "WIN11" }],
  taskHashes: { "finding:f1": "abc123" },
};

describe("PlaybookHuntStore", () => {
  let store: PlaybookHuntStore;
  let caseId: string;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-pbhstore-"));
    const cases = new CaseStore(root);
    caseId = "c1";
    await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
    store = new PlaybookHuntStore(cases);
  });

  it("returns an empty record before anything is saved", async () => {
    expect(await store.load(caseId)).toEqual({ generatedAt: "", suggestions: [], taskHashes: {} });
  });

  it("saves and reloads the suggestions + task hashes", async () => {
    await store.save(caseId, data);
    const loaded = await store.load(caseId);
    expect(loaded.generatedAt).toBe(data.generatedAt);
    expect(loaded.suggestions).toHaveLength(1);
    expect(loaded.suggestions[0].targetHost).toBe("WIN11");
    expect(loaded.taskHashes["finding:f1"]).toBe("abc123");
  });

  it("tolerates a malformed/partial file", async () => {
    await store.save(caseId, { generatedAt: "t", suggestions: [], taskHashes: {} });
    // a later partial write (e.g. only suggestions) still loads with defaults filled in
    const loaded = await store.load(caseId);
    expect(loaded.suggestions).toEqual([]);
    expect(loaded.taskHashes).toEqual({});
  });
});
