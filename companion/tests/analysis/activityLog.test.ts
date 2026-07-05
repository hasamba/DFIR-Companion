import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ActivityLogStore, logActivity } from "../../src/analysis/activityLog.js";

describe("ActivityLogStore", () => {
  let store: ActivityLogStore;
  let casesRoot: string;
  beforeEach(async () => {
    casesRoot = await mkdtemp(join(tmpdir(), "dfir-activity-"));
    const cases = new CaseStore(casesRoot);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ActivityLogStore(cases);
  });

  it("returns [] when no activity has been recorded", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("appends an entry (server-assigned id + timestamp) and lists it newest-first", async () => {
    const a = await store.add("c1", { category: "import", action: "import", detail: "THOR — +5 events, +2 IOCs" });
    const b = await store.add("c1", { category: "triage", action: "mark-false-positive", detail: "ioc 1.2.3.4 (duplicate)" });
    expect(a.id).toBeTruthy();
    expect(a.timestamp).toBeTruthy();
    expect(a.outcome).toBe("success");
    const list = await store.load("c1");
    expect(list.map((e) => e.id)).toEqual([b.id, a.id]); // newest first
  });

  it("defaults a blank/missing actor to 'analyst' and trims a provided one", async () => {
    const noActor = await store.add("c1", { category: "settings", action: "scope-changed", detail: "x" });
    expect(noActor.actor).toBe("analyst");
    const withActor = await store.add("c1", { category: "collaboration", action: "comment-added", detail: "x", actor: "  Alice  " });
    expect(withActor.actor).toBe("Alice");
  });

  it("filters by category", async () => {
    await store.add("c1", { category: "import", action: "import", detail: "a" });
    await store.add("c1", { category: "ai", action: "synthesis", detail: "b" });
    const onlyAi = await store.load("c1", { category: "ai" });
    expect(onlyAi).toHaveLength(1);
    expect(onlyAi[0].category).toBe("ai");
  });

  it("caps results with limit", async () => {
    for (let i = 0; i < 5; i++) await store.add("c1", { category: "import", action: "import", detail: String(i) });
    expect(await store.load("c1", { limit: 2 })).toHaveLength(2);
  });

  it("skips a malformed line instead of throwing", async () => {
    await store.add("c1", { category: "import", action: "import", detail: "good" });
    const { appendFile } = await import("node:fs/promises");
    await appendFile(join(casesRoot, "c1", "metadata", "activity.jsonl"), "not json\n", "utf8");
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0].detail).toBe("good");
  });
});

describe("logActivity helper", () => {
  it("no-ops without throwing when the store is undefined", () => {
    expect(() => logActivity(undefined, undefined, "c1", { category: "import", action: "import", detail: "x" })).not.toThrow();
  });
});
