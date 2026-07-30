import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CockpitStore } from "../../src/analysis/cockpitStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";

async function makeStore(): Promise<CockpitStore> {
  const root = await mkdtemp(join(tmpdir(), "dfir-cockpit-store-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Case", investigator: "Alice", aiProvider: null });
  return new CockpitStore(cases);
}

describe("CockpitStore", () => {
  it("keeps the full action history while updating current card state", async () => {
    const store = await makeStore();
    await store.recordAction("c1", "lead:finding:f1", { action: "pin", actor: "Alice" }, "2026-07-30T10:00:00.000Z");
    await store.recordAction("c1", "lead:finding:f1", { action: "assign", actor: "Alice", value: "Bob" }, "2026-07-30T10:01:00.000Z");
    await store.recordAction("c1", "lead:finding:f1", { action: "dismiss", actor: "Bob" }, "2026-07-30T10:02:00.000Z");
    await store.recordAction("c1", "lead:finding:f1", { action: "restore", actor: "Bob" }, "2026-07-30T10:03:00.000Z");

    const saved = await store.load("c1");
    expect(saved.cards).toEqual([expect.objectContaining({
      cardId: "lead:finding:f1",
      pinned: true,
      assignee: "Bob",
    })]);
    expect(saved.cards[0].dismissedAt).toBeUndefined();
    expect(saved.history.map((entry) => entry.action)).toEqual(["pin", "assign", "dismiss", "restore"]);
    expect(saved.history.map((entry) => entry.actor)).toEqual(["Alice", "Alice", "Bob", "Bob"]);
  });

  it("tracks last review separately per normalized investigator identity", async () => {
    const store = await makeStore();
    await store.markReviewed("c1", " Alice ", "2026-07-30T10:00:00.000Z");
    await store.markReviewed("c1", "BOB", "2026-07-30T11:00:00.000Z");
    await store.markReviewed("c1", "alice", "2026-07-30T12:00:00.000Z");

    const saved = await store.load("c1");
    expect(saved.reviews).toEqual([
      { investigatorKey: "alice", investigator: "alice", reviewedAt: "2026-07-30T12:00:00.000Z" },
      { investigatorKey: "bob", investigator: "BOB", reviewedAt: "2026-07-30T11:00:00.000Z" },
    ]);
    expect(saved.history.filter((entry) => entry.action === "review")).toHaveLength(3);
  });

  it("bounds and normalizes action values", async () => {
    const store = await makeStore();
    await store.recordAction("c1", "gap:question:q1", {
      action: "defer",
      actor: "",
      value: "not-an-iso-date",
    });
    await store.recordAction("c1", "gap:question:q1", {
      action: "assign",
      actor: "Alice",
      value: "x".repeat(300),
    });

    const saved = await store.load("c1");
    expect(saved.cards[0].deferredUntil).toBeUndefined();
    expect(saved.cards[0].assignee).toHaveLength(120);
    expect(saved.history[0].actor).toBe("analyst");
  });
});
