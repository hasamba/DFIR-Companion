import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("c1"), ...over };
}

describe("PlaybookStore", () => {
  let store: PlaybookStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-playbook-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new PlaybookStore(cases);
  });

  it("returns [] when no playbook exists", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("adds a custom task (server id/order/timestamps) and lists it", async () => {
    const t = await store.add("c1", { title: "Notify client", priority: "high", assignee: "ana" });
    expect(t.id).toMatch(/^custom:/);
    expect(t).toMatchObject({ title: "Notify client", priority: "high", assignee: "ana", status: "todo", source: "custom", order: 0 });
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("trims title and omits empty optional fields", async () => {
    const t = await store.add("c1", { title: "  Contain  ", assignee: "   ", dueDate: "" });
    expect(t.title).toBe("Contain");
    expect(t.assignee).toBeUndefined();
    expect(t.dueDate).toBeUndefined();
  });

  it("updates status and clears an optional field with an empty string", async () => {
    const t = await store.add("c1", { title: "x", assignee: "ana" });
    const done = await store.update("c1", t.id, { status: "done" });
    expect(done!.status).toBe("done");
    const cleared = await store.update("c1", t.id, { assignee: "" });
    expect(cleared!.assignee).toBeUndefined();
  });

  it("ignores an unknown status on update", async () => {
    const t = await store.add("c1", { title: "x" });
    const r = await store.update("c1", t.id, { status: "bogus" as never });
    expect(r!.status).toBe("todo");
  });

  it("removes a custom task and returns false for a missing id", async () => {
    expect(await store.update("c1", "nope", { status: "done" })).toBeNull();
    const t = await store.add("c1", { title: "x" });
    expect(await store.remove("c1", t.id)).toBe(true);
    expect(await store.load("c1")).toHaveLength(0);
    expect(await store.remove("c1", t.id)).toBe(false);
  });

  it("remove on an auto-derived task marks it skipped (not removed) so sync cannot re-add it as todo", async () => {
    const state = stateWith({ nextSteps: [{ id: "ns1", priority: "high", action: "Pull logs", rationale: "r", pointer: "host" }] });
    await store.sync("c1", state);
    expect(await store.remove("c1", "next_step:ns1")).toBe(true);
    const tasks = await store.load("c1");
    expect(tasks).toHaveLength(1);
    expect(tasks[0]).toMatchObject({ id: "next_step:ns1", status: "skipped" });
    // Sync with same state must preserve the skipped status, not reset to todo.
    const synced = await store.sync("c1", state);
    expect(synced.find((t) => t.id === "next_step:ns1")).toMatchObject({ status: "skipped" });
  });

  it("reorders by a supplied id sequence", async () => {
    const a = await store.add("c1", { title: "a" });
    const b = await store.add("c1", { title: "b" });
    const c = await store.add("c1", { title: "c" });
    const out = await store.reorder("c1", [c.id, a.id, b.id]);
    expect(out.map((t) => t.title)).toEqual(["c", "a", "b"]);
    expect(out.map((t) => t.order)).toEqual([0, 1, 2]);
  });

  it("sync derives tasks from state and is idempotent (no rewrite on no-op)", async () => {
    const state = stateWith({ nextSteps: [{ id: "ns1", priority: "high", action: "Pull logs", rationale: "r", pointer: "host" }] });
    const first = await store.sync("c1", state);
    expect(first.map((t) => t.id)).toEqual(["next_step:ns1"]);
    const before = JSON.stringify(await store.load("c1"));
    await store.sync("c1", state);
    expect(JSON.stringify(await store.load("c1"))).toBe(before);
  });

  it("sync preserves analyst status across a re-derive", async () => {
    const state = stateWith({ nextSteps: [{ id: "ns1", priority: "high", action: "Pull logs", rationale: "r", pointer: "host" }] });
    await store.sync("c1", state);
    await store.update("c1", "next_step:ns1", { status: "done", assignee: "ana" });
    const after = await store.sync("c1", state);
    expect(after.find((t) => t.id === "next_step:ns1")).toMatchObject({ status: "done", assignee: "ana" });
  });

  it("sync keeps custom tasks alongside derived ones", async () => {
    await store.add("c1", { title: "Call client" });
    const state = stateWith({ nextSteps: [{ id: "ns1", priority: "low", action: "Pull logs", rationale: "", pointer: "" }] });
    const out = await store.sync("c1", state);
    expect(out.map((t) => t.source).sort()).toEqual(["custom", "next_step"]);
  });
});
