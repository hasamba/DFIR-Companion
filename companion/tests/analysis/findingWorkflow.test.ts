import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { FindingWorkflowStore, MAX_ASSIGNEE_LENGTH } from "../../src/analysis/findingWorkflow.js";

describe("FindingWorkflowStore", () => {
  let cases: CaseStore;
  let store: FindingWorkflowStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-fwf-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new FindingWorkflowStore(cases);
  });

  it("returns [] when nothing is set", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("assigns a finding to a person and records provenance", async () => {
    const rec = await store.patch("c1", "f-1", { assignee: "Alice", updatedBy: "Bob" });
    expect(rec).not.toBeNull();
    expect(rec!.findingId).toBe("f-1");
    expect(rec!.assignee).toBe("Alice");
    expect(rec!.status).toBeNull();
    expect(rec!.updatedBy).toBe("Bob");
    expect(rec!.updatedAt).toBeTruthy();
    expect(await store.load("c1")).toHaveLength(1);
  });

  it("sets a workflow status independently of the assignee", async () => {
    const rec = await store.patch("c1", "f-1", { status: "in_progress" });
    expect(rec!.status).toBe("in_progress");
    expect(rec!.assignee).toBe("");
  });

  it("merges partial patches: status-only leaves the assignee intact and vice versa", async () => {
    await store.patch("c1", "f-1", { assignee: "Alice" });
    const rec = await store.patch("c1", "f-1", { status: "in_review" });
    expect(rec!.assignee).toBe("Alice");     // preserved
    expect(rec!.status).toBe("in_review");
    const rec2 = await store.patch("c1", "f-1", { assignee: "Carol" });
    expect(rec2!.assignee).toBe("Carol");
    expect(rec2!.status).toBe("in_review");  // preserved
  });

  it("clears the record when both assignee and status become empty", async () => {
    await store.patch("c1", "f-1", { assignee: "Alice", status: "resolved" });
    const cleared = await store.patch("c1", "f-1", { assignee: "", status: null });
    expect(cleared).toBeNull();
    expect(await store.load("c1")).toEqual([]);
  });

  it("keeps the record when only one field is cleared", async () => {
    await store.patch("c1", "f-1", { assignee: "Alice", status: "resolved" });
    const rec = await store.patch("c1", "f-1", { status: null });
    expect(rec).not.toBeNull();
    expect(rec!.assignee).toBe("Alice");
    expect(rec!.status).toBeNull();
  });

  it("coerces an unknown status to null (defensive)", async () => {
    // @ts-expect-error — exercising the runtime guard with a bad value
    const rec = await store.patch("c1", "f-1", { assignee: "Alice", status: "bogus" });
    expect(rec!.status).toBeNull();
  });

  it("trims the findingId and caps a very long assignee", async () => {
    const long = "x".repeat(500);
    const rec = await store.patch("c1", "  f-2  ", { assignee: long });
    expect(rec!.findingId).toBe("f-2");
    expect(rec!.assignee).toHaveLength(MAX_ASSIGNEE_LENGTH);
  });

  it("rejects a blank findingId", async () => {
    await expect(store.patch("c1", "   ", { assignee: "x" })).rejects.toThrow(/findingId is required/);
  });

  it("keeps records for multiple findings independent", async () => {
    await store.patch("c1", "f-1", { assignee: "Alice" });
    await store.patch("c1", "f-2", { status: "new" });
    const all = await store.load("c1");
    expect(all).toHaveLength(2);
    expect(all.find((r) => r.findingId === "f-1")!.assignee).toBe("Alice");
    expect(all.find((r) => r.findingId === "f-2")!.status).toBe("new");
  });

  it("persists across store instances (survives a reload / re-synthesis)", async () => {
    await store.patch("c1", "f-1", { assignee: "Alice", status: "in_progress" });
    // A fresh store instance reads the same on-disk side file — the whole point is that it lives
    // outside InvestigationState, so re-synthesis (which rewrites state.json, not this file) can't wipe it.
    const reopened = new FindingWorkflowStore(cases);
    const all = await reopened.load("c1");
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ findingId: "f-1", assignee: "Alice", status: "in_progress" });
  });
});
