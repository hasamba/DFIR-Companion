import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ClickUpClient } from "../../src/integrations/clickup/clickupClient.js";
import { ClickUpExportStore } from "../../src/integrations/clickup/clickupExportStore.js";
import { pushPlaybookToClickUp, type ClickUpClientLike } from "../../src/integrations/clickup/clickupPush.js";
import {
  clickupPriority, clickupStatusCandidates, resolveClickUpStatus, mapPlaybookTaskToClickUp,
} from "../../src/integrations/clickup/clickupMap.js";
import type { PlaybookTask } from "../../src/integrations/clickup/../../analysis/playbook.js";

const NOW = "2026-06-10T00:00:00.000Z";
function task(over: Partial<PlaybookTask> = {}): PlaybookTask {
  return {
    id: "next_step:s1", title: "Isolate DC01", description: "Active C2", status: "todo", priority: "high",
    source: "next_step", sourceKey: "next_step:s1", order: 0, createdAt: NOW, updatedAt: NOW, ...over,
  };
}

describe("clickupMap", () => {
  it("maps playbook priority → ClickUp priority int", () => {
    expect(clickupPriority("critical")).toBe(1);
    expect(clickupPriority("high")).toBe(2);
    expect(clickupPriority("medium")).toBe(3);
    expect(clickupPriority("low")).toBe(4);
  });

  it("resolves a playbook status to an existing list status (case-insensitive), else undefined", () => {
    expect(resolveClickUpStatus(["to do", "in progress", "complete"], "done")).toBe("complete");
    expect(resolveClickUpStatus(["To Do", "In Progress", "Complete"], "in_progress")).toBe("in progress");
    expect(resolveClickUpStatus(["backlog"], "todo")).toBe("backlog");
    expect(resolveClickUpStatus(["weird-only"], "todo")).toBeUndefined();
    expect(clickupStatusCandidates("skipped")[0]).toBe("closed");
  });

  it("builds a task body with name/description/priority/status and a parsed due date", () => {
    const body = mapPlaybookTaskToClickUp(task({ assignee: "ana", dueDate: "2026-06-15" }), "to do");
    expect(body.name).toBe("Isolate DC01");
    expect(body.priority).toBe(2);
    expect(body.status).toBe("to do");
    expect(body.description).toContain("Assignee: ana");
    expect(body.description).toContain("DFIR Companion");
    expect(body.due_date).toBe(Date.parse("2026-06-15"));
  });

  it("omits status when unresolved and due_date when unparseable", () => {
    const body = mapPlaybookTaskToClickUp(task({ dueDate: "not-a-date" }));
    expect(body.status).toBeUndefined();
    expect(body.due_date).toBeUndefined();
  });
});

describe("ClickUpClient (HTTP via injected fetch)", () => {
  it("sends the token in the Authorization header and reads list statuses", async () => {
    let seenAuth = "";
    const fetchFn = (async (_url: string, init: RequestInit) => {
      seenAuth = (init.headers as Record<string, string>).Authorization;
      return new Response(JSON.stringify({ statuses: [{ status: "To Do" }, { status: "Complete" }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = new ClickUpClient({ token: "pk_123", fetchFn });
    expect(await client.listStatuses("L1")).toEqual(["to do", "complete"]);
    expect(seenAuth).toBe("pk_123");
  });

  it("maps a 401 to an actionable auth error", async () => {
    const fetchFn = (async () => new Response(JSON.stringify({ err: "Token invalid" }), { status: 401 })) as unknown as typeof fetch;
    const client = new ClickUpClient({ token: "bad", fetchFn });
    await expect(client.me()).rejects.toThrow(/auth failed/i);
  });
});

class MockClickUp implements ClickUpClientLike {
  statuses = ["to do", "in progress", "complete"];
  created: { listId: string; body: unknown }[] = [];
  updated: { taskId: string; body: unknown }[] = [];
  failTitles = new Set<string>();
  private seq = 1;
  async me() { return { id: "u1", username: "tester" }; }
  async listStatuses() { return this.statuses; }
  async createTask(listId: string, body: { name: string }) {
    if (this.failTitles.has(body.name)) throw new Error("boom");
    this.created.push({ listId, body });
    return { id: `ct${this.seq++}`, url: `https://app.clickup.com/t/ct${this.seq}` };
  }
  async updateTask(taskId: string, body: unknown) { this.updated.push({ taskId, body }); return { id: taskId }; }
}

describe("pushPlaybookToClickUp", () => {
  let store: ClickUpExportStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-clickup-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ClickUpExportStore(cases);
  });

  it("creates tasks for new playbook tasks, mapping status, and remembers the ClickUp ids", async () => {
    const m = new MockClickUp();
    const res = await pushPlaybookToClickUp(m, {
      caseId: "c1", listId: "L1",
      tasks: [task({ id: "next_step:s1", status: "in_progress" }), task({ id: "custom:1", title: "Notify", status: "done" })],
    }, store, NOW);
    expect(res.created).toBe(2);
    expect(res.updated).toBe(0);
    expect((m.created[0].body as { status: string }).status).toBe("in progress");
    expect((m.created[1].body as { status: string }).status).toBe("complete");
    const saved = await store.load("c1");
    expect(saved.listId).toBe("L1");
    expect(Object.keys(saved.taskIds)).toEqual(["next_step:s1", "custom:1"]);
  });

  it("UPDATES an already-exported task on re-push instead of creating a duplicate", async () => {
    const m = new MockClickUp();
    await pushPlaybookToClickUp(m, { caseId: "c1", listId: "L1", tasks: [task()] }, store, NOW);
    const res2 = await pushPlaybookToClickUp(m, { caseId: "c1", listId: "L1", tasks: [task({ status: "done" })] }, store, NOW);
    expect(res2.created).toBe(0);
    expect(res2.updated).toBe(1);
    expect(m.updated[0].taskId).toBe("ct1");
  });

  it("records a warning and counts a skip when a task fails to create", async () => {
    const m = new MockClickUp();
    m.failTitles.add("Isolate DC01");
    const res = await pushPlaybookToClickUp(m, { caseId: "c1", listId: "L1", tasks: [task()] }, store, NOW);
    expect(res.skipped).toBe(1);
    expect(res.created).toBe(0);
    expect(res.warnings[0]).toContain("Isolate DC01");
  });
});
