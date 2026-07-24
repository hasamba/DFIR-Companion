import { describe, it, expect, vi } from "vitest";
import type { Finding } from "../../src/analysis/stateTypes.js";
import { pushFindingToJira, type JiraClientLike, type JiraExportStoreLike } from "../../src/integrations/jira/jiraPush.js";

function makeFinding(partial: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    title: "Suspicious PowerShell download cradle",
    description: "Encoded PowerShell payload downloaded from 192.0.2.5.",
    severity: "high",
    confidence: 82,
    relatedIocs: ["ioc-1"],
    relatedEventIds: ["evt-1"],
    sourceScreenshots: [],
    mitreTechniques: ["T1059.001"],
    firstSeen: "2026-07-24T10:00:00Z",
    ...partial,
  } as Finding;
}

function inMemoryStore(initial: { issueRefs: Record<string, { id: string; key: string; url?: string }>; lastExportedAt: string } = { issueRefs: {}, lastExportedAt: "" }): JiraExportStoreLike {
  let state = { ...initial, issueRefs: { ...initial.issueRefs } };
  return {
    load: async () => ({ ...state, issueRefs: { ...state.issueRefs } }),
    save: async (_caseId, refs) => { state = { ...state, issueRefs: { ...state.issueRefs, ...refs } }; },
  };
}

function mockClient(): { client: JiraClientLike; calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    client: {
      me: async () => { calls.push("me"); return { id: "user-1", displayName: "Analyst" }; },
      createIssue: async (body) => {
        calls.push(body);
        return { id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" };
      },
    },
    calls,
  };
}

describe("pushFindingToJira", () => {
  it("creates a Jira issue from a high-severity finding", async () => {
    const { client, calls } = mockClient();
    const store = inMemoryStore();
    const result = await pushFindingToJira(client, store, { caseId: "case-a", projectKey: "IR", finding: makeFinding() });

    expect(calls[0]).toBe("me");
    expect(result.created).toBe(true);
    expect(result.issue.key).toBe("IR-42");
    const body = calls[1] as { priority?: string; summary: string; labels: string[]; description?: string };
    expect(body.priority).toBe("High");
    expect(body.summary).toContain("case-a");
    expect(body.labels).toContain("dfir-companion");
    expect(body.description).toContain("Encoded PowerShell");
  });

  it("marks updated=true when a previous issue exists", async () => {
    const { client, calls } = mockClient();
    const store = inMemoryStore({ issueRefs: { "finding-1": { id: "x", key: "IR-1" } }, lastExportedAt: "" });
    const result = await pushFindingToJira(client, store, { caseId: "case-a", projectKey: "IR", finding: makeFinding() });

    expect(result.created).toBe(false);
    expect(result.updated).toBe(true);
  });

  it("remembers the created issue in the store", async () => {
    const { client } = mockClient();
    const store = inMemoryStore();
    await pushFindingToJira(client, store, { caseId: "case-a", projectKey: "IR", finding: makeFinding() });
    const saved = await store.load("case-a");
    expect(saved.issueRefs["finding-1"]).toEqual({ id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" });
  });
});
