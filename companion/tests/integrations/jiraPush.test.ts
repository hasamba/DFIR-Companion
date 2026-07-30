import { describe, it, expect } from "vitest";
import type { Finding } from "../../src/analysis/stateTypes.js";
import { pushFindingToJira, pushFindingsToJira, type JiraExportStoreLike } from "../../src/integrations/jira/jiraPush.js";
import type { JiraClientLike } from "../../src/integrations/jira/jiraClient.js";

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

function mockClient(): { client: JiraClientLike; calls: unknown[]; created: number; updated: string[] } {
  const calls: unknown[] = [];
  const tally = { created: 0, updated: [] as string[] };
  const client: JiraClientLike = {
    me: async () => { calls.push("me"); return { id: "user-1", displayName: "Analyst" }; },
    createIssue: async (body) => {
      calls.push(body);
      tally.created += 1;
      return { id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" };
    },
    // Jira answers a real edit with 204, so the mock mirrors that: key echoed back, no id/url.
    updateIssue: async (idOrKey, body) => {
      calls.push(body);
      tally.updated.push(idOrKey);
      return { id: "", key: idOrKey, url: undefined };
    },
  };
  return { client, calls, get created() { return tally.created; }, get updated() { return tally.updated; } };
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

  it("UPDATES the remembered issue on re-push instead of creating a duplicate", async () => {
    const mock = mockClient();
    const store = inMemoryStore({ issueRefs: { "finding-1": { id: "x", key: "IR-1", url: "https://jira.example.com/browse/IR-1" } }, lastExportedAt: "" });
    const result = await pushFindingToJira(mock.client, store, { caseId: "case-a", projectKey: "IR", finding: makeFinding() });

    expect(result.created).toBe(false);
    expect(result.updated).toBe(true);
    expect(mock.created).toBe(0);          // no duplicate issue
    expect(mock.updated).toEqual(["IR-1"]); // edited the one we already opened
    // The 204 edit response must not blank out the id/url the create response gave us.
    expect(result.issue).toEqual({ id: "x", key: "IR-1", url: "https://jira.example.com/browse/IR-1" });
  });

  it("pushing the same finding twice creates once, then updates", async () => {
    const mock = mockClient();
    const store = inMemoryStore();
    const input = { caseId: "case-a", projectKey: "IR", finding: makeFinding() };

    const first = await pushFindingToJira(mock.client, store, input);
    const second = await pushFindingToJira(mock.client, store, input);

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.updated).toBe(true);
    expect(mock.created).toBe(1);
    expect(mock.updated).toEqual(["IR-42"]);
  });

  it("remembers the created issue in the store", async () => {
    const { client } = mockClient();
    const store = inMemoryStore();
    await pushFindingToJira(client, store, { caseId: "case-a", projectKey: "IR", finding: makeFinding() });
    const saved = await store.load("case-a");
    expect(saved.issueRefs["finding-1"]).toEqual({ id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" });
  });
});

// A client that files one issue per finding and can be told to reject specific ones, so a batch
// can be checked for "the failure is reported, the rest still go".
function bulkClient(failTitles: string[] = []): JiraClientLike {
  let n = 0;
  return {
    me: async () => ({ id: "user-1", displayName: "Analyst" }),
    createIssue: async (body) => {
      if (failTitles.some((t) => body.summary.includes(t))) throw new Error("Jira rejected the request: summary too long");
      n += 1;
      return { id: `issue-${n}`, key: `IR-${n}`, url: `https://jira.example.com/browse/IR-${n}` };
    },
    updateIssue: async (idOrKey) => ({ id: "", key: idOrKey, url: `https://jira.example.com/browse/${idOrKey}` }),
  };
}

describe("pushFindingsToJira", () => {
  it("files one issue per finding and counts them", async () => {
    const store = inMemoryStore();
    const findings = [makeFinding(), makeFinding({ id: "finding-2", title: "Persistence via Run key" })];
    const result = await pushFindingsToJira(bulkClient(), store, { caseId: "case-a", projectKey: "IR", findings });

    expect(result).toMatchObject({ created: 2, updated: 0, skipped: 0 });
    expect(result.issues.map((i) => i.findingId)).toEqual(["finding-1", "finding-2"]);
    expect(result.issues.map((i) => i.key)).toEqual(["IR-1", "IR-2"]);
    expect(result.warnings).toEqual([]);
  });

  it("keeps going when one finding fails, and reports which one", async () => {
    const store = inMemoryStore();
    const findings = [
      makeFinding(),
      makeFinding({ id: "finding-2", title: "Persistence via Run key" }),
      makeFinding({ id: "finding-3", title: "Exfil over DNS" }),
    ];
    const result = await pushFindingsToJira(bulkClient(["Persistence via Run key"]), store, { caseId: "case-a", projectKey: "IR", findings });

    expect(result).toMatchObject({ created: 2, updated: 0, skipped: 1 });
    expect(result.issues.map((i) => i.findingId)).toEqual(["finding-1", "finding-3"]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("Persistence via Run key");
    expect(result.warnings[0]).toContain("summary too long");
  });

  it("UPDATES the findings already pushed and creates only the new ones", async () => {
    const store = inMemoryStore({ issueRefs: { "finding-1": { id: "issue-9", key: "IR-9", url: "https://jira.example.com/browse/IR-9" } }, lastExportedAt: "" });
    const findings = [makeFinding(), makeFinding({ id: "finding-2", title: "Persistence via Run key" })];
    const result = await pushFindingsToJira(bulkClient(), store, { caseId: "case-a", projectKey: "IR", findings });

    expect(result).toMatchObject({ created: 1, updated: 1, skipped: 0 });
    const saved = await store.load("case-a");
    expect(Object.keys(saved.issueRefs).sort()).toEqual(["finding-1", "finding-2"]);
  });

  it("offers the first issue url so the dashboard can link the batch", async () => {
    const store = inMemoryStore();
    const result = await pushFindingsToJira(bulkClient(), store, { caseId: "case-a", projectKey: "IR", findings: [makeFinding()] });
    expect(result.issueUrl).toBe("https://jira.example.com/browse/IR-1");
  });

  it("does nothing on an empty batch", async () => {
    const store = inMemoryStore();
    const result = await pushFindingsToJira(bulkClient(), store, { caseId: "case-a", projectKey: "IR", findings: [] });
    expect(result).toMatchObject({ created: 0, updated: 0, skipped: 0, warnings: [] });
    expect(result.issues).toEqual([]);
  });
});
