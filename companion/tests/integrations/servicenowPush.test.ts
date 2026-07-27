import { describe, it, expect } from "vitest";
import type { Finding } from "../../src/analysis/stateTypes.js";
import { pushFindingToServiceNow, type ServiceNowClientLike, type ServiceNowExportStoreLike } from "../../src/integrations/servicenow/servicenowPush.js";

function makeFinding(partial: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    title: "Suspicious PowerShell download cradle",
    description: "Encoded PowerShell payload downloaded from 192.0.2.5.",
    severity: "critical",
    confidence: 95,
    relatedIocs: ["ioc-1"],
    relatedEventIds: ["evt-1"],
    sourceScreenshots: [],
    mitreTechniques: ["T1059.001"],
    firstSeen: "2026-07-24T10:00:00Z",
    ...partial,
  } as Finding;
}

function inMemoryStore(initial: { incidentRefs: Record<string, { id: string; number: string; url?: string }>; lastExportedAt: string } = { incidentRefs: {}, lastExportedAt: "" }): ServiceNowExportStoreLike {
  let state = { ...initial, incidentRefs: { ...initial.incidentRefs } };
  return {
    load: async () => ({ ...state, incidentRefs: { ...state.incidentRefs } }),
    save: async (_caseId, refs) => { state = { ...state, incidentRefs: { ...state.incidentRefs, ...refs } }; },
  };
}

function mockClient(): { client: ServiceNowClientLike; calls: unknown[]; created: number; updated: string[] } {
  const calls: unknown[] = [];
  const tally = { created: 0, updated: [] as string[] };
  const client: ServiceNowClientLike = {
    me: async () => { calls.push("me"); return { userId: "admin", userName: "admin" }; },
    createIncident: async (body) => {
      calls.push(body);
      tally.created += 1;
      return { id: "sys-100", number: "INC0012345", url: "https://snow.example.com/incident.do?sys_id=sys-100" };
    },
    updateIncident: async (sysId, body) => {
      calls.push(body);
      tally.updated.push(sysId);
      return { id: sysId, number: "INC0012345", url: `https://snow.example.com/incident.do?sys_id=${sysId}` };
    },
  };
  return { client, calls, get created() { return tally.created; }, get updated() { return tally.updated; } };
}

describe("pushFindingToServiceNow", () => {
  it("creates an incident from a critical finding", async () => {
    const { client, calls } = mockClient();
    const store = inMemoryStore();
    const result = await pushFindingToServiceNow(client, store, { caseId: "case-b", finding: makeFinding() });

    expect(calls[0]).toBe("me");
    expect(result.created).toBe(true);
    expect(result.incident.number).toBe("INC0012345");
    const body = calls[1] as { urgency?: number; impact?: number; shortDescription: string };
    expect(body.urgency).toBe(1);
    expect(body.impact).toBe(1);
    expect(body.shortDescription).toContain("case-b");
  });

  it("passes caller, category and subcategory overrides", async () => {
    const { client, calls } = mockClient();
    const store = inMemoryStore();
    await pushFindingToServiceNow(client, store, {
      caseId: "case-b",
      finding: makeFinding(),
      caller: "analyst@example.com",
      category: "Security",
      subcategory: "Incident Response",
    });
    const body = calls[1] as { caller?: string; category?: string; subcategory?: string };
    expect(body.caller).toBe("analyst@example.com");
    expect(body.category).toBe("Security");
    expect(body.subcategory).toBe("Incident Response");
  });

  it("pushing the same finding twice opens one incident, then updates it", async () => {
    const mock = mockClient();
    const store = inMemoryStore();
    const input = { caseId: "case-b", finding: makeFinding() };

    const first = await pushFindingToServiceNow(mock.client, store, input);
    const second = await pushFindingToServiceNow(mock.client, store, input);

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.updated).toBe(true);
    expect(mock.created).toBe(1);            // no duplicate incident
    expect(mock.updated).toEqual(["sys-100"]);
    expect(second.incident.number).toBe("INC0012345");
  });
});
