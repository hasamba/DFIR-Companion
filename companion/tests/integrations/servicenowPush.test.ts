import { describe, it, expect, vi } from "vitest";
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

function mockClient(): { client: ServiceNowClientLike; calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    client: {
      me: async () => { calls.push("me"); return { userId: "admin", userName: "admin" }; },
      createIncident: async (body) => {
        calls.push(body);
        return { id: "sys-100", number: "INC0012345", url: "https://snow.example.com/incident.do?sys_id=sys-100" };
      },
    },
    calls,
  };
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
});
