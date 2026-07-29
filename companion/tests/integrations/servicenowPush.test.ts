import { describe, it, expect } from "vitest";
import type { Finding } from "../../src/analysis/stateTypes.js";
import { pushFindingToServiceNow, pushFindingsToServiceNow, type ServiceNowClientLike, type ServiceNowExportStoreLike } from "../../src/integrations/servicenow/servicenowPush.js";

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

// One incident per finding, with the option to reject specific ones, so a batch can be checked for
// "the failure is reported, the rest still go".
function bulkClient(failTitles: string[] = []): ServiceNowClientLike {
  let n = 0;
  return {
    me: async () => ({ userId: "admin", userName: "admin" }),
    createIncident: async (body) => {
      if (failTitles.some((t) => body.shortDescription.includes(t))) throw new Error("ServiceNow permission denied");
      n += 1;
      return { id: `sys-${n}`, number: `INC000000${n}`, url: `https://snow.example.com/incident.do?sys_id=sys-${n}` };
    },
    updateIncident: async (sysId) => ({ id: sysId, number: "INC0012345", url: `https://snow.example.com/incident.do?sys_id=${sysId}` }),
  };
}

describe("pushFindingsToServiceNow", () => {
  it("opens one incident per finding and counts them", async () => {
    const store = inMemoryStore();
    const findings = [makeFinding(), makeFinding({ id: "finding-2", title: "Persistence via Run key" })];
    const result = await pushFindingsToServiceNow(bulkClient(), store, { caseId: "case-b", findings });

    expect(result).toMatchObject({ created: 2, updated: 0, skipped: 0 });
    expect(result.incidents.map((i) => i.findingId)).toEqual(["finding-1", "finding-2"]);
    expect(result.incidents.map((i) => i.number)).toEqual(["INC0000001", "INC0000002"]);
    expect(result.warnings).toEqual([]);
  });

  it("keeps going when one finding fails, and reports which one", async () => {
    const store = inMemoryStore();
    const findings = [
      makeFinding(),
      makeFinding({ id: "finding-2", title: "Persistence via Run key" }),
      makeFinding({ id: "finding-3", title: "Exfil over DNS" }),
    ];
    const result = await pushFindingsToServiceNow(bulkClient(["Persistence via Run key"]), store, { caseId: "case-b", findings });

    expect(result).toMatchObject({ created: 2, updated: 0, skipped: 1 });
    expect(result.incidents.map((i) => i.findingId)).toEqual(["finding-1", "finding-3"]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("Persistence via Run key");
    expect(result.warnings[0]).toContain("permission denied");
  });

  it("UPDATES the findings already pushed and opens incidents only for the new ones", async () => {
    const store = inMemoryStore({ incidentRefs: { "finding-1": { id: "sys-9", number: "INC0009", url: "https://snow.example.com/incident.do?sys_id=sys-9" } }, lastExportedAt: "" });
    const findings = [makeFinding(), makeFinding({ id: "finding-2", title: "Persistence via Run key" })];
    const result = await pushFindingsToServiceNow(bulkClient(), store, { caseId: "case-b", findings });

    expect(result).toMatchObject({ created: 1, updated: 1, skipped: 0 });
    const saved = await store.load("case-b");
    expect(Object.keys(saved.incidentRefs).sort()).toEqual(["finding-1", "finding-2"]);
  });

  it("offers the first incident url so the dashboard can link the batch", async () => {
    const store = inMemoryStore();
    const result = await pushFindingsToServiceNow(bulkClient(), store, { caseId: "case-b", findings: [makeFinding()] });
    expect(result.incidentUrl).toBe("https://snow.example.com/incident.do?sys_id=sys-1");
  });

  it("does nothing on an empty batch", async () => {
    const store = inMemoryStore();
    const result = await pushFindingsToServiceNow(bulkClient(), store, { caseId: "case-b", findings: [] });
    expect(result).toMatchObject({ created: 0, updated: 0, skipped: 0, warnings: [] });
    expect(result.incidents).toEqual([]);
  });
});
