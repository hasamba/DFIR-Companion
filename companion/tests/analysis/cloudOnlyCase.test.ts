import { describe, it, expect } from "vitest";
import { hasCloudProvenance, hasHostTelemetry, isCloudOnlyCase } from "../../src/analysis/cloudOnlyCase.js";
import { coverageEventAt } from "../../src/analysis/cloudMetadataAccess.js";
import { ualRowCanonical } from "../../src/analysis/cloudRowCanonical.js";
import { buildCollectionInventory } from "../../src/analysis/collectionInventory.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const T = "2026-11-01T10:00:00.000Z";

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const ualRow = (id: string): ForensicEvent =>
  ev(id, {
    description: "M365 New-InboxRule by alice@example.test",
    sources: ["Microsoft 365"],
    canonical: ualRowCanonical({
      operation: "New-InboxRule",
      user: "alice@example.test",
      ip: "",
      observed: T,
      normalized: T,
      failed: false,
      tenant: "",
      recordId: id,
      index: 0,
    }),
  });

const entra = (id: string): ForensicEvent =>
  ev(id, { description: "Entra sign-in: alice@example.test", sources: ["Entra ID"] });

describe("isCloudOnlyCase (#2555)", () => {
  it("is true for a UAL-only case", () => {
    expect(isCloudOnlyCase({ events: [ualRow("u1"), ualRow("u2")] })).toBe(true);
  });

  it("is true for an Entra sign-in-only case (no cloud canonical category)", () => {
    expect(isCloudOnlyCase({ events: [entra("s1")] })).toBe(true);
  });

  it("matches the Entra sign-in description prefix even without a source label", () => {
    expect(hasCloudProvenance(ev("s2", { description: "Entra sign-in: bob@example.test" }))).toBe(true);
  });

  it("is false once one row carries host process telemetry", () => {
    const events = [ualRow("u1"), ev("p1", { processName: "powershell.exe" })];
    expect(isCloudOnlyCase({ events })).toBe(false);
  });

  it("is false once one row names a host, or the inventory holds a host", () => {
    expect(isCloudOnlyCase({ events: [ualRow("u1"), ev("h1", { asset: "WS01" })] })).toBe(false);
    expect(isCloudOnlyCase({ events: [ualRow("u1")], hosts: ["WS01"] })).toBe(false);
  });

  it("ignores the generated metadata coverage row", () => {
    expect(isCloudOnlyCase({ events: [ualRow("u1"), coverageEventAt(T)] })).toBe(true);
    expect(isCloudOnlyCase({ events: [coverageEventAt(T)] })).toBe(false);
  });

  it("is false for an empty case and for a host-less case with no cloud evidence", () => {
    expect(isCloudOnlyCase({ events: [] })).toBe(false);
    expect(isCloudOnlyCase({ events: [ev("m1", { sources: ["Manual"] })] })).toBe(false);
  });

  it("hasHostTelemetry reads asset and processName", () => {
    expect(hasHostTelemetry(ev("a", { asset: " " }))).toBe(false);
    expect(hasHostTelemetry(ev("b", { asset: "WS01" }))).toBe(true);
  });
});

// The fixtures above are hand-built. These run real records through the M365 importer, so a change
// that starts stamping `asset` on tenant rows (and silently turns the cloud-only guard off) fails here.
describe("isCloudOnlyCase — rows from the real M365 / Entra importer (#2555)", () => {
  const imported = (records: unknown[]): ForensicEvent[] =>
    parseM365Audit(JSON.stringify(records)).events.map((e) => ({
      ...e,
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));
  const ualRecord = {
    Id: "11111111-1111-4111-8111-111111111111",
    CreationTime: "2026-11-01T10:00:00Z",
    RecordType: 1,
    Operation: "New-InboxRule",
    Workload: "Exchange",
    UserId: "alice@example.test",
    ClientIP: "203.0.113.7",
  };
  const signIn = {
    id: "22222222-2222-4222-8222-222222222222",
    createdDateTime: "2026-11-01T10:05:00Z",
    userPrincipalName: "alice@example.test",
    appDisplayName: "Office 365 Exchange Online",
    ipAddress: "203.0.113.7",
    status: { errorCode: 0 },
  };

  it("a UAL-only import is cloud-only, and the inventory has no host", () => {
    const events = imported([ualRecord]);
    expect(events.length).toBeGreaterThan(0);
    const inv = buildCollectionInventory({ events });
    expect(inv.hosts).toEqual([]);
    expect(isCloudOnlyCase({ events, hosts: inv.hosts })).toBe(true);
  });

  it("an Entra sign-in-only import is cloud-only, and the inventory has no host", () => {
    const events = imported([signIn]);
    expect(events.length).toBeGreaterThan(0);
    const inv = buildCollectionInventory({ events });
    expect(inv.hosts).toEqual([]);
    expect(isCloudOnlyCase({ events, hosts: inv.hosts })).toBe(true);
  });
});
