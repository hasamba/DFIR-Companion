// exchangeAuditImport — the ingest half of the Exchange UAL decoder (#931 item 2). Direct tests
// for isExchangeRecord / mapExchangeRow (#2170); tests/analysis/exchangeAudit.test.ts covers the
// separate decoder module, not this one.
import { describe, expect, it } from "vitest";
import { isExchangeRecord, mapExchangeRow } from "../../src/analysis/exchangeAuditImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const OWNER = "alice@example.invalid";
const ACTOR = "helpdesk@example.invalid";

const newInboxRule = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Id: "rec-1",
  CreationTime: "2024-05-01T10:00:00Z",
  Workload: "Exchange",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: ACTOR,
  ResultStatus: "True",
  ClientIP: "203.0.113.9",
  RecordType: 1,
  Operation: "New-InboxRule",
  ObjectId: OWNER,
  Parameters: [
    { Name: "Name", Value: "r" },
    { Name: "ForwardTo", Value: "x@attacker.invalid" },
  ],
  ...over,
});

describe("isExchangeRecord", () => {
  it.each([
    ["Exchange", true],
    ["exchange", true],
    ["  EXCHANGE  ", true],
    ["AzureActiveDirectory", false],
    ["ExchangeOnline", false],
    ["", false],
  ])("Workload %j → %s", (workload, expected) => {
    expect(isExchangeRecord({ Workload: workload })).toBe(expected);
  });

  it.each([
    ["an empty record", {}],
    ["a null Workload", { Workload: null }],
    ["a numeric Workload", { Workload: 7 }],
  ])("is false for %s", (_name, rec) => {
    expect(isExchangeRecord(rec)).toBe(false);
  });
});

describe("mapExchangeRow — happy path", () => {
  it("maps a forwarding New-InboxRule with actor, IP, canonical envelope and an IP IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapExchangeRow(newInboxRule(), sink, 4);
    expect(e).not.toBeNull();
    if (!e) return;
    expect(e.description).toContain(`M365 Exchange: New-InboxRule by ${ACTOR} from 203.0.113.9`);
    expect(e.timestamp).toContain("2024-05-01T10:00:00");
    expect(e.sources).toEqual(["Microsoft 365"]);
    expect(["Medium", "High", "Critical"]).toContain(e.severity);
    expect(e.mitre.length).toBeGreaterThan(0);
    expect(e.canonical?.event?.category).toBe("email");
    expect(e.canonical?.evidence?.rawRecords?.[0]).toMatchObject({ source: "m365-ual", locator: "record:4" });
    expect(e.canonical?.network?.source?.address).toBe("203.0.113.9");
    expect([...sink.values()].some((i) => i.type === "ip" && i.value === "203.0.113.9")).toBe(true);
  });

  it("omits the IP clause and IOC when ClientIP is absent", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapExchangeRow(newInboxRule({ ClientIP: undefined }), sink, 0);
    expect(e?.description).not.toContain(" from ");
    expect(sink.size).toBe(0);
  });
});

describe("mapExchangeRow — malformed records", () => {
  it.each([
    ["an empty record", {}],
    ["a non-Exchange workload", { Workload: "SharePoint", Operation: "FileAccessed" }],
    ["an Exchange record with an unknown RecordType", { Workload: "Exchange", RecordType: 999 }],
  ])("returns null for %s", (_name, rec) => {
    const sink = new Map<string, SiemIoc>();
    expect(mapExchangeRow(rec, sink, 0)).toBeNull();
    expect(sink.size).toBe(0);
  });

  it.each([
    ["Parameters as a string", newInboxRule({ Parameters: "not-an-array" })],
    ["Parameters as null", newInboxRule({ Parameters: null })],
    ["Parameters with null entries", newInboxRule({ Parameters: [null, 3, { Name: null }] })],
    ["a non-string UserId", newInboxRule({ UserId: { nested: true } })],
    ["an unparseable CreationTime", newInboxRule({ CreationTime: "yesterday-ish" })],
  ])("does not throw on %s", (_name, rec) => {
    expect(() => mapExchangeRow(rec, new Map(), 0)).not.toThrow();
  });
});
