import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

// #2096 — Microsoft Sentinel / Log Analytics exports carry the event time only in
// `TimeGenerated` (and the collector clock in `TimeCollected`). Both importers must use
// `TimeGenerated` as a fallback, never `TimeCollected`, and never over a native time key.

const securityEvent = (extra: Record<string, unknown> = {}) => ({
  Type: "SecurityEvent",
  EventID: 4624,
  Computer: "ws1.example.test",
  Account: "EXAMPLE\\alice",
  LogonType: 3,
  TimeGenerated: "2021-08-02T13:09:20.04Z",
  TimeCollected: "2021-08-02T13:10:01Z",
  ...extra,
});

const officeActivity = (extra: Record<string, unknown> = {}) => ({
  Type: "OfficeActivity",
  RecordType: "ExchangeItem",
  Operation: "MailItemsAccessed",
  OfficeWorkload: "Exchange",
  UserId: "alice@example.test",
  ClientIP: "203.0.113.7",
  TimeGenerated: "2021-08-02T14:00:00Z",
  ...extra,
});

describe("Sentinel TimeGenerated — SIEM import (#2096)", () => {
  it("uses TimeGenerated, not TimeCollected, when no native time key exists", () => {
    const r = parseSiemExport(JSON.stringify([securityEvent()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toMatch(/^2021-08-02T13:09:20/);
  });

  it("keeps a native EventTime over TimeGenerated", () => {
    const r = parseSiemExport(JSON.stringify([securityEvent({ EventTime: "2021-08-02T12:00:00Z" })]));
    expect(r.events[0].timestamp).toMatch(/^2021-08-02T12:00:00/);
  });
});

describe("Sentinel TimeGenerated — OfficeActivity import (#2096)", () => {
  it("uses TimeGenerated when CreationTime is absent", () => {
    const r = parseM365Audit(JSON.stringify([officeActivity()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toMatch(/^2021-08-02T14:00:00/);
  });

  it("keeps CreationTime over TimeGenerated", () => {
    const r = parseM365Audit(JSON.stringify([officeActivity({ CreationTime: "2021-08-02T13:30:00Z" })]));
    expect(r.events[0].timestamp).toMatch(/^2021-08-02T13:30:00/);
  });
});
