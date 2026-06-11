import { describe, it, expect } from "vitest";
import {
  eventMatchesSearch,
  findingMatchesSearch,
  iocMatchesSearch,
  eventMatchesTimeRange,
} from "../../src/analysis/searchFilter.js";
import type { ForensicEvent, Finding, IOC } from "../../src/analysis/stateTypes.js";

function mkEvent(overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1", timestamp: "2025-01-15T12:00:00Z",
    description: "powershell.exe spawned encoded command",
    severity: "High", mitreTechniques: ["T1059.001"],
    relatedFindingIds: [], sourceScreenshots: [],
    asset: "WORKSTATION01", sources: ["Velociraptor"],
    ...overrides,
  };
}

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1", severity: "High",
    title: "Powershell execution via encoded command",
    description: "Attacker used encoded powershell to evade detection",
    relatedIocs: [], sourceScreenshots: [],
    mitreTechniques: ["T1059.001"],
    firstSeen: "2025-01-15T12:00:00Z",
    lastUpdated: "2025-01-15T12:00:00Z",
    status: "open",
    ...overrides,
  };
}

function mkIoc(overrides: Partial<IOC> = {}): IOC {
  return { id: "ioc1", type: "ip", value: "10.0.0.5", firstSeen: "2025-01-15T12:00:00Z", ...overrides };
}

describe("eventMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(eventMatchesSearch(mkEvent(), "")).toBe(true);
  });
  it("matches description substring (case-insensitive)", () => {
    expect(eventMatchesSearch(mkEvent(), "POWERSHELL")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "encoded")).toBe(true);
  });
  it("matches asset name", () => {
    expect(eventMatchesSearch(mkEvent(), "workstation01")).toBe(true);
  });
  it("matches MITRE technique", () => {
    expect(eventMatchesSearch(mkEvent(), "t1059")).toBe(true);
    expect(eventMatchesSearch(mkEvent(), "T1059.001")).toBe(true);
  });
  it("matches source tool", () => {
    expect(eventMatchesSearch(mkEvent(), "velociraptor")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(eventMatchesSearch(mkEvent(), "mimikatz")).toBe(false);
  });
  it("handles missing optional fields gracefully", () => {
    const e = mkEvent({ asset: undefined, sources: undefined, mitreTechniques: [] });
    expect(eventMatchesSearch(e, "powershell")).toBe(true);
    expect(eventMatchesSearch(e, "missing")).toBe(false);
  });
});

describe("findingMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(findingMatchesSearch(mkFinding(), "")).toBe(true);
  });
  it("matches title", () => {
    expect(findingMatchesSearch(mkFinding(), "powershell")).toBe(true);
    expect(findingMatchesSearch(mkFinding(), "encoded command")).toBe(true);
  });
  it("matches description", () => {
    expect(findingMatchesSearch(mkFinding(), "evade detection")).toBe(true);
  });
  it("matches MITRE technique", () => {
    expect(findingMatchesSearch(mkFinding(), "t1059")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(findingMatchesSearch(mkFinding(), "ransomware")).toBe(false);
  });
});

describe("iocMatchesSearch", () => {
  it("empty term matches everything", () => {
    expect(iocMatchesSearch(mkIoc(), "")).toBe(true);
  });
  it("matches value substring", () => {
    expect(iocMatchesSearch(mkIoc(), "10.0.0.5")).toBe(true);
    expect(iocMatchesSearch(mkIoc(), "10.0.0")).toBe(true);
  });
  it("matches type", () => {
    expect(iocMatchesSearch(mkIoc(), "ip")).toBe(true);
  });
  it("does not match unrelated term", () => {
    expect(iocMatchesSearch(mkIoc(), "domain")).toBe(false);
  });
  it("matches hash value", () => {
    const ioc = mkIoc({ type: "hash", value: "e3b0c44298fc1c149afb" });
    expect(iocMatchesSearch(ioc, "e3b0")).toBe(true);
    expect(iocMatchesSearch(ioc, "hash")).toBe(true);
  });
});

describe("eventMatchesTimeRange", () => {
  it("no bounds always matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, null)).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), undefined, undefined)).toBe(true);
  });
  it("event within range matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T00:00:00.000Z", "2025-01-16T00:00:00.000Z")).toBe(true);
  });
  it("event exactly on 'from' boundary matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T12:00:00Z", null)).toBe(true);
  });
  it("event exactly on 'to' boundary matches", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T12:00:00Z")).toBe(true);
  });
  it("event before 'from' does not match", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-16T00:00:00.000Z", null)).toBe(false);
  });
  it("event after 'to' does not match", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-14T00:00:00.000Z")).toBe(false);
  });
  it("event with empty timestamp always matches", () => {
    const e = mkEvent({ timestamp: "" });
    expect(eventMatchesTimeRange(e, "2025-01-01T00:00:00Z", "2025-01-14T00:00:00Z")).toBe(true);
  });
  it("only 'from' bound: events on-or-after pass, events before fail", () => {
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T12:00:00Z", null)).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), "2025-01-15T13:00:00Z", null)).toBe(false);
  });
  it("only 'to' bound: events on-or-before pass, events after fail", () => {
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T12:00:00Z")).toBe(true);
    expect(eventMatchesTimeRange(mkEvent(), null, "2025-01-15T11:00:00Z")).toBe(false);
  });
});
