import { describe, it, expect } from "vitest";
import { renderScopeSection } from "../../src/reports/scopeSection.js";
import type { HostScopeLedger, HostScopeRow } from "../../src/analysis/hostScope.js";

function row(over: Partial<HostScopeRow> = {}): HostScopeRow {
  return {
    name: "ws-042",
    presence: "collected",
    derivedStatus: "unknown",
    effectiveStatus: "cleared",
    eligibility: { eligible: true, criteria: [] },
    sources: [],
    firstSeen: "",
    lastSeen: "",
    eventCount: 0,
    referencedBy: [],
    fingerprint: "",
    ...over,
  };
}

function ledger(over: Partial<HostScopeLedger> = {}): HostScopeLedger {
  return {
    hosts: [],
    counts: { unknown: 3, suspected: 2, confirmed: 1, cleared: 4, "out-of-scope": 0 },
    referencedNeverCollected: 2,
    fleet: null,
    nearDuplicates: [],
    ...over,
  };
}

describe("renderScopeSection", () => {
  it("never claims hosts are clean", () => {
    const md = renderScopeSection(ledger());
    expect(md).toContain("no evidence of compromise was found on 4 host");
    expect(md.toLowerCase()).not.toContain("are clean");
  });

  it("reports the fleet figure with its snapshot date when present", () => {
    const md = renderScopeSection(
      ledger({ fleet: { enrolled: 5000, collected: 4200, snapshotAt: "2026-08-12T00:00:00Z" } }),
    );
    expect(md).toContain("4,200 of 5,000");
    expect(md).toContain("2026-08-12");
  });

  it("omits the fleet figure entirely when there is no snapshot", () => {
    expect(renderScopeSection(ledger())).not.toContain("enrolled endpoints");
  });

  it("reports collection gaps", () => {
    expect(renderScopeSection(ledger())).toContain("2 host(s) appear in the evidence");
  });

  it("counts stale clearances separately", () => {
    const md = renderScopeSection(ledger({ hosts: [row({ stale: "evidence changed" })] }));
    expect(md).toContain("1 clearance needs review");
  });
});
