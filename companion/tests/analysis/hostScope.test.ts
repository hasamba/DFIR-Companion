import { describe, it, expect } from "vitest";
import {
  buildHostScopeLedger,
  evidenceFingerprint,
  emptyHostFingerprint,
} from "../../src/analysis/hostScope.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { HostEvidence, HostEvidenceMap } from "../../src/analysis/hostScopeAggregate.js";
import type { HostScopeDecision } from "../../src/analysis/hostScopeStore.js";

function evidence(over: Partial<HostEvidence> = {}): HostEvidence {
  return {
    collected: true,
    sources: new Set(["Microsoft Defender"]),
    firstSeen: "2026-05-01T00:00:00Z",
    lastSeen: "2026-05-11T00:00:00Z",
    eventCount: 5,
    maxSeverity: "Info",
    findingIds: new Set(),
    referencedBy: new Set(),
    ...over,
  };
}

const WINDOW = { start: "2026-05-01T00:00:00Z", end: "2026-05-11T00:00:00Z" };

function ledgerOf(map: HostEvidenceMap, decisions: HostScopeDecision[] = []) {
  return buildHostScopeLedger({
    evidence: map,
    decisions,
    window: WINDOW,
    caseTactics: [],
    clients: [],
    fleetSnapshotAt: "",
    nearDuplicates: [],
  });
}

describe("derived status", () => {
  it("escalates to suspected on a High event", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ maxSeverity: "High" })]]);
    expect(ledgerOf(map).hosts[0].derivedStatus).toBe("suspected");
  });

  it("escalates to confirmed when a finding references the host", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ findingIds: new Set(["f1"]) })]]);
    expect(ledgerOf(map).hosts[0].derivedStatus).toBe("confirmed");
  });

  it("classifies a referenced-only host and explains the gap", () => {
    const map: HostEvidenceMap = new Map([
      [
        "ws-099",
        evidence({
          collected: false,
          sources: new Set(),
          eventCount: 0,
          referencedBy: new Set(["srv-file01"]),
        }),
      ],
    ]);
    const row = ledgerOf(map).hosts[0];
    expect(row.presence).toBe("referenced");
    expect(row.gap).toContain("never collected");
  });
});

describe("decisions", () => {
  const cleared: HostScopeDecision = {
    host: "ws-042",
    from: "unknown",
    to: "cleared",
    reason: "full coverage",
    analyst: "a.analyst@example.invalid",
    at: "2026-08-13T09:41:00Z",
    basis: {
      sources: ["Microsoft Defender"],
      windowCovered: true,
      tacticsCovered: [],
      evidenceFingerprint: "",
    },
  };

  it("lets a decision win over derivation when its basis still matches", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence()]]);
    const fingerprint = evidenceFingerprint(evidence(), WINDOW, []);
    const row = ledgerOf(map, [{ ...cleared, basis: { ...cleared.basis, evidenceFingerprint: fingerprint } }])
      .hosts[0];
    expect(row.effectiveStatus).toBe("cleared");
    expect(row.stale).toBeUndefined();
  });

  it("flags a clearance as stale when evidence changed, without reverting it", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ eventCount: 99 })]]);
    const fingerprint = evidenceFingerprint(evidence(), WINDOW, []);
    const row = ledgerOf(map, [{ ...cleared, basis: { ...cleared.basis, evidenceFingerprint: fingerprint } }])
      .hosts[0];
    expect(row.effectiveStatus).toBe("cleared");
    expect(row.stale).toBeTruthy();
  });

  it("keeps a decided host in the ledger even when the case holds no evidence for it", () => {
    const decided = { ...cleared, host: "ws-500", to: "out-of-scope" as const };
    const ledger = ledgerOf(new Map(), [decided]);
    const row = ledger.hosts.find((h) => h.name === "ws-500")!;
    expect(row.effectiveStatus).toBe("out-of-scope");
  });

  it("does not flag a first decision on an evidence-less host as stale", () => {
    const fingerprint = emptyHostFingerprint(WINDOW, []);
    const decided = {
      ...cleared,
      host: "ws-500",
      to: "out-of-scope" as const,
      basis: { ...cleared.basis, evidenceFingerprint: fingerprint },
    };
    const row = ledgerOf(new Map(), [decided]).hosts.find((h) => h.name === "ws-500")!;
    expect(row.stale).toBeUndefined();
  });

  it("reopen returns a host to its derived status and cannot hide a finding", () => {
    // A confirmed host that an analyst reopens must not read as `unknown`: one click would
    // otherwise bury a Critical finding behind a stale flag.
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ findingIds: new Set(["f1"]) })]]);
    const reopened = { ...cleared, to: "unknown" as const, at: "2026-08-13T13:00:00Z" };
    const row = ledgerOf(map, [reopened]).hosts[0];
    expect(row.derivedStatus).toBe("confirmed");
    expect(row.effectiveStatus).toBe("confirmed");
  });

  it("reopen leaves no stale clearance behind — there is no clearance left to be stale", () => {
    // Evidence has moved since the decision was recorded, which would flag a live clearance.
    // A reopen retracts the claim, so nothing should surface as "clearance needs review".
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ eventCount: 99 })]]);
    const reopened = {
      ...cleared,
      to: "unknown" as const,
      at: "2026-08-13T13:00:00Z",
      basis: { ...cleared.basis, evidenceFingerprint: "a-stale-fingerprint" },
    };
    const row = ledgerOf(map, [reopened]).hosts[0];
    expect(row.stale).toBeUndefined();
  });

  it("still flags a live clearance whose evidence moved", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence({ eventCount: 99 })]]);
    const stillCleared = {
      ...cleared,
      basis: { ...cleared.basis, evidenceFingerprint: "a-stale-fingerprint" },
    };
    expect(ledgerOf(map, [stillCleared]).hosts[0].stale).toBeTruthy();
  });

  it("reopen still falls back to a quiet derived status when the evidence is quiet", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence()]]);
    const reopened = { ...cleared, to: "unknown" as const, at: "2026-08-13T13:00:00Z" };
    expect(ledgerOf(map, [reopened]).hosts[0].effectiveStatus).toBe("unknown");
  });

  it("applies the latest decision for a host", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence()]]);
    const row = ledgerOf(map, [cleared, { ...cleared, to: "confirmed", at: "2026-08-13T12:00:00Z" }])
      .hosts[0];
    expect(row.effectiveStatus).toBe("confirmed");
  });
});

describe("coverage figures", () => {
  it("counts enrolled-only hosts from the fleet and reports both figures", () => {
    const map: HostEvidenceMap = new Map([["ws-042", evidence()]]);
    const ledger = buildHostScopeLedger({
      evidence: map,
      decisions: [],
      window: WINDOW,
      caseTactics: [],
      clients: [
        { clientId: "C.1", hostname: "ws-042", fqdn: "ws-042" },
        { clientId: "C.2", hostname: "ws-500", fqdn: "ws-500" },
      ],
      fleetSnapshotAt: "2026-08-12T00:00:00Z",
      nearDuplicates: [],
    });
    expect(ledger.fleet).toEqual({ enrolled: 2, collected: 1, snapshotAt: "2026-08-12T00:00:00Z" });
    expect(ledger.hosts.find((h) => h.name === "ws-500")!.presence).toBe("enrolled-only");
  });

  it("reports no fleet figure when there is no snapshot", () => {
    expect(ledgerOf(new Map([["ws-042", evidence()]])).fleet).toBeNull();
  });
});

// An analyst merge re-points a host's canonical identity. Evidence is aggregated through the alias
// index, so it lands on the merged name — the fleet roster and the decision log must be read through
// the same index or the same machine splits into two rows, and a clearance recorded against the
// pre-merge spelling detaches from the host it was granted for.
describe("alias merges", () => {
  const MERGE = { "ws-042.corp.local": "ws-042.example.invalid" };
  const CLIENTS = [{ clientId: "C.1", hostname: "ws-042", fqdn: "ws-042.corp.local" }];

  function mergedLedger(decisions: HostScopeDecision[] = []) {
    return buildHostScopeLedger({
      evidence: new Map([["ws-042.example.invalid", evidence()]]),
      decisions,
      window: WINDOW,
      caseTactics: [],
      clients: CLIENTS,
      fleetSnapshotAt: "2026-08-12T00:00:00Z",
      nearDuplicates: [],
      aliasIndex: buildHostAliasIndex(CLIENTS, MERGE),
    });
  }

  it("keeps a merged host as one row instead of splitting it across both spellings", () => {
    const ledger = mergedLedger();
    expect(ledger.hosts.map((h) => h.name)).toEqual(["ws-042.example.invalid"]);
    expect(ledger.counts.unknown).toBe(1);
  });

  it("counts the merged host as collected against the fleet", () => {
    expect(mergedLedger().fleet).toEqual({
      enrolled: 1,
      collected: 1,
      snapshotAt: "2026-08-12T00:00:00Z",
    });
  });

  it("keeps a clearance recorded against the pre-merge spelling attached to the host", () => {
    const decision: HostScopeDecision = {
      host: "ws-042.corp.local",
      from: "unknown",
      to: "cleared",
      reason: "full coverage",
      analyst: "a.analyst@example.invalid",
      at: "2026-08-13T09:41:00Z",
      basis: {
        sources: ["Microsoft Defender"],
        windowCovered: true,
        tacticsCovered: [],
        evidenceFingerprint: evidenceFingerprint(evidence(), WINDOW, []),
      },
    };
    const ledger = mergedLedger([decision]);
    expect(ledger.hosts).toHaveLength(1);
    expect(ledger.hosts[0].effectiveStatus).toBe("cleared");
    expect(ledger.counts.cleared).toBe(1);
  });
});
