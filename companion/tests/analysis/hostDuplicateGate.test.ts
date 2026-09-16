import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { buildHostBindingIndex, type HostBindingIndex } from "../../src/analysis/hostBinding.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
  pendingNetworkIdentityDuplicates,
} from "../../src/analysis/hostDuplicateGate.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

const EMPTY_INDEX = buildHostAliasIndex([], {});

describe("hostNamesFromState", () => {
  it("collects distinct assets and ignores blanks", () => {
    const s = emptyState("c1");
    s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11"), ev("c", "  "), ev("d", "DC01"));
    expect(hostNamesFromState(s).sort()).toEqual(["DC01", "WIN11"]);
  });
});

describe("pendingNearDuplicates", () => {
  it("flags a short-name/FQDN pair nothing has linked", () => {
    const pending = pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, []);
    expect(pending).toHaveLength(1);
    expect(pending[0].canonical).toBe("win11.windomain.local");
    expect(pending[0].other).toBe("win11");
  });

  it("does not flag a pair the fleet roster already links", () => {
    const index = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "win11", fqdn: "win11.windomain.local" }],
      {},
    );
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], index, [])).toEqual([]);
  });

  it("does not flag a pair the analyst has merged", () => {
    const index = buildHostAliasIndex([], { win11: "win11.windomain.local" });
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], index, [])).toEqual([]);
  });

  it("does not flag a pair the analyst has dismissed", () => {
    const dismissals = [
      { canonical: "win11.windomain.local", other: "win11", dismissedAt: "t", dismissedBy: "a" },
    ];
    expect(pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, dismissals)).toEqual([]);
  });

  it("a dismissal of one pair does not suppress a different pair", () => {
    const dismissals = [{ canonical: "a.corp", other: "a", dismissedAt: "t", dismissedBy: "x" }];
    const pending = pendingNearDuplicates(["WIN11", "WIN11.windomain.local"], EMPTY_INDEX, dismissals);
    expect(pending).toHaveLength(1);
  });

  it("yields one pair per short/FQDN combination when a host has three spellings", () => {
    const pending = pendingNearDuplicates(
      ["win11", "win11.example.com", "win11.corp.local"],
      EMPTY_INDEX,
      [],
    );
    expect(pending).toHaveLength(2);
  });

  it("returns nothing when there is only one spelling", () => {
    expect(pendingNearDuplicates(["WIN11", "DC01"], EMPTY_INDEX, [])).toEqual([]);
  });
});

// Windows 4624 fixture matching hostBinding.ts's own directionality: recorded ON the file server
// (`sessionHost`), the CLIENT's own name is Workstation Name, never the session host.
let seq = 0;
function logonEvent(o: { sessionHost: string; clientName: string; ip: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `id-${seq}`,
    timestamp: o.ts,
    description: `Windows Security logon @ ${o.sessionHost}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.sessionHost,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: o.sessionHost },
      authentication: { logonType: 3 },
      session: { terminal: o.clientName },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function bindingIndexFor(events: readonly ForensicEvent[]): HostBindingIndex {
  return buildHostBindingIndex(events);
}

describe("pendingNetworkIdentityDuplicates", () => {
  it("flags an IP-shaped host name that resolves unambiguously to a real machine", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const pending = pendingNetworkIdentityDuplicates(
      ["10.0.0.5"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      [],
    );
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ canonical: "ws-042", other: "10.0.0.5", reason: "network-identity" });
    expect(pending[0].sampleTime).toBe("2026-06-10T12:00:00Z");
  });

  it("does not flag an IP bound to two different hosts (ambiguous)", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-001", ip: "10.0.0.9", ts: "2026-06-10T08:00:00Z" }),
      logonEvent({ sessionHost: "fs-01", clientName: "ws-002", ip: "10.0.0.9", ts: "2026-06-10T20:00:00Z" }),
    ];
    const pending = pendingNetworkIdentityDuplicates(
      ["10.0.0.9"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      [],
    );
    expect(pending).toEqual([]);
  });

  it("does not flag an IP with no binding evidence at all", () => {
    const pending = pendingNetworkIdentityDuplicates(
      ["10.0.0.9"],
      buildHostAliasIndex([], {}),
      bindingIndexFor([]),
      [],
    );
    expect(pending).toEqual([]);
  });

  it("does not flag an IP already aliased to a real name", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostAliasIndex([], { "10.0.0.5": "ws-042" });
    const pending = pendingNetworkIdentityDuplicates(["10.0.0.5"], index, bindingIndexFor(events), []);
    expect(pending).toEqual([]);
  });

  it("does not resurface a dismissed pair", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const dismissals = [{ canonical: "ws-042", other: "10.0.0.5", dismissedAt: "t", dismissedBy: "a" }];
    const pending = pendingNetworkIdentityDuplicates(
      ["10.0.0.5"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      dismissals,
    );
    expect(pending).toEqual([]);
  });

  it("never flags an IPv6-shaped host name, even with matching binding evidence", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "fe80::1",
        ip: "10.0.0.5",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    // fe80::1 itself as the host name under review — must never be flagged regardless of any
    // binding evidence, since IPv6 is out of scope for this feature (see PLAN-1163.md).
    const pending = pendingNetworkIdentityDuplicates(
      ["fe80::1"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      [],
    );
    expect(pending).toEqual([]);
  });

  it("does not flag a binding that resolves to the IP itself (self-referential)", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "10.0.0.5",
        ip: "10.0.0.5",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const pending = pendingNetworkIdentityDuplicates(
      ["10.0.0.5"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      [],
    );
    expect(pending).toEqual([]);
  });

  it("does not flag a non-IP host name at all", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const pending = pendingNetworkIdentityDuplicates(
      ["ws-042", "WIN11"],
      buildHostAliasIndex([], {}),
      bindingIndexFor(events),
      [],
    );
    expect(pending).toEqual([]);
  });
});

describe("HostMergeDecisionRequired", () => {
  it("carries the pairs and names itself", () => {
    const err = new HostMergeDecisionRequired([
      { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" },
    ]);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("HostMergeDecisionRequired");
    expect(err.pairs).toHaveLength(1);
    expect(err.message).toContain("1");
  });
});
