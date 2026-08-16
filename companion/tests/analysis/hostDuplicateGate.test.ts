import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
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
