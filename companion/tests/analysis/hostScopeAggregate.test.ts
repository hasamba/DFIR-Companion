import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import {
  accumulate,
  aggregateHostEvidence,
  overlayFindingLinks,
} from "../../src/analysis/hostScopeAggregate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-02T10:00:00Z",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

const index = buildHostAliasIndex([], {});

describe("accumulate", () => {
  it("marks a host with its own telemetry as collected and records its sources", () => {
    const acc = accumulate(
      [
        ev({ id: "1", asset: "WS-042", sources: ["Chainsaw"], severity: "High" }),
        ev({
          id: "2",
          asset: "ws-042",
          sources: ["Microsoft Defender"],
          timestamp: "2026-05-04T08:00:00Z",
        }),
      ],
      index,
      new Map(),
    );
    const host = acc.get("ws-042")!;
    expect(host.collected).toBe(true);
    expect([...host.sources].sort()).toEqual(["Chainsaw", "Microsoft Defender"]);
    expect(host.eventCount).toBe(2);
    expect(host.maxSeverity).toBe("High");
    expect(host.firstSeen).toBe("2026-05-02T10:00:00Z");
    expect(host.lastSeen).toBe("2026-05-04T08:00:00Z");
  });

  it("records a logon source workstation as referenced, not collected", () => {
    const acc = accumulate(
      [
        ev({
          id: "3",
          asset: "srv-file01",
          sources: ["Chainsaw"],
          canonical: { session: { terminal: "WS-099" } } as ForensicEvent["canonical"],
        }),
      ],
      index,
      new Map(),
    );
    expect(acc.get("srv-file01")!.collected).toBe(true);
    const referenced = acc.get("ws-099")!;
    expect(referenced.collected).toBe(false);
    expect([...referenced.referencedBy]).toEqual(["srv-file01"]);
  });

  it("does not treat a canonical target equal to the event's own asset as a reference", () => {
    const acc = accumulate(
      [
        ev({
          id: "4",
          asset: "ws-042",
          canonical: { target: { kind: "host", name: "ws-042" } } as ForensicEvent["canonical"],
        }),
      ],
      index,
      new Map(),
    );
    expect(acc.size).toBe(1);
    expect(acc.get("ws-042")!.collected).toBe(true);
  });

  it("collects finding ids per host", () => {
    const acc = accumulate(
      [ev({ id: "5", asset: "ws-042", relatedFindingIds: ["f1", "f2"] })],
      index,
      new Map(),
    );
    expect([...acc.get("ws-042")!.findingIds].sort()).toEqual(["f1", "f2"]);
  });
});

describe("overlayFindingLinks", () => {
  it("attaches finding links the super-timeline never carries", () => {
    // The super-timeline pass sees the host but no findings — synthesis only writes
    // relatedFindingIds onto state.forensicTimeline, which is never folded into the super-timeline.
    const acc = accumulate([ev({ id: "1", asset: "ws-042", sources: ["Chainsaw"] })], index, new Map());
    expect(acc.get("ws-042")!.findingIds.size).toBe(0);

    overlayFindingLinks(
      [ev({ id: "1", asset: "ws-042", relatedFindingIds: ["f1"], severity: "Critical" })],
      index,
      acc,
    );
    expect([...acc.get("ws-042")!.findingIds]).toEqual(["f1"]);
    expect(acc.get("ws-042")!.maxSeverity).toBe("Critical");
  });

  it("does not double-count events for a host the super-timeline already covered", () => {
    const acc = accumulate([ev({ id: "1", asset: "ws-042" })], index, new Map());
    overlayFindingLinks([ev({ id: "1", asset: "ws-042", relatedFindingIds: ["f1"] })], index, acc);
    expect(acc.get("ws-042")!.eventCount).toBe(1);
  });

  it("adds a host that exists only in the forensic timeline", () => {
    const acc = accumulate([], index, new Map());
    overlayFindingLinks([ev({ id: "9", asset: "ws-777", relatedFindingIds: ["f2"] })], index, acc);
    expect(acc.get("ws-777")!.collected).toBe(true);
    expect([...acc.get("ws-777")!.findingIds]).toEqual(["f2"]);
  });
});

describe("aggregateHostEvidence", () => {
  it("folds every batch into one map", async () => {
    const store = {
      async *eventBatches() {
        yield [ev({ id: "1", asset: "ws-042", sources: ["Chainsaw"] })];
        yield [ev({ id: "2", asset: "ws-043", sources: ["THOR"] })];
      },
    };
    const acc = await aggregateHostEvidence(store, "case-1", index);
    expect([...acc.keys()].sort()).toEqual(["ws-042", "ws-043"]);
  });
});
