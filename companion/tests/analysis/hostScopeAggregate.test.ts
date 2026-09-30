import { describe, it, expect } from "vitest";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { HostAliasIndex } from "../../src/analysis/hostAlias.js";
import {
  accumulate,
  aggregateHostEvidence,
  collectRawHostEvidence,
  emptyRawHostEvidence,
  foldRawHostEvidence,
  overlayFindingLinks,
  type HostEvidenceMap,
} from "../../src/analysis/hostScopeAggregate.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

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

  // #1231: a "-"/"*" Workstation Name (Windows' own unpopulated-field placeholder) was admitted as
  // a literal referenced host, producing a junk "-" entry in host-evidence aggregation.
  it("never treats a placeholder Workstation Name ('-' or '*') as a referenced host", () => {
    const acc = accumulate(
      [
        ev({
          id: "4",
          asset: "srv-file01",
          sources: ["Chainsaw"],
          canonical: { session: { terminal: "-" } } as ForensicEvent["canonical"],
        }),
        ev({
          id: "5",
          asset: "srv-file02",
          sources: ["Chainsaw"],
          canonical: { session: { terminal: "*" } } as ForensicEvent["canonical"],
        }),
      ],
      index,
      new Map(),
    );
    expect(acc.has("-")).toBe(false);
    expect(acc.has("*")).toBe(false);
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

// ---------------------------------------------------------------------------------------------
// #1881: the raw collection is cached per content version and folded under whatever alias index is
// current. The fold must reproduce accumulate() exactly, or caching changes the ledger's answer.

type NormalizedHost = {
  collected: boolean;
  sources: string[];
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  maxSeverity: Severity;
  findingIds: string[];
  referencedBy: string[];
};

function normalize(map: HostEvidenceMap): Record<string, NormalizedHost> {
  const out: Record<string, NormalizedHost> = {};
  for (const key of [...map.keys()].sort()) {
    const h = map.get(key)!;
    out[key] = {
      collected: h.collected,
      sources: [...h.sources].sort(),
      firstSeen: h.firstSeen,
      lastSeen: h.lastSeen,
      eventCount: h.eventCount,
      maxSeverity: h.maxSeverity,
      findingIds: [...h.findingIds].sort(),
      referencedBy: [...h.referencedBy].sort(),
    };
  }
  return out;
}

function expectFoldMatchesAccumulate(events: ForensicEvent[], idx: HostAliasIndex): void {
  const folded = foldRawHostEvidence(collectRawHostEvidence(events), idx);
  expect(normalize(folded)).toEqual(normalize(accumulate(events, idx, new Map())));
}

// Deterministic PRNG (mulberry32) so a failure reproduces.
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const HOST_SPELLINGS = [
  "WS-042",
  "ws-042",
  " ws-042 ",
  "ws-042.corp.example.com",
  "WS-042.CORP.EXAMPLE.COM.",
  "srv-file01",
  "SRV-FILE01.",
  "srv-file01.corp.example.com",
  "dc01",
  "DC01.corp.example.com",
  "ws-099",
  "ws-100",
  "old-name",
  "c.1234",
  "   ",
];
const TERMINALS = [...HOST_SPELLINGS, "-", "*", ""];
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const TIMESTAMPS = [
  "",
  "2026-05-01T00:00:00Z",
  "2026-05-02T10:00:00Z",
  "2026-05-03T12:00:00Z",
  "2026-05-09T23:59:59Z",
];

function randomEvents(seed: number, count: number): ForensicEvent[] {
  const rnd = prng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];
  const maybe = <T>(p: number, v: () => T): T | undefined => (rnd() < p ? v() : undefined);
  const events: ForensicEvent[] = [];
  for (let i = 0; i < count; i++) {
    const canonical = maybe(0.7, () => ({
      session: maybe(0.5, () => ({ terminal: pick(TERMINALS) })),
      target: maybe(0.4, () =>
        rnd() < 0.8 ? { kind: "host", name: pick(HOST_SPELLINGS) } : { kind: "user", name: "alice" },
      ),
      network: maybe(0.4, () => ({
        source: maybe(0.6, () => ({ hostname: pick(HOST_SPELLINGS) })),
        destination: maybe(0.6, () => ({ hostname: pick(HOST_SPELLINGS) })),
      })),
    }));
    events.push(
      ev({
        id: String(i),
        asset: maybe(0.85, () => pick(HOST_SPELLINGS)),
        timestamp: pick(TIMESTAMPS),
        severity: pick(SEVERITIES),
        sources: maybe(0.8, () => [pick(["Chainsaw", "THOR", "Hayabusa", "Defender"])]),
        relatedFindingIds: rnd() < 0.3 ? [pick(["f1", "f2", "f3", "f4"])] : [],
        canonical: canonical as ForensicEvent["canonical"],
      }),
    );
  }
  return events;
}

const fleetIndex = buildHostAliasIndex(
  [
    { hostname: "WS-042", fqdn: "ws-042.corp.example.com", clientId: "C.1234" },
    { hostname: "srv-file01", fqdn: "srv-file01.corp.example.com" },
    { hostname: "dc01", fqdn: "DC01.corp.example.com." },
  ],
  { "old-name": "ws-100", "ws-100": "ws-099" },
);

describe("foldRawHostEvidence", () => {
  it("equals accumulate on randomized events under an empty index", () => {
    for (const seed of [1, 2, 3]) expectFoldMatchesAccumulate(randomEvents(seed, 400), index);
  });

  it("equals accumulate on randomized events under a fleet + merge alias index", () => {
    for (const seed of [4, 5, 6]) expectFoldMatchesAccumulate(randomEvents(seed, 400), fleetIndex);
  });

  it("creates a referenced host from an event with no asset, with no referencedBy", () => {
    const events = [
      ev({ id: "1", canonical: { session: { terminal: "WS-099" } } as ForensicEvent["canonical"] }),
    ];
    expectFoldMatchesAccumulate(events, index);
    const host = foldRawHostEvidence(collectRawHostEvidence(events), index).get("ws-099")!;
    expect(host.collected).toBe(false);
    expect(host.referencedBy.size).toBe(0);
  });

  it("drops an edge whose owner and referenced alias resolve to the same host", () => {
    const events = [
      ev({
        id: "1",
        asset: "WS-042",
        canonical: {
          target: { kind: "host", name: "ws-042.corp.example.com" },
        } as ForensicEvent["canonical"],
      }),
    ];
    expectFoldMatchesAccumulate(events, fleetIndex);
    const folded = foldRawHostEvidence(collectRawHostEvidence(events), fleetIndex);
    expect([...folded.keys()]).toEqual(["ws-042.corp.example.com"]);
    expect(folded.get("ws-042.corp.example.com")!.referencedBy.size).toBe(0);
  });

  it("merges several raw owner spellings into one host", () => {
    const events = [
      ev({ id: "1", asset: "WS-042", severity: "Low", timestamp: "2026-05-03T00:00:00Z", sources: ["A"] }),
      ev({ id: "2", asset: "ws-042.corp.example.com.", severity: "High", timestamp: "", sources: ["B"] }),
      ev({ id: "3", asset: "c.1234", timestamp: "2026-05-01T00:00:00Z", relatedFindingIds: ["f1"] }),
    ];
    expectFoldMatchesAccumulate(events, fleetIndex);
    const host = foldRawHostEvidence(collectRawHostEvidence(events), fleetIndex).get(
      "ws-042.corp.example.com",
    )!;
    expect(host.eventCount).toBe(3);
    expect(host.maxSeverity).toBe("High");
    expect(host.firstSeen).toBe("2026-05-01T00:00:00Z");
    expect(host.lastSeen).toBe("2026-05-03T00:00:00Z");
    expect([...host.sources].sort()).toEqual(["A", "B"]);
    expect([...host.findingIds]).toEqual(["f1"]);
  });

  it("flags a host collected even when it was first seen only as a reference", () => {
    const events = [
      ev({
        id: "1",
        asset: "srv-file01",
        canonical: { session: { terminal: "ws-099" } } as ForensicEvent["canonical"],
      }),
      ev({ id: "2", asset: "WS-099" }),
    ];
    expectFoldMatchesAccumulate(events, index);
    expect(foldRawHostEvidence(collectRawHostEvidence(events), index).get("ws-099")!.collected).toBe(true);
  });

  it("gives each index its own answer from the same raw collection", () => {
    const events = randomEvents(7, 300);
    const raw = collectRawHostEvidence(events);
    expect(normalize(foldRawHostEvidence(raw, index))).toEqual(
      normalize(accumulate(events, index, new Map())),
    );
    expect(normalize(foldRawHostEvidence(raw, fleetIndex))).toEqual(
      normalize(accumulate(events, fleetIndex, new Map())),
    );
    expect(normalize(foldRawHostEvidence(raw, index))).toEqual(
      normalize(accumulate(events, index, new Map())),
    );
  });

  it("returns a fresh map: mutating one fold never leaks into the next", () => {
    const events = randomEvents(8, 200);
    const raw = collectRawHostEvidence(events);
    const first = foldRawHostEvidence(raw, fleetIndex);
    for (const host of first.values()) {
      host.eventCount += 100;
      host.sources.add("MUTATED");
      host.findingIds.add("MUTATED");
      host.referencedBy.add("MUTATED");
      host.maxSeverity = "Critical";
    }
    overlayFindingLinks([ev({ id: "x", asset: "brand-new", relatedFindingIds: ["f9"] })], fleetIndex, first);
    expect(normalize(foldRawHostEvidence(raw, fleetIndex))).toEqual(
      normalize(accumulate(events, fleetIndex, new Map())),
    );
  });

  it("collecting in several batches equals collecting in one", () => {
    const events = randomEvents(9, 300);
    let raw = emptyRawHostEvidence();
    for (let i = 0; i < events.length; i += 37) raw = collectRawHostEvidence(events.slice(i, i + 37), raw);
    expect(normalize(foldRawHostEvidence(raw, fleetIndex))).toEqual(
      normalize(foldRawHostEvidence(collectRawHostEvidence(events), fleetIndex)),
    );
    expectFoldMatchesAccumulate(events, fleetIndex);
  });
});
