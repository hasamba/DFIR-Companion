// The settle-time carry pass (#1495): rows the case already holds under a name it later learned
// was a former one are re-homed — and re-homed BACK when the case learns the pair is ambiguous.
// Only a row that kept the name it wrote (`assetRecord`) is ever touched.
import { describe, it, expect } from "vitest";
import { carryHostRenames } from "../../src/analysis/hostRenameCarry.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { createCanonicalEvent, type CanonicalEntity } from "../../src/analysis/canonicalEvent.js";

const envelope = (target: CanonicalEntity) =>
  createCanonicalEvent({
    event: { category: "other", type: "event" },
    time: { observed: "2025-12-05T03:02:24.000Z", normalized: "2025-12-05T03:02:24.000Z" },
    evidence: { rawRecords: [{ source: "windows-event", locator: "row:0" }] },
    producer: { importer: "windows-event", parserVersion: "1", mappingVersion: "windows-event-v1" },
    target,
  });

const OLD = "WIN-UK1GV882OK6";
const NEW = "DESKTOP-16OJFO6";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2025-12-05T03:02:24.000Z",
    description: `Security Logon (EID 4624) - vagrant @ ${over.asset ?? OLD}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function withLedger(events: ForensicEvent[], over: Partial<InvestigationState> = {}): InvestigationState {
  return {
    ...emptyState("C1"),
    forensicTimeline: events,
    hostRenames: [
      { formerName: OLD, currentName: NEW, until: "2026-08-26T13:49:52.000Z", basis: "machine-account" },
    ],
    ...over,
  };
}

describe("carryHostRenames — folding rows imported before the case learned the rename", () => {
  it("re-homes a bare row under the former name, with the note and the host target", () => {
    const row = ev({
      id: "e1",
      asset: OLD,
      assetRecord: OLD,
      canonical: envelope({ kind: "host", name: OLD }),
    });
    const { state, changed } = carryHostRenames(withLedger([row]));
    expect(changed).toBe(1);
    const out = state.forensicTimeline[0];
    expect(out.asset).toBe(NEW);
    expect(out.assetRecord).toBe(OLD);
    expect(out.description).toBe(
      `Security Logon (EID 4624) - vagrant @ ${OLD} [logged under former hostname ${OLD}]`,
    );
    expect(out.canonical?.target).toEqual({ kind: "host", name: NEW });
    expect(row.asset).toBe(OLD); // the input is not mutated
  });

  it("strips a sample-corpus note the fold contradicts, and leaves the severity alone", () => {
    const row = ev({
      id: "e1",
      asset: OLD,
      assetRecord: OLD,
      severity: "Info",
      description: `Hayabusa: x @ ${OLD} [detection sample corpus — ${OLD} is not a host in this collection]`,
    });
    const out = carryHostRenames(withLedger([row])).state.forensicTimeline[0];
    expect(out.description).toBe(`Hayabusa: x @ ${OLD} [logged under former hostname ${OLD}]`);
    expect(out.severity).toBe("Info");
  });

  it("is idempotent", () => {
    const once = carryHostRenames(withLedger([ev({ id: "e1", asset: OLD, assetRecord: OLD })]));
    const twice = carryHostRenames(once.state);
    expect(twice.changed).toBe(0);
    expect(twice.state).toBe(once.state);
  });

  it("re-homes a row BACK when the case later learns the pair is ambiguous", () => {
    const folded = carryHostRenames(withLedger([ev({ id: "e1", asset: OLD, assetRecord: OLD })])).state;
    expect(folded.forensicTimeline[0].asset).toBe(NEW);
    const ambiguous: InvestigationState = {
      ...folded,
      hostRenames: [
        ...(folded.hostRenames ?? []),
        { formerName: OLD, currentName: "DESKTOP-OTHER", until: "2026-08-27T00:00:00.000Z", basis: "6011" },
      ],
    };
    const { state, changed } = carryHostRenames(ambiguous);
    expect(changed).toBe(1);
    expect(state.forensicTimeline[0].asset).toBe(OLD);
    expect(state.forensicTimeline[0].description).not.toContain("former hostname");
  });

  it("re-homes a row BACK when a tighter bound now excludes it", () => {
    const folded = carryHostRenames(withLedger([ev({ id: "e1", asset: OLD, assetRecord: OLD })])).state;
    const tighter: InvestigationState = {
      ...folded,
      hostRenames: [{ formerName: OLD, currentName: NEW, until: "2025-01-01T00:00:00.000Z", basis: "6011" }],
    };
    expect(carryHostRenames(tighter).state.forensicTimeline[0].asset).toBe(OLD);
  });

  it("follows a chain through a row already folded to the middle name", () => {
    const row = ev({
      id: "e1",
      asset: "WIN-0NNTB2RTNB1",
      assetRecord: OLD,
      description: `x @ ${OLD} [logged under former hostname ${OLD}]`,
    });
    const state = withLedger([row], {
      hostRenames: [
        {
          formerName: OLD,
          currentName: "WIN-0NNTB2RTNB1",
          until: "2026-08-26T13:49:52.000Z",
          basis: "machine-account",
        },
        {
          formerName: "WIN-0NNTB2RTNB1",
          currentName: NEW,
          until: "2026-08-26T13:52:06.000Z",
          basis: "machine-account",
        },
      ],
    });
    const out = carryHostRenames(state).state.forensicTimeline[0];
    expect(out.asset).toBe(NEW);
    expect(out.description).toBe(`x @ ${OLD} [logged under former hostname ${OLD}]`);
  });
});

describe("carryHostRenames — what it never touches", () => {
  it("a row without assetRecord, whatever its asset says", () => {
    const rows = [
      ev({ id: "collector", asset: OLD }), // a collector-identified or forwarded row kept no record name
      ev({ id: "generic", asset: OLD, description: "Zeek conn 10.0.0.5 -> 10.0.0.9" }),
    ];
    const { state, changed } = carryHostRenames(withLedger(rows));
    expect(changed).toBe(0);
    expect(state.forensicTimeline.map((e) => e.asset)).toEqual([OLD, OLD]);
  });

  it("a row dated after the bound, or with no date", () => {
    const rows = [
      ev({ id: "late", asset: OLD, assetRecord: OLD, timestamp: "2026-09-01T00:00:00.000Z" }),
      ev({ id: "undated", asset: OLD, assetRecord: OLD, timestamp: "" }),
    ];
    expect(carryHostRenames(withLedger(rows)).changed).toBe(0);
  });

  it("a former name that is a live collector identity in the case", () => {
    const row = ev({ id: "e1", asset: OLD, assetRecord: OLD });
    const state = withLedger([row], { collectorHostnames: [`${OLD}.example.com`] });
    expect(carryHostRenames(state).changed).toBe(0);
  });

  it("a canonical target that is not a host", () => {
    const row = ev({
      id: "e1",
      asset: OLD,
      assetRecord: OLD,
      canonical: envelope({ kind: "account", name: "vagrant" }),
    });
    const out = carryHostRenames(withLedger([row])).state.forensicTimeline[0];
    expect(out.asset).toBe(NEW);
    expect(out.canonical?.target).toEqual({ kind: "account", name: "vagrant" });
  });

  it("a case with no ledger returns the same state object", () => {
    const state = { ...emptyState("C1"), forensicTimeline: [ev({ id: "e1", asset: OLD, assetRecord: OLD })] };
    const out = carryHostRenames(state);
    expect(out.changed).toBe(0);
    expect(out.state).toBe(state);
  });
});

// A carry made by an import while synthesis was waiting on the model survives the synthesis save:
// the ledger the import wrote is unioned in, and the pass re-runs over the merged timeline.
describe("mergeConcurrentAdditions — re-applies the ledger an import wrote during synthesis (#1495)", () => {
  it("keeps the re-homed row even though synthesis started from the pre-import snapshot", async () => {
    const { mergeConcurrentAdditions } = await import("../../src/analysis/ai/synthesisPersist.js");
    const stale = ev({ id: "e1", asset: OLD, assetRecord: OLD });
    const loaded: InvestigationState = { ...emptyState("C1"), forensicTimeline: [stale] };
    const next: InvestigationState = { ...loaded, lastSummary: "the model's summary" };
    const latest = carryHostRenames(withLedger([stale])).state;
    expect(latest.forensicTimeline[0].asset).toBe(NEW);
    const merged = mergeConcurrentAdditions(loaded, next, latest);
    expect(merged.hostRenames).toEqual(latest.hostRenames);
    expect(merged.forensicTimeline[0].asset).toBe(NEW);
    expect(merged.forensicTimeline[0].description).toContain(`[logged under former hostname ${OLD}]`);
    expect(merged.lastSummary).toBe("the model's summary");
  });
});
