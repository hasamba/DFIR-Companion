import { describe, it, expect } from "vitest";
import { evtxRecordIdentity } from "../../src/analysis/evtxRecordId.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The same physical Windows record, read by two different parsers (#688). An analyst who runs
// Hayabusa over Security.evtx and later runs Chainsaw over the SAME file must not end up with two
// timeline rows for one logon.
const CHANNEL = "Security";
const RECORD_ID = "884213";
const HOST = "WS-01";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T12:00:00Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

describe("evtxRecordIdentity", () => {
  it("mints a channel-scoped identity, lowercasing the channel", () => {
    expect(evtxRecordIdentity("Security", "884213")).toBe("evtx:security:884213");
    expect(evtxRecordIdentity("security", 884213)).toBe("evtx:security:884213");
  });

  it("refuses a half identity — both parts must be there", () => {
    expect(evtxRecordIdentity("", "884213")).toBeUndefined();
    expect(evtxRecordIdentity("Security", "")).toBeUndefined();
    expect(evtxRecordIdentity("Security", undefined)).toBeUndefined();
  });

  it("refuses a record id that is not a plain number, including a parser's placeholder zero", () => {
    expect(evtxRecordIdentity("Security", "abc")).toBeUndefined();
    expect(evtxRecordIdentity("Security", "12-34")).toBeUndefined();
    expect(evtxRecordIdentity("Security", "0")).toBeUndefined();
    expect(evtxRecordIdentity("Security", "000")).toBeUndefined();
  });

  it("keeps different channels on one host apart", () => {
    expect(evtxRecordIdentity("Security", "7")).not.toBe(evtxRecordIdentity("System", "7"));
  });
});

describe("the EVTX importers mint the record identity", () => {
  it("Hayabusa reads it from the RecordID column of a csv-timeline", () => {
    const csv = [
      "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details",
      `2026-05-26 12:00:00.000 +00:00,Suspicious Logon,high,${HOST},${CHANNEL},4624,${RECORD_ID},TgtUser: bob`,
    ].join("\n");
    const parsed = parseHayabusaTimeline(csv);
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].sourceRecordId).toBe(`evtx:security:${RECORD_ID}`);
  });

  it("Chainsaw reads it from the raw Event.System block it embeds", () => {
    const hunt = JSON.stringify([
      {
        group: "Sigma",
        name: "Suspicious Logon",
        level: "high",
        timestamp: "2026-05-26T12:00:00Z",
        document: {
          data: {
            Event: {
              System: {
                EventID: 4624,
                Channel: CHANNEL,
                Computer: HOST,
                EventRecordID: RECORD_ID,
                TimeCreated: { SystemTime: "2026-05-26T12:00:00Z" },
              },
              EventData: { TargetUserName: "bob" },
            },
          },
        },
      },
    ]);
    const parsed = parseChainsawReport(hunt);
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].sourceRecordId).toBe(`evtx:security:${RECORD_ID}`);
  });

  it("does NOT claim a record identity for an aggregated group, which stands for many records", () => {
    const rows = [1, 2, 3].map(
      (n) =>
        `2026-05-26 12:00:0${n}.000 +00:00,Repeated Logon Failure,low,${HOST},${CHANNEL},4625,${90000 + n},TgtUser: bob`,
    );
    const csv = ["Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details", ...rows].join("\n");
    const parsed = parseHayabusaTimeline(csv, { aggregate: true });
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].count).toBe(3);
    expect(parsed.events[0].sourceRecordId).toBeUndefined();
  });
});

describe("correlateEvents folds one record read by two parsers into one row (#688)", () => {
  const identity = `evtx:security:${RECORD_ID}`;

  it("merges the Hayabusa row and the Chainsaw row, keeping both tools as sources", () => {
    const hayabusa = ev({
      id: "h1e1",
      description: "Hayabusa: Suspicious Logon (EID 4624 Security) — TgtUser=bob",
      severity: "High",
      asset: HOST,
      sources: ["Hayabusa"],
      sourceRecordId: identity,
      mitreTechniques: ["T1078"],
    });
    const chainsaw = ev({
      id: "c2e1",
      description: "Sigma - Suspicious Logon: Logon by bob",
      severity: "Medium",
      asset: HOST,
      sources: ["Chainsaw"],
      sourceRecordId: identity,
      mitreTechniques: ["T1021"],
    });
    const merged = correlateEvents([hayabusa, chainsaw]);
    expect(merged).toHaveLength(1);
    expect(merged[0].sources?.sort()).toEqual(["Chainsaw", "Hayabusa"]);
    // The more severe reading supplies the shown text; nothing is silently downgraded.
    expect(merged[0].severity).toBe("High");
    expect(merged[0].mitreTechniques.sort()).toEqual(["T1021", "T1078"]);
  });

  it("keeps the SAME record on two hosts as two events", () => {
    const a = ev({ id: "h1", asset: "WS-01", sources: ["Hayabusa"], sourceRecordId: identity });
    const b = ev({ id: "c1", asset: "WS-02", sources: ["Chainsaw"], sourceRecordId: identity });
    expect(correlateEvents([a, b])).toHaveLength(2);
  });

  it("keeps TWO detections from the SAME parser on one record as two events", () => {
    // Two Sigma rules can match one 4688. They are two findings, not a duplicate — merging them
    // would delete one outright.
    const first = ev({
      id: "h1",
      description: "Hayabusa: LOLBin Execution (EID 4688 Security)",
      asset: HOST,
      sources: ["Hayabusa"],
      sourceRecordId: identity,
    });
    const second = ev({
      id: "h2",
      description: "Hayabusa: Suspicious Parent Process (EID 4688 Security)",
      asset: HOST,
      sources: ["Hayabusa"],
      sourceRecordId: identity,
    });
    expect(correlateEvents([first, second])).toHaveLength(2);
  });

  it("merges only ONE row per parser, leaving that parser's second detection standing", () => {
    const hayaA = ev({
      id: "h1",
      description: "Hayabusa: LOLBin Execution",
      asset: HOST,
      sources: ["Hayabusa"],
      sourceRecordId: identity,
    });
    const hayaB = ev({
      id: "h2",
      description: "Hayabusa: Suspicious Parent Process",
      asset: HOST,
      sources: ["Hayabusa"],
      sourceRecordId: identity,
    });
    const chainsaw = ev({
      id: "c1",
      description: "Sigma - LOLBin: rundll32 launched",
      asset: HOST,
      sources: ["Chainsaw"],
      sourceRecordId: identity,
    });
    const merged = correlateEvents([hayaA, hayaB, chainsaw]);
    expect(merged).toHaveLength(2);
    const withBoth = merged.find((e) => (e.sources ?? []).includes("Chainsaw"))!;
    expect(withBoth.sources?.sort()).toEqual(["Chainsaw", "Hayabusa"]);
  });

  it("leaves events without a record identity to the existing correlation steps", () => {
    const a = ev({ id: "a1", description: "one thing", asset: HOST, sources: ["Hayabusa"] });
    const b = ev({ id: "b1", description: "another thing", asset: HOST, sources: ["Chainsaw"] });
    expect(correlateEvents([a, b])).toHaveLength(2);
  });
});
