import { describe, it, expect } from "vitest";
import { parseExporterFlowNdjson, isNfdumpFlowRecord } from "../../src/analysis/exporterFlowImport.js";

// Shape verified live against nfdump's own src/output/output_json.c (stringEXgenericFlow,
// stringEXipv4Flow, and the exporter-context field emitters) — not invented.
function record(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    first: "2026-01-01T00:00:00.000",
    last: "2026-01-01T00:00:05.000",
    received: "2026-01-01T00:05:00.000",
    proto: 6,
    src4_addr: "10.0.0.5",
    dst4_addr: "203.0.113.9",
    src_port: 51000,
    dst_port: 443,
    tcp_flags: ".S....",
    in_bytes: 1000,
    in_packets: 10,
    export_sysid: 1,
    observationPointID: 5,
    sampled: 0,
    ...overrides,
  };
}

function ndjson(records: Record<string, unknown>[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

describe("isNfdumpFlowRecord", () => {
  it("recognizes a real nfdump flow record", () => {
    expect(isNfdumpFlowRecord(record())).toBe(true);
  });

  it("rejects a record missing export_sysid", () => {
    const bad = record();
    delete bad.export_sysid;
    expect(isNfdumpFlowRecord(bad)).toBe(false);
  });

  it("rejects a plain unrelated JSON object", () => {
    expect(isNfdumpFlowRecord({ hello: "world" })).toBe(false);
  });
});

describe("parseExporterFlowNdjson — malformed input", () => {
  it("returns null for an empty string", () => {
    expect(parseExporterFlowNdjson("")).toBeNull();
  });

  it("returns null when no line is a valid nfdump flow record", () => {
    expect(parseExporterFlowNdjson('{"hello":"world"}')).toBeNull();
  });

  it("counts an unparsable JSON line as malformed, never crashes", () => {
    const text = `${JSON.stringify(record())}\nnot json at all`;
    const r = parseExporterFlowNdjson(text)!;
    expect(r.flowCount).toBe(1);
    expect(r.malformedRecords).toBe(1);
  });
});

describe("parseExporterFlowNdjson — a single flow", () => {
  it("maps to an Info-severity structural event, never a current-state verdict", () => {
    const r = parseExporterFlowNdjson(ndjson([record()]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow);
    expect(flow).toBeDefined();
    expect(flow!.severity).toBe("Info");
    const block = flow!.canonical!.exporterFlow!;
    expect(block.srcAddr).toBe("10.0.0.5");
    expect(block.dstAddr).toBe("203.0.113.9");
    expect(block.exporterSysId).toBe(1);
    expect(block.sampled).toBe(false);
    expect(flow!.description).toContain("never a current-state verdict");
  });

  it("coerces nfdump's own numeric sampled field (0/1) to a real boolean (Codex code review finding)", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ sampled: 1 })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.sampled).toBe(true);
    expect(flow.description).toContain("sampled, an estimate");
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata", () => {
    const r = parseExporterFlowNdjson(ndjson([record()]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.mappingVersion).toBe("exporter-flow-v1");
    expect(flow.canonical!.producer.mappingVersion).toBe(flow.canonical!.exporterFlow!.mappingVersion);
  });
});

describe("parseExporterFlowNdjson — interim-record normalization (the spec's own central ask)", () => {
  it("merges two temporally-adjacent records of the SAME flow (an active-timeout re-export) into one logical flow", () => {
    const r1 = record({
      first: "2026-01-01T00:00:00.000",
      last: "2026-01-01T00:01:00.000",
      in_bytes: 1000,
      in_packets: 10,
    });
    const r2 = record({
      first: "2026-01-01T00:01:02.000", // 2s after r1's last — within the 5s merge gap
      last: "2026-01-01T00:02:00.000",
      in_bytes: 500,
      in_packets: 5,
    });
    const r = parseExporterFlowNdjson(ndjson([r1, r2]))!;
    expect(r.flowCount).toBe(1);
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!.canonical!.exporterFlow!;
    expect(flow.mergedRecordCount).toBe(2);
    expect(flow.inBytes).toBe(1500);
    expect(flow.inPackets).toBe(15);
  });

  it("does NOT merge two records of the same tuple separated by a gap wider than the merge threshold — each stays its own flow", () => {
    const r1 = record({ first: "2026-01-01T00:00:00.000", last: "2026-01-01T00:00:05.000" });
    const r2 = record({ first: "2026-01-01T00:05:00.000", last: "2026-01-01T00:05:05.000" }); // far apart
    const r = parseExporterFlowNdjson(ndjson([r1, r2]))!;
    expect(r.flowCount).toBe(2);
  });

  it("does not merge a genuinely short, periodically-recurring flow into one — each real connection stays distinct", () => {
    // Five separate 1-second connections, 60s apart — a real beacon candidate, not an interim split.
    const records = Array.from({ length: 5 }, (_, i) =>
      record({
        first: new Date(Date.parse("2026-01-01T00:00:00.000") + i * 60_000).toISOString(),
        last: new Date(Date.parse("2026-01-01T00:00:01.000") + i * 60_000).toISOString(),
      }),
    );
    const r = parseExporterFlowNdjson(ndjson(records))!;
    expect(r.flowCount).toBe(5);
  });
});

describe("parseExporterFlowNdjson — duplicate-exporter disclosure (Codex design review finding)", () => {
  it("discloses a possible duplicate when the SAME tuple is reported by a different exporter in an overlapping window, without merging or dropping either", () => {
    const r1 = record({ export_sysid: 1, first: "2026-01-01T00:00:00.000", last: "2026-01-01T00:00:10.000" });
    const r2 = record({ export_sysid: 2, first: "2026-01-01T00:00:02.000", last: "2026-01-01T00:00:12.000" });
    const r = parseExporterFlowNdjson(ndjson([r1, r2]))!;
    expect(r.flowCount).toBe(2);
    const flows = r.events.filter((e) => e.canonical?.exporterFlow).map((e) => e.canonical!.exporterFlow!);
    expect(flows.every((f) => f.possibleDuplicateExporterCount === 1)).toBe(true);
  });

  it("never treats a reversed-direction record (src/dst swapped) as a duplicate — it is a structurally different tuple", () => {
    const forward = record({ export_sysid: 1, src4_addr: "10.0.0.5", dst4_addr: "203.0.113.9" });
    const reverse = record({ export_sysid: 2, src4_addr: "203.0.113.9", dst4_addr: "10.0.0.5" });
    const r = parseExporterFlowNdjson(ndjson([forward, reverse]))!;
    const flows = r.events.filter((e) => e.canonical?.exporterFlow).map((e) => e.canonical!.exporterFlow!);
    expect(flows.every((f) => f.possibleDuplicateExporterCount === 0)).toBe(true);
  });

  it("counts DISTINCT exporters, not overlapping-window count, when the SAME other exporter reports several non-adjacent overlapping windows (Codex code review finding)", () => {
    const r1 = record({ export_sysid: 1, first: "2026-01-01T00:00:00.000", last: "2026-01-01T00:01:00.000" });
    // Two records from exporter 2, far enough apart they don't merge with each other, but both
    // still overlap r1's own wide window.
    const r2a = record({
      export_sysid: 2,
      first: "2026-01-01T00:00:05.000",
      last: "2026-01-01T00:00:06.000",
    });
    const r2b = record({
      export_sysid: 2,
      first: "2026-01-01T00:00:50.000",
      last: "2026-01-01T00:00:51.000",
    });
    const r = parseExporterFlowNdjson(ndjson([r1, r2a, r2b]))!;
    const flows = r.events.filter((e) => e.canonical?.exporterFlow).map((e) => e.canonical!.exporterFlow!);
    const flow1 = flows.find((f) => f.exporterSysId === 1)!;
    // Overlaps TWO windows from exporter 2, but that is only ONE distinct other exporter.
    expect(flow1.possibleDuplicateExporterCount).toBe(1);
  });

  it("skips the duplicate-exporter disclosure for a pathologically large same-tuple bucket rather than paying its quadratic cost (Codex code review finding)", () => {
    // MAX_DUPLICATE_CHECK_BUCKET is 500 — 501 distinct exporters reporting the identical tuple in
    // one upload is the crafted worst case a pairwise check would have to pay O(n^2) for.
    const records = Array.from({ length: 501 }, (_, i) =>
      record({ export_sysid: i + 1, first: "2026-01-01T00:00:00.000", last: "2026-01-01T00:00:10.000" }),
    );
    const r = parseExporterFlowNdjson(ndjson(records))!;
    const flows = r.events.filter((e) => e.canonical?.exporterFlow).map((e) => e.canonical!.exporterFlow!);
    expect(flows).toHaveLength(501);
    expect(flows.every((f) => f.possibleDuplicateExporterCount === 0)).toBe(true);
  });
});

describe("parseExporterFlowNdjson — direction (Codex code review finding: a completed handshake leaves SYN on BOTH directions' own aggregate flags, so 'contains S' alone cannot tell initiator from responder)", () => {
  it("treats a bare SYN with no ACK as the unambiguous initiating (outbound) direction", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ tcp_flags: ".S....." })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.initiatingDirection).toBe("outbound");
  });

  it("discloses 'unknown' — never a guessed direction — for SYN+ACK together (a responder's own reply flow can carry both)", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ tcp_flags: ".AS...." })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.initiatingDirection).toBe("unknown");
  });

  it("discloses 'unknown' for an ACK-only continuation flow", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ tcp_flags: ".A....P." })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.initiatingDirection).toBe("unknown");
  });

  it("discloses 'unknown' for UDP (no TCP flags) rather than fabricating a direction", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ proto: 17, tcp_flags: undefined, dst_port: 53 })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    expect(flow.canonical!.exporterFlow!.initiatingDirection).toBe("unknown");
  });

  it("still includes direction-'unknown' flows in the in-memory beacon-candidate scan — no reliable exclusion signal exists", () => {
    const records = Array.from({ length: 6 }, (_, i) =>
      record({
        tcp_flags: ".A....P.", // ambiguous — could be either direction
        first: new Date(Date.parse("2026-01-01T00:00:00.000") + i * 60_000).toISOString(),
        last: new Date(Date.parse("2026-01-01T00:00:01.000") + i * 60_000).toISOString(),
      }),
    );
    const r = parseExporterFlowNdjson(ndjson(records))!;
    expect(r.beaconLeadCount).toBeGreaterThanOrEqual(1);
  });
});

describe("parseExporterFlowNdjson — tcp_flags merge across interim records (Codex code review finding)", () => {
  it("unions flag characters across merged records instead of keeping only the FIRST record's own flags", () => {
    // The chronologically FIRST record carries no SYN; the SECOND (merged) one does. Keeping only
    // the first record's own flags (the pre-fix bug) would report "unknown"; unioning correctly
    // surfaces the SYN and reports "outbound".
    const r1 = record({
      tcp_flags: "........",
      first: "2026-01-01T00:00:00.000",
      last: "2026-01-01T00:00:01.000",
    });
    const r2 = record({
      tcp_flags: ".S......",
      first: "2026-01-01T00:00:02.000", // within the merge gap
      last: "2026-01-01T00:00:03.000",
    });
    const r = parseExporterFlowNdjson(ndjson([r1, r2]))!;
    expect(r.flowCount).toBe(1);
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!.canonical!.exporterFlow!;
    expect(flow.initiatingDirection).toBe("outbound");
  });
});

describe("parseExporterFlowNdjson — IOC linkage", () => {
  it("registers a non-internal destination address as an IOC linked to its own flow event", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ dst4_addr: "203.0.113.9" })]))!;
    const flow = r.events.find((e) => e.canonical?.exporterFlow)!;
    const ioc = r.iocs.find((i) => i.type === "ip" && i.value === "203.0.113.9");
    expect(ioc).toBeDefined();
    expect(ioc?.sourceAggKeys).toEqual([flow.aggKey]);
  });

  it("never registers an internal (RFC1918) destination address as an IOC", () => {
    const r = parseExporterFlowNdjson(ndjson([record({ dst4_addr: "10.0.0.9" })]))!;
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "10.0.0.9")).toBe(false);
  });
});

describe("parseExporterFlowNdjson — beacon-lead integration (the architecture fix)", () => {
  it("calls the EXISTING detectBeacons() in-memory and emits a bounded Low-severity lead for a genuine periodicity candidate, leaving the bulk flow events at Info", () => {
    const records = Array.from({ length: 6 }, (_, i) =>
      record({
        first: new Date(Date.parse("2026-01-01T00:00:00.000") + i * 60_000).toISOString(),
        last: new Date(Date.parse("2026-01-01T00:00:01.000") + i * 60_000).toISOString(),
      }),
    );
    const r = parseExporterFlowNdjson(ndjson(records))!;
    expect(r.beaconLeadCount).toBeGreaterThanOrEqual(1);
    const lead = r.events.find((e) => e.canonical?.exporterFlowBeaconLead)!;
    expect(lead).toBeDefined();
    expect(lead.severity).toBe("Low");
    expect(lead.description).toContain("hunting lead, not a verdict");
    // Every underlying flow event is still Info — the lead is the ONLY thing above the floor.
    expect(r.events.filter((e) => e.canonical?.exporterFlow).every((e) => e.severity === "Info")).toBe(true);
  });

  it("emits no beacon lead when flows don't meet detectBeacons()'s own existing minimum-count threshold", () => {
    const records = Array.from({ length: 2 }, (_, i) =>
      record({
        first: new Date(Date.parse("2026-01-01T00:00:00.000") + i * 60_000).toISOString(),
        last: new Date(Date.parse("2026-01-01T00:00:01.000") + i * 60_000).toISOString(),
      }),
    );
    const r = parseExporterFlowNdjson(ndjson(records))!;
    expect(r.beaconLeadCount).toBe(0);
  });
});

describe("parseExporterFlowNdjson — report identity", () => {
  it("gives two separate reports different aggKeys even with an identical flow", () => {
    const r1 = parseExporterFlowNdjson(ndjson([record()]))!;
    const r2 = parseExporterFlowNdjson(ndjson([record(), record({ dst_port: 8443 })]))!;
    const flow1 = r1.events.find((e) => e.canonical?.exporterFlow)!;
    const flow2 = r2.events.find(
      (e) => e.canonical?.exporterFlow && e.canonical.exporterFlow.dstPort === 443,
    )!;
    expect(flow1.aggKey).not.toBe(flow2.aggKey);
  });
});

describe("parseExporterFlowNdjson — record-scan volume bound", () => {
  it("discloses recordsTruncated once the number of records exceeds the report-wide cap", () => {
    const records = Array.from({ length: 20_001 }, (_, i) => record({ dst_port: 1000 + i }));
    const r = parseExporterFlowNdjson(ndjson(records))!;
    expect(r.recordsTruncated).toBe(true);
  });
});
