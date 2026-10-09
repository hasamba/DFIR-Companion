import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { buildWindowsEventResult } from "../../src/analysis/siemBuildProgress.js";
import { clockDisputeText, SYSMON_CLOCK_DISPUTE_MS } from "../../src/analysis/siemFieldPick.js";

// #2089 — a Sysmon UtcTime hours or days away from the record's own (zoned) time moved rows out of
// the attack window. The record time wins past an hour; UtcTime stays as the observed time and the
// row says so. Synthetic fixtures only.

const WLB6 = {
  log_name: "Microsoft-Windows-Sysmon/Operational",
  source_name: "Microsoft-Windows-Sysmon",
  computer_name: "WS01.example.test",
  level: "Information",
};

const CONN_SKEWED = {
  ...WLB6,
  "@timestamp": "2019-05-14T22:32:36.000Z",
  event_id: 3,
  event_data: {
    UtcTime: "2019-05-03 13:45:52.000",
    Image: "C:\\Windows\\System32\\svchost.exe",
    Protocol: "tcp",
    SourceIp: "10.0.0.5",
    SourcePort: "50000",
    DestinationIp: "10.0.0.9",
    DestinationPort: "445",
  },
};

const PROC_AGREEING = {
  ...WLB6,
  "@timestamp": "2019-05-14T22:31:28.512Z",
  event_id: 1,
  event_data: {
    UtcTime: "2019-05-14 22:31:28.401",
    Image: "C:\\Windows\\System32\\cmd.exe",
    CommandLine: "cmd.exe /c whoami",
    ParentImage: "C:\\Windows\\explorer.exe",
    User: "EXAMPLE\\user1",
    ProcessId: "4242",
  },
};

const CONN_LAGGING = {
  ...CONN_SKEWED,
  "@timestamp": "2019-05-14T22:37:52.000Z",
  event_data: { ...CONN_SKEWED.event_data, UtcTime: "2019-05-14 22:32:52.000", DestinationPort: "443" },
};

// Flat NXLog shape (#2023): event data at the top level, @timestamp zoned, UtcTime 19 h ahead.
const FLAT_NXLOG = {
  "@timestamp": "2023-08-15T09:53:48.554Z",
  EventTime: "2023-08-15 05:53:48",
  Hostname: "WS02.example.test",
  Channel: "Microsoft-Windows-Sysmon/Operational",
  SourceName: "Microsoft-Windows-Sysmon",
  EventID: 1,
  UtcTime: "2023-08-16 04:53:48.446",
  Image: "C:\\Windows\\System32\\rundll32.exe",
  CommandLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 600 C:\\temp\\o.dmp full",
  ParentImage: "C:\\Windows\\System32\\cmd.exe",
  User: "EXAMPLE\\user2",
  ProcessId: "7001",
};

// No record-level clock at all (EVTX-XML-like row with only the Sysmon field).
const NO_RECORD_TIME = {
  log_name: "Microsoft-Windows-Sysmon/Operational",
  computer_name: "WS03.example.test",
  event_id: 1,
  event_data: { ...PROC_AGREEING.event_data, UtcTime: "2019-05-01 01:00:00.000", ProcessId: "5151" },
};

function parse(records: unknown[]) {
  return parseSiemExport(JSON.stringify(records), { aggregate: false });
}

describe("Sysmon UtcTime vs record time (#2089)", () => {
  it("dates a row by the record time when UtcTime is days away, keeps UtcTime as observed, flags it", () => {
    const r = parse([CONN_SKEWED]);
    const e = r.events[0];
    expect(e.timestamp).toBe("2019-05-14T22:32:36.000Z");
    expect(e.canonical?.time?.observed).toBe("2019-05-03 13:45:52.000");
    expect(e.description).toMatch(
      /Sysmon UtcTime 2019-05-03 13:45:52\.000 disagrees with the record time by 11d; dated by @timestamp/,
    );
    expect(r.clockDisputed).toEqual({ rows: 1, maxOffsetMs: expect.any(Number) });
    expect(r.clockDisputed!.maxOffsetMs).toBeGreaterThan(11 * 24 * 3_600_000);
  });

  it("keeps UtcTime when the two clocks agree (sub-second), with no flag and no count", () => {
    const r = parse([PROC_AGREEING]);
    expect(r.events[0].timestamp).toBe("2019-05-14T22:31:28.401Z");
    expect(r.events[0].description).not.toMatch(/disagrees with the record time/);
    expect(r.clockDisputed).toBeUndefined();
  });

  it("counts only the disputed rows in a mixed file", () => {
    const r = parse([CONN_SKEWED, PROC_AGREEING, CONN_LAGGING]);
    expect(r.clockDisputed?.rows).toBe(1);
  });

  it("prefers the zoned @timestamp on a flat NXLog record 19 h behind UtcTime", () => {
    const r = parse([FLAT_NXLOG]);
    expect(r.events[0].timestamp).toBe("2023-08-15T09:53:48.554Z");
    expect(r.events[0].description).toMatch(/by 19h; dated by @timestamp/);
    expect(r.clockDisputed?.rows).toBe(1);
  });

  it("keeps UtcTime for an EID 3 lagging its record by five minutes (below the threshold)", () => {
    expect(SYSMON_CLOCK_DISPUTE_MS).toBe(3_600_000);
    const r = parse([CONN_LAGGING]);
    expect(r.events[0].timestamp).toBe("2019-05-14T22:32:52.000Z");
    expect(r.clockDisputed).toBeUndefined();
  });

  it("keeps UtcTime when the record has no time field of its own", () => {
    const r = parse([NO_RECORD_TIME]);
    expect(r.events[0].timestamp).toBe("2019-05-01T01:00:00.000Z");
    expect(r.clockDisputed).toBeUndefined();
  });

  it("does not dispute against a naive (zone-less) record time such as NXLog's local EventTime", () => {
    const { "@timestamp": _drop, ...naiveOnly } = FLAT_NXLOG;
    const r = parse([naiveOnly]);
    expect(r.events[0].timestamp).toBe("2023-08-16T04:53:48.446Z");
    expect(r.clockDisputed).toBeUndefined();
  });

  it("treats a Sentinel TimeGenerated as a record clock", () => {
    const { "@timestamp": _drop, ...rest } = CONN_SKEWED;
    const r = parse([{ ...rest, TimeGenerated: "2019-05-14T22:32:36Z" }]);
    expect(r.events[0].timestamp).toBe("2019-05-14T22:32:36Z");
    expect(r.events[0].description).toMatch(/dated by TimeGenerated/);
  });

  it("the streaming Windows builder counts the same way", () => {
    const r = buildWindowsEventResult([CONN_SKEWED, PROC_AGREEING], "array", { aggregate: false });
    expect(r.clockDisputed?.rows).toBe(1);
  });

  it("states the dispute to the analyst in one line", () => {
    expect(clockDisputeText(undefined)).toBe("");
    expect(clockDisputeText({ rows: 27, maxOffsetMs: 11 * 24 * 3_600_000 })).toBe(
      "27 Sysmon row(s) had a UtcTime up to 11d from the record time; dated by the record time",
    );
  });
});
