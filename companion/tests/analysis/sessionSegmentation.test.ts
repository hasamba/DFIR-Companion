import { describe, it, expect } from "vitest";
import {
  segmentSessions,
  DEFAULT_SESSION_GAP_SECONDS,
  DEFAULT_IOC_GRACE_FACTOR,
  UNKNOWN_HOST,
} from "../../src/analysis/sessionSegmentation.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("segmentSessions", () => {
  it("returns no sessions for an empty or fully-undated timeline", () => {
    expect(segmentSessions([])).toEqual([]);
    expect(segmentSessions([ev("e1", ""), ev("e2", "not-a-date")])).toEqual([]);
  });

  it("groups a dense run on one host into a single session and splits on a large gap", () => {
    const events: ForensicEvent[] = [
      ev("e1", "2026-05-20T14:01:00Z", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:02:00Z", { asset: "DC01" }),
      ev("e3", "2026-05-20T14:03:00Z", { asset: "DC01" }),
      // > 5 min gap → new session on the same host
      ev("e4", "2026-05-20T15:10:00Z", { asset: "DC01" }),
      ev("e5", "2026-05-20T15:11:00Z", { asset: "DC01" }),
    ];
    const sessions = segmentSessions(events);
    expect(sessions).toHaveLength(2);
    expect(sessions[0].id).toBe("session-1");
    expect(sessions[0].host).toBe("DC01");
    expect(sessions[0].startTime).toBe("2026-05-20T14:01:00Z");
    expect(sessions[0].endTime).toBe("2026-05-20T14:03:00Z");
    expect(sessions[0].eventCount).toBe(3);
    expect(sessions[1].id).toBe("session-2");
    expect(sessions[1].eventCount).toBe(2);
  });

  it("segments per host so back-to-back cross-host events never join", () => {
    const events: ForensicEvent[] = [
      ev("e1", "2026-05-20T14:01:00Z", { asset: "WS01" }),
      ev("e2", "2026-05-20T14:01:30Z", { asset: "WS02" }),
      ev("e3", "2026-05-20T14:02:00Z", { asset: "WS01" }),
      ev("e4", "2026-05-20T14:02:30Z", { asset: "WS02" }),
    ];
    const sessions = segmentSessions(events);
    expect(sessions).toHaveLength(2);
    const byHost = new Map(sessions.map((s) => [s.host, s]));
    expect(byHost.get("WS01")?.eventCount).toBe(2);
    expect(byHost.get("WS02")?.eventCount).toBe(2);
    expect(byHost.get("WS01")?.startTime).toBe("2026-05-20T14:01:00Z");
    expect(byHost.get("WS02")?.startTime).toBe("2026-05-20T14:01:30Z");
  });

  it("auto-generates a dominant-tactic label and reports worst-first severity range", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:01:00Z", { asset: "DC01", mitreTechniques: ["T1566"], description: "phishing email", severity: "High" }),
      ev("e2", "2026-05-20T14:02:00Z", { asset: "DC01", mitreTechniques: ["T1566.001"], severity: "Medium" }),
      ev("e3", "2026-05-20T14:02:30Z", { asset: "DC01", mitreTechniques: ["T1059"], description: "powershell", severity: "Low" }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].dominantTactic).toBe("Initial Access");
    expect(sessions[0].severityRange).toEqual(["High", "Medium", "Low"]);
    expect(sessions[0].label).toBe(
      "Initial Access DC01 → 2026-05-20T14:01:00Z-2026-05-20T14:02:30Z, 3 events",
    );
  });

  it("falls back to 'Activity' in the label when no tactic can be inferred", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:01:00Z", { asset: "WS01", description: "benign file read" }),
    ]);
    expect(sessions[0].dominantTactic).toBeUndefined();
    expect(sessions[0].label).toBe("Activity WS01 → 2026-05-20T14:01:00Z-2026-05-20T14:01:00Z, 1 events");
  });

  it("honors a custom gapSeconds threshold", () => {
    const events = [
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:00:30Z", { asset: "DC01" }),   // 30s apart
    ];
    expect(segmentSessions(events, { gapSeconds: 10 })).toHaveLength(2); // 30s > 10s → split
    expect(segmentSessions(events, { gapSeconds: 60 })).toHaveLength(1); // 30s ≤ 60s → one session
  });

  it("sums aggregated counts and spans aggregated end times within a session", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", count: 20, endTimestamp: "2026-05-20T14:04:00Z" }),
      // starts 1 min after e1's END (14:04) → within the default 5-min gap, same session
      ev("e2", "2026-05-20T14:05:00Z", { asset: "DC01" }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].eventCount).toBe(21);                    // 20 (aggregated) + 1
    expect(sessions[0].endTime).toBe("2026-05-20T14:05:00Z");
  });

  it("sorts sessions chronologically by start time and re-numbers ids", () => {
    const events: ForensicEvent[] = [
      ev("e3", "2026-05-20T14:03:00Z", { asset: "WS02" }),
      ev("e1", "2026-05-20T14:01:00Z", { asset: "WS01" }),
      ev("e2", "2026-05-20T14:02:00Z", { asset: "WS01" }),
    ];
    const sessions = segmentSessions(events);
    expect(sessions).toHaveLength(2);
    expect(sessions[0].id).toBe("session-1");
    expect(sessions[0].host).toBe("WS01");
    expect(sessions[0].startTime).toBe("2026-05-20T14:01:00Z");
    expect(sessions[1].id).toBe("session-2");
    expect(sessions[1].host).toBe("WS02");
    expect(sessions[1].startTime).toBe("2026-05-20T14:03:00Z");
  });

  it("buckets events with no asset under a named unknown host, not a blank one", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z"),                          // no asset at all
      ev("e2", "2026-05-20T14:00:30Z", { asset: "" }),           // empty-string asset means the same
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].host).toBe(UNKNOWN_HOST);
    // The label must never render a blank where a host belongs — that reads like a real machine.
    expect(sessions[0].label).toBe(
      "Activity (unknown host) → 2026-05-20T14:00:00Z-2026-05-20T14:00:30Z, 2 events",
    );
  });

  it("keeps the unknown-host bucket separate from real hosts", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:00:30Z"),                          // unknown host, back-to-back
      ev("e3", "2026-05-20T14:01:00Z", { asset: "DC01" }),
    ]);
    expect(sessions).toHaveLength(2);
    const byHost = new Map(sessions.map((s) => [s.host, s]));
    expect(byHost.get("DC01")?.eventCount).toBe(2);
    expect(byHost.get(UNKNOWN_HOST)?.eventCount).toBe(1);
  });

  it("defaults the gap threshold to 5 minutes", () => {
    expect(DEFAULT_SESSION_GAP_SECONDS).toBe(300);
  });

  it("carries every event id so the caller can filter the timeline to exactly this session", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:00:30Z", { asset: "DC01" }),
      ev("e3", "2026-05-20T16:00:00Z", { asset: "DC01" }),
    ]);
    expect(sessions).toHaveLength(2);
    expect(sessions[0].eventIds).toEqual(["e1", "e2"]);
    expect(sessions[1].eventIds).toEqual(["e3"]);
  });
});

// #344 — segmentation binds on more than host + time.
const logon = (acct: string, host: string, type = 10) =>
  `Windows Security Successful logon (EID 4624) - ${acct} - LogonType=${type} @ ${host}`;

describe("segmentSessions — account binding (#344)", () => {
  it("splits when a second account logs on to the same host inside the gap window", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "SRV-01", description: logon("CORP\\jdoe", "SRV-01") }),
      ev("e2", "2026-05-20T14:00:30Z", { asset: "SRV-01", description: "file read" }),
      // 30s later — well inside the 5-min gap, but a DIFFERENT account. Two stories, not one.
      ev("e3", "2026-05-20T14:01:00Z", { asset: "SRV-01", description: logon("CORP\\svc_backup", "SRV-01") }),
      ev("e4", "2026-05-20T14:01:30Z", { asset: "SRV-01", description: "file write" }),
    ]);
    expect(sessions).toHaveLength(2);
    expect(sessions[0]).toMatchObject({ account: "CORP\\jdoe", eventCount: 2 });
    expect(sessions[1]).toMatchObject({ account: "CORP\\svc_backup", eventCount: 2 });
  });

  it("names the account in the label when one was observed", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "SRV-01", description: logon("CORP\\jdoe", "SRV-01") }),
    ]);
    expect(sessions[0].label).toBe(
      "Activity SRV-01 (CORP\\jdoe) → 2026-05-20T14:00:00Z-2026-05-20T14:00:00Z, 1 events",
    );
  });

  it("leaves account undefined and the label unchanged when no logon was observed", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "SRV-01", description: "file read" }),
    ]);
    expect(sessions[0].account).toBeUndefined();
    expect(sessions[0].label).toContain("Activity SRV-01 →");
  });

  it("re-logon by the SAME account does not split the session", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "SRV-01", description: logon("CORP\\jdoe", "SRV-01") }),
      ev("e2", "2026-05-20T14:00:30Z", { asset: "SRV-01", description: logon("CORP\\jdoe", "SRV-01", 3) }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].eventCount).toBe(2);
  });

  it("does not split on FAILED logons, so a brute-force burst stays one readable block", () => {
    const fail = (acct: string) =>
      `Windows Security Failed logon (EID 4625) - ${acct} - LogonType=3 @ SRV-01`;
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "SRV-01", description: fail("CORP\\a") }),
      ev("e2", "2026-05-20T14:00:10Z", { asset: "SRV-01", description: fail("CORP\\b") }),
      ev("e3", "2026-05-20T14:00:20Z", { asset: "SRV-01", description: fail("CORP\\c") }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].eventCount).toBe(3);
    expect(sessions[0].account).toBeUndefined();   // a rejected logon establishes nothing
  });
});

describe("segmentSessions — shared-IOC gap resistance (#344)", () => {
  it("absorbs an over-gap event that shares a hash with the running session", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", sha256: "AABB" }),
      // 8 min later: over the 5-min gap, but under the 3x grace, and it shares the hash.
      ev("e2", "2026-05-20T14:08:00Z", { asset: "DC01", sha256: "aabb" }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].eventCount).toBe(2);
  });

  it("still splits a shared-indicator event once it exceeds the grace window", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", sha256: "aabb" }),
      // 20 min later: past 3 x 5 min, so even a shared hash cannot hold it.
      ev("e2", "2026-05-20T14:20:00Z", { asset: "DC01", sha256: "aabb" }),
    ]);
    expect(sessions).toHaveLength(2);
  });

  it("splits an over-gap event that shares nothing", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", sha256: "aabb" }),
      ev("e2", "2026-05-20T14:08:00Z", { asset: "DC01", sha256: "ccdd" }),
    ]);
    expect(sessions).toHaveLength(2);
  });

  it("matches on path, IP, and decoded-payload IOC ids too", () => {
    const byPath = segmentSessions([
      ev("a1", "2026-05-20T14:00:00Z", { asset: "DC01", path: "c:\\temp\\x.exe" }),
      ev("a2", "2026-05-20T14:08:00Z", { asset: "DC01", path: "c:\\temp\\x.exe" }),
    ]);
    expect(byPath).toHaveLength(1);

    const byIp = segmentSessions([
      ev("b1", "2026-05-20T14:00:00Z", { asset: "DC01", dstIp: "203.0.113.7" }),
      ev("b2", "2026-05-20T14:08:00Z", { asset: "DC01", srcIp: "203.0.113.7" }),
    ]);
    expect(byIp).toHaveLength(1);

    const byIoc = segmentSessions([
      ev("c1", "2026-05-20T14:00:00Z", { asset: "DC01", deobfuscated: { decoded: "x", method: "base64", iocs: ["i12"] } }),
      ev("c2", "2026-05-20T14:08:00Z", { asset: "DC01", deobfuscated: { decoded: "y", method: "base64", iocs: ["i12"] } }),
    ]);
    expect(byIoc).toHaveLength(1);
  });

  it("iocGraceFactor: 1 disables the grace entirely", () => {
    const sessions = segmentSessions([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", sha256: "aabb" }),
      ev("e2", "2026-05-20T14:08:00Z", { asset: "DC01", sha256: "aabb" }),
    ], { iocGraceFactor: 1 });
    expect(sessions).toHaveLength(2);
  });

  it("defaults the IOC grace factor to 3", () => {
    expect(DEFAULT_IOC_GRACE_FACTOR).toBe(3);
  });
});