import { describe, it, expect } from "vitest";
import { parseEcarJson, mapEcarRecord, isEcarRecord, ECAR_SOURCE } from "../../src/analysis/ecarImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

// One ECAR record (the EDR Common Activity Record NDJSON shape). `properties` carries the detail.
function rec(object: string, action: string, properties: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    timestamp_ms: 1715688049745, // 2024-05-14T12:00:49.745Z
    id: "00000000-0000-0000-0000-000000000000",
    hostname: "WEB-BO-01",
    object,
    action,
    properties,
    ...extra,
  };
}

function ndjson(...recs: object[]): string {
  return recs.map((r) => JSON.stringify(r)).join("\n");
}

describe("isEcarRecord — signature", () => {
  it("accepts the (timestamp_ms + object + action) triple", () => {
    expect(isEcarRecord(rec("PROCESS", "CREATE", {}))).toBe(true);
  });
  it("rejects non-ECAR shapes", () => {
    expect(isEcarRecord({ "@timestamp": "2024-01-01", message: "x" })).toBe(false);
    expect(isEcarRecord({ timestamp_ms: 1, object: "X" })).toBe(false); // no action
    expect(isEcarRecord(null)).toBe(false);
    expect(isEcarRecord([])).toBe(false);
  });
});

describe("parseEcarJson — timestamp + container", () => {
  it("reads timestamp_ms as epoch-ms ISO and tags the source", () => {
    const r = parseEcarJson(ndjson(rec("PROCESS", "CREATE", { command_line: "id", image_path: "/usr/bin/id" })));
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toBe("2024-05-14T12:00:49.745Z");
    expect(r.events[0].asset).toBe("WEB-BO-01");
    expect(r.events[0].sources).toEqual([ECAR_SOURCE]);
    expect(r.hostname).toBe("WEB-BO-01");
  });
});

describe("mapEcarRecord — PROCESS/CREATE", () => {
  it("keeps a benign process at Info with process/parent names", () => {
    const m = mapEcarRecord(
      rec("PROCESS", "CREATE", {
        command_line: "dllhost.exe /Processid:{X}",
        image_path: "C:\\Windows\\System32\\dllhost.exe",
        parent_image_path: "C:\\Windows\\System32\\svchost.exe",
      }),
      new Map(),
    )!;
    expect(m.severity).toBe("Info");
    expect(m.processName).toBe("dllhost.exe");
    expect(m.parentName).toBe("svchost.exe");
    expect(m.description).toContain("Process created:");
  });

  it("bumps a suspicious command line (LOLBin / encoded) and emits a process IOC + MITRE", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapEcarRecord(
      rec("PROCESS", "CREATE", {
        command_line: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      }),
      sink,
    )!;
    expect(["Medium", "High"]).toContain(m.severity);
    expect(m.mitre).toContain("T1059");
    expect([...sink.values()].some((i) => i.type === "process")).toBe(true);
  });
});

describe("mapEcarRecord — PROCESS/OPEN does NOT auto-flag lsass (FP guard)", () => {
  it("keeps Windows Defender opening lsass at Info, no credential-dumping verdict", () => {
    const m = mapEcarRecord(
      rec("PROCESS", "OPEN", {
        image_path: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
        target_image_path: "C:\\Windows\\System32\\lsass.exe",
        granted_access: "0x1410",
      }),
      new Map(),
    )!;
    expect(m.severity).toBe("Info");
    expect(m.mitre).toEqual([]);
    expect(m.description).toContain("lsass.exe");
    expect(m.description).toContain("0x1410");
  });
});

describe("mapEcarRecord — FLOW/CONNECT IOCs are public-only", () => {
  it("records a PUBLIC dst as an IP IOC and marks the flow Low", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapEcarRecord(
      rec("FLOW", "CONNECT", {
        src_ip: "10.44.30.10", src_port: "55001",
        dst_ip: "45.83.221.30", dst_port: "443", protocol: "tcp", direction: "OUTBOUND",
      }),
      sink,
    )!;
    expect(m.severity).toBe("Low");
    expect(m.dstIp).toBe("45.83.221.30");
    expect(m.port).toBe(443);
    const ips = [...sink.values()].filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("45.83.221.30"); // public dst → IOC
    expect(ips).not.toContain("10.44.30.10"); // RFC1918 src → NOT an IOC
  });

  it("keeps a purely-internal flow at Info with no IOCs", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapEcarRecord(
      rec("FLOW", "CONNECT", {
        src_ip: "10.44.20.10", dst_ip: "10.44.20.20", dst_port: "3389", protocol: "tcp", direction: "OUTBOUND",
      }),
      sink,
    )!;
    expect(m.severity).toBe("Info");
    expect([...sink.values()]).toHaveLength(0);
  });
});

describe("mapEcarRecord — USER_SESSION + THREAD", () => {
  it("treats '-' src_ip as empty and a failed logon as Low", () => {
    const m = mapEcarRecord(
      rec("USER_SESSION", "LOGIN", { src_ip: "-", outcome: "failure", logon_type: "3", failure_reason: "bad password" }),
      new Map(),
    )!;
    expect(m.severity).toBe("Low");
    expect(m.description).toContain("FAILED");
    expect(m.srcIp).toBeUndefined();
  });

  it("keeps a remote thread create as Info evidence (no auto-verdict — benign system procs do it too)", () => {
    const m = mapEcarRecord(
      rec("THREAD", "REMOTE_CREATE", { image_path: "C:\\Windows\\System32\\services.exe", target_pid: "5652" }),
      new Map(),
    )!;
    expect(m.severity).toBe("Info");
    expect(m.mitre).toEqual([]);
    expect(m.description).toContain("possible process injection");
  });
});

describe("parseEcarJson — aggregation collapses repetitive flows", () => {
  it("collapses identical flows into one counted row", () => {
    const flow = rec("FLOW", "CONNECT", {
      src_ip: "10.44.30.10", dst_ip: "45.83.221.30", dst_port: "443", protocol: "tcp", direction: "OUTBOUND",
    });
    const r = parseEcarJson(ndjson(flow, flow, flow));
    expect(r.total).toBe(3);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });
});
