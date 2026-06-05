import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// ── A Velociraptor Sigma detection row (parsed evtx event + matched rule).
function sigmaRow(): object {
  return {
    _Source: "Windows.Detection.Sigma",
    Rule: { Title: "Mimikatz LSASS Access", Level: "critical", Tags: ["attack.t1003.001"] },
    System: { EventID: 10, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DC01", TimeCreated: "2023-03-01T10:00:00Z" },
    EventData: { TargetImage: "C:\\Windows\\System32\\lsass.exe", SourceImage: "C:\\temp\\mimikatz.exe" },
  };
}

// ── A Velociraptor YARA detection row (file glob scan).
function yaraRow(): object {
  return {
    _Source: "Windows.Detection.Yara.Glob",
    Rule: "APT_Malware_Foo",
    Namespace: "default",
    Meta: { author: "x", mitre: "T1059" },
    Strings: ["$a"],
    OSPath: "C:\\Users\\bob\\evil.exe",
    HashSHA256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  };
}

// ── A Velociraptor parsed-evtx row (no detection) — EventID as a {Value} object.
function eventlogRow(): object {
  return {
    _Source: "Windows.EventLogs.Evtx",
    System: { EventID: { Value: 4624 }, Channel: "Security", Computer: "WS05", TimeCreated: "2023-03-01T08:00:00Z" },
    EventData: { TargetUserName: "alice", TargetDomainName: "CORP", IpAddress: "10.0.0.20", LogonType: "3" },
  };
}

// ── A generic Velociraptor artifact row (netstat) — raw evidence, no verdict.
function netstatRow(): object {
  return {
    _Source: "Windows.Network.Netstat",
    Pid: 4321,
    Exe: "C:\\temp\\evil.exe",
    RemoteAddr: "8.8.8.8",
    Status: "ESTABLISHED",
    _ts: 1677662400,
  };
}

describe("parseVelociraptorJson — detection rows", () => {
  it("maps a Sigma row verdict-first over the parsed evtx event", () => {
    const r = parseVelociraptorJson(JSON.stringify([sigmaRow()]));
    expect(r.detections).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor Sigma: Mimikatz LSASS Access");
    expect(e.description).toContain("EID 10");          // the underlying event is still mapped
    expect(e.severity).toBe("Critical");                // Sigma critical ≥ the EVTX-derived High
    expect(e.mitreTechniques).toContain("T1003.001");
    expect(e.asset).toBe("DC01");
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("maps a YARA row as a High detection with rule, path and hash", () => {
    const r = parseVelociraptorJson(JSON.stringify([yaraRow()]));
    expect(r.detections).toBe(1);
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor YARA: APT_Malware_Foo");
    expect(e.severity).toBe("High");
    expect(e.path).toBe("C:\\Users\\bob\\evil.exe");
    expect(e.sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(e.mitreTechniques).toContain("T1059"); // from rule Meta
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("C:\\Users\\bob\\evil.exe");
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });
});

describe("parseVelociraptorJson — eventlog & generic rows", () => {
  it("maps a parsed-evtx row per-EID, normalizing the {Value} EventID", () => {
    const r = parseVelociraptorJson(JSON.stringify([eventlogRow()]));
    expect(r.detections).toBe(0);
    const e = r.events[0];
    expect(e.description).toContain("EID 4624");
    expect(e.severity).toBe("Low");
    expect(e.asset).toBe("WS05");
    expect(e.sources).toEqual(["Velociraptor"]);
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("10.0.0.20");
  });

  it("maps a generic artifact row (Info), extracting IOCs by value", () => {
    const r = parseVelociraptorJson(JSON.stringify([netstatRow()]));
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("Velociraptor [Windows.Network.Netstat]");
    expect(e.processName).toBe("evil.exe");
    expect(e.timestamp).toBe("2023-03-01T09:20:00.000Z"); // _ts epoch seconds → UTC
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("8.8.8.8");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "evil.exe")).toBe(true);
  });

  it("prefers the artifact's own time over the _ts collection time", () => {
    const row = { _Source: "Custom.X", EventTime: "2022-01-01T00:00:00Z", _ts: 1677662400, Message: "hi" };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].timestamp).toBe("2022-01-01T00:00:00Z");
  });
});

describe("parseVelociraptorJson — inputs, floor & edges", () => {
  it("reads JSONL (native collection results)", () => {
    const text = [JSON.stringify(eventlogRow()), JSON.stringify(yaraRow())].join("\n");
    const r = parseVelociraptorJson(text);
    expect(r.format).toBe("jsonl");
    expect(r.events).toHaveLength(2);
    expect(r.detections).toBe(1);
  });

  it("reads a multi-artifact map { Artifact: [rows] } and tags _Source", () => {
    const yaraNoSource = { Rule: "Bar", Strings: ["$x"], OSPath: "C:\\a.exe" };
    const text = JSON.stringify({ "Windows.Detection.Yara.Glob": [yaraNoSource], "Custom.Other": [{ Message: "x" }] });
    const r = parseVelociraptorJson(text);
    expect(r.format).toBe("artifact-map");
    expect(r.events).toHaveLength(2);
    expect(r.detections).toBe(1); // the yara row classified via the artifact key
  });

  it("applies a minSeverity floor (drops Info raw-collection rows)", () => {
    const text = JSON.stringify([sigmaRow(), netstatRow()]);
    const r = parseVelociraptorJson(text, { minSeverity: "Low" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Critical");
  });

  it("reports empty for a non-Velociraptor file", () => {
    const r = parseVelociraptorJson("nonsense");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});
