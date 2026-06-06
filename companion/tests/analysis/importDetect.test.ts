import { describe, it, expect } from "vitest";
import { detectImportKind } from "../../src/analysis/importDetect.js";

const j = (o: unknown): string => JSON.stringify(o);
const ndjson = (...o: unknown[]): string => o.map((x) => JSON.stringify(x)).join("\n");

describe("detectImportKind — JSON formats", () => {
  it("sandbox: CAPE report.json", () => {
    expect(detectImportKind("report.json", j({ info: { id: 1 }, target: { file: {} }, signatures: [] }))).toBe("sandbox");
  });
  it("sandbox: Falcon summary", () => {
    expect(detectImportKind("summary.json", j({ verdict: "malicious", threat_score: 90, sha256: "x" }))).toBe("sandbox");
  });
  it("aws: CloudTrail { Records: [...] }", () => {
    expect(detectImportKind("ct.json", j({ Records: [{ eventName: "RunInstances", eventSource: "ec2.amazonaws.com" }] }))).toBe("aws");
  });
  it("cloud: GCP protoPayload", () => {
    expect(detectImportKind("gcp.json", j([{ protoPayload: { methodName: "x" }, logName: "projects/p/logs/cloudaudit.googleapis.com" }]))).toBe("cloud");
  });
  it("cloud: Azure activity", () => {
    expect(detectImportKind("az.json", j([{ operationName: { value: "Microsoft.X/write" }, caller: "a@b.com" }]))).toBe("cloud");
  });
  it("m365: Unified Audit Log JSON", () => {
    expect(detectImportKind("ual.json", j([{ Operation: "New-InboxRule", Workload: "Exchange", AuditData: "{}" }]))).toBe("m365");
  });
  it("m365: Entra sign-in", () => {
    expect(detectImportKind("signin.json", j([{ userPrincipalName: "u@x.com", status: { errorCode: 0 }, appDisplayName: "X" }]))).toBe("m365");
  });
  it("chainsaw: hunt output with document+rule", () => {
    expect(detectImportKind("cs.json", j([{ group: "Sigma", document: { data: { Event: { System: {} } } }, rule: { name: "x" } }]))).toBe("chainsaw");
  });
  it("chainsaw: raw evtx_dump { Event: { System } }", () => {
    expect(detectImportKind("evtx.json", ndjson({ Event: { System: { EventID: 1 }, EventData: {} } }))).toBe("chainsaw");
  });
  it("velociraptor: _Source-tagged rows", () => {
    expect(detectImportKind("vr.json", ndjson({ _Source: "Windows.EventLogs.Evtx", System: { EventID: 1 }, EventData: {} }))).toBe("velociraptor");
  });
  it("velociraptor: artifact map", () => {
    expect(detectImportKind("vr.json", j({ "Windows.Detection.Yara.Glob": [{ Rule: "x" }] }))).toBe("velociraptor");
  });
  it("hayabusa: json-timeline", () => {
    expect(detectImportKind("hb.json", j([{ Timestamp: "t", RuleTitle: "x", Level: "high" }]))).toBe("hayabusa");
  });
  it("hayabusa: Velociraptor Windows.Hayabusa.Rules variant (Title+Level+Channel, no RuleTitle/Mitre)", () => {
    // Content match wins even though the filename also looks like a Velociraptor export.
    const row = { Timestamp: "t", Computer: "WIN11", Channel: "Microsoft-Windows-Sysmon/Operational", EID: 1, Level: "high", Title: "Possible LOLBIN", RecordID: 9, Details: "Proc: x" };
    expect(detectImportKind("Velociraptor-Windows.Hayabusa.Rules-sample.json", ndjson(row))).toBe("hayabusa");
  });
  it("velociraptor: artifact-named export with no content signature → filename hint (not 'siem')", () => {
    // Windows.Triage.HighValueMemory rows have no distinctive content keys → generic SIEM fallback,
    // but the Velociraptor-export filename routes them to the Velociraptor importer.
    const mem = { ProcessName: "cmd.exe", CommandLine: "cmd.exe", Pid: 2432, FullPath: "x.dmp", CrashDump: { sha256: "a".repeat(64) } };
    expect(detectImportKind("Velociraptor-Windows.Triage.HighValueMemory-sample.json", ndjson(mem))).toBe("velociraptor");
    // Same content under a non-Velociraptor name has no signal → stays the SIEM catch-all.
    expect(detectImportKind("dump.json", ndjson(mem))).toBe("siem");
  });
  it("network: Suricata eve.json", () => {
    expect(detectImportKind("eve.json", ndjson({ event_type: "alert", alert: { signature: "x" } }))).toBe("network");
  });
  it("network: Zeek json", () => {
    expect(detectImportKind("conn.json", ndjson({ _path: "notice", note: "x" }))).toBe("network");
  });
  it("thor: JSON-Lines findings", () => {
    expect(detectImportKind("thor.json", ndjson({ time: "t", module: "Filescan", level: "Warning", message: "x" }))).toBe("thor");
  });
  it("siem: Windows event JSON (catch-all)", () => {
    expect(detectImportKind("win.json", j({ data: [{ event_id: 4624, log_name: "Security", event_data: {} }] }))).toBe("siem");
  });
});

describe("detectImportKind — CSV formats", () => {
  it("kape: Prefetch (PECmd) header", () => {
    expect(detectImportKind("pf.csv", "SourceFilename,ExecutableName,RunCount,LastRun\nx,Y.EXE,1,2023-01-01 00:00:00")).toBe("kape");
  });
  it("kape: Amcache header", () => {
    expect(detectImportKind("am.csv", "ApplicationName,FullPath,SHA1,FileKeyLastWriteTimestamp\na,c:/x,abc,t")).toBe("kape");
  });
  it("plaso: dynamic header", () => {
    expect(detectImportKind("tl.csv", "datetime,timestamp_desc,source,message,parser\n2023-01-01T00:00:00+00:00,ctime,FILE,hi,filestat")).toBe("plaso");
  });
  it("plaso: l2tcsv header", () => {
    expect(detectImportKind("tl.csv", "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc\n01/01/2023,00:00:00,UTC,M,FILE,x,t,u,h,s,d")).toBe("plaso");
  });
  it("hayabusa: csv-timeline header", () => {
    expect(detectImportKind("hb.csv", "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details\nt,c,Sec,4625,med,Failed,x")).toBe("hayabusa");
  });
  it("m365: UAL CSV with AuditData column", () => {
    expect(detectImportKind("ual.csv", "RecordType,CreationDate,UserIds,Operations,AuditData\n8,t,u,Op,{}")).toBe("m365");
  });
  it("csv: a generic comma table → AI CSV importer", () => {
    expect(detectImportKind("data.csv", "colA,colB,colC\n1,2,3\n4,5,6")).toBe("csv");
  });
});

describe("detectImportKind — logs & edges", () => {
  it("log: a line-oriented syslog file", () => {
    expect(detectImportKind("auth.log", "Jan  1 00:00:01 host sshd[1]: Failed password for root\nJan  1 00:00:02 host sshd[1]: Failed password for admin")).toBe("log");
  });
  it("unknown: empty input", () => {
    expect(detectImportKind("x", "")).toBe("unknown");
  });
  it("unknown: malformed JSON", () => {
    expect(detectImportKind("x.json", "{ not valid json ")).toBe("unknown");
  });
});
