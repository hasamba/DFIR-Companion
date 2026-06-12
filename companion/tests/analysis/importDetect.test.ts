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
  it("hayabusa: concatenated pretty-printed objects (json-timeline default, no array/commas)", () => {
    const rec = { Timestamp: "t", RuleTitle: "x", Level: "high", Computer: "h", EventID: 1 };
    const pretty = JSON.stringify(rec, null, 4);
    expect(detectImportKind("timeline.json", `${pretty}\n${pretty}\n`)).toBe("hayabusa");
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
  it("cybertriage: timeline JSONL (epoch + timestamp_desc + score)", () => {
    expect(detectImportKind("tl.jsonl", ndjson(
      { epoch_timestamp: 1769593923, event_timestamp: "2026-01-28T01:52:03", hostName: "win11", message: "/x", score: "None", timestamp_desc: "File Modified" },
    ))).toBe("cybertriage");
  });
  it("cybertriage: claimed ahead of the SIEM message catch-all", () => {
    expect(detectImportKind("tl.json", j([{ epoch_timestamp: 1769593923, message: "/x", scoreDescription: "Yara pattern detected", timestamp_desc: "Process Created" }]))).toBe("cybertriage");
  });
  it("memory: Volatility 3 pslist array (__children + ImageFileName)", () => {
    expect(detectImportKind("pslist.json", j([{ __children: [], PID: 4, PPID: 0, ImageFileName: "System", CreateTime: "t" }]))).toBe("memory");
  });
  it("memory: Volatility 3 netscan (LocalAddr + ForeignAddr)", () => {
    expect(detectImportKind("netscan.json", j([{ __children: [], Proto: "TCPv4", LocalAddr: "10.0.0.1", ForeignAddr: "8.8.8.8", State: "ESTABLISHED", PID: 4 }]))).toBe("memory");
  });
  it("memory: Volatility 3 malfind (Protection + Tag)", () => {
    expect(detectImportKind("malfind.json", j([{ __children: [], PID: 4, Process: "x.exe", Protection: "PAGE_EXECUTE_READWRITE", Tag: "VadS" }]))).toBe("memory");
  });
  it("memory: combined { plugin: rows } map — claimed ahead of the Velociraptor artifact-map", () => {
    expect(detectImportKind("vol.json", j({ "windows.pslist.PsList": [{ PID: 4, ImageFileName: "System" }] }))).toBe("memory");
  });
  it("memory: Rekall JSON statement list", () => {
    expect(detectImportKind("rekall.json", j([["m", { tool_name: "rekall", plugin: { name: "pslist" } }], ["t", [], {}], ["r", { _EPROCESS: { name: "System" }, ppid: 0 }]]))).toBe("memory");
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
  it("cybertriage: timeline CSV header", () => {
    expect(detectImportKind("tl.csv", "event_timestamp,epoch_timestamp,message,timestamp_description,item_type,threat_level\n2026-01-28T01:52:03,1769593923,/x,File Modified,File,None")).toBe("cybertriage");
  });
  it("csv: a generic comma table → AI CSV importer", () => {
    expect(detectImportKind("data.csv", "colA,colB,colC\n1,2,3\n4,5,6")).toBe("csv");
  });
});

describe("detectImportKind — email", () => {
  const eml = [
    "Return-Path: <attacker@evil.example>",
    "Received: from mx.evil.example (mx.evil.example [203.0.113.7]) by mail.victim.com",
    "Authentication-Results: mail.victim.com; spf=fail; dkim=fail; dmarc=fail",
    "From: \"IT Support\" <attacker@evil.example>",
    "To: victim@victim.com",
    "Subject: Urgent: reset your password",
    "Date: Tue, 01 Dec 2017 08:00:00 +0000",
    "Message-ID: <abc@evil.example>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain",
    "",
    "Click http://evil.example/login now.",
  ].join("\n");

  it("email: .eml RFC 822 header block", () => {
    expect(detectImportKind("phish.eml", eml)).toBe("email");
  });
  it("email: filename hint isn't required — content alone suffices", () => {
    expect(detectImportKind("message.txt", eml)).toBe("email");
  });
  it("email: .msg via OLE MAPI stream markers in mangled text", () => {
    const msg = "���__substg1.0_007D001F\x00F\x00r\x00o\x00m\x00:\x00 \x00a@b.com";
    expect(detectImportKind("evidence.msg", msg)).toBe("email");
  });
  it("email: .msg filename alone routes (binary body sniffs as nothing else)", () => {
    expect(detectImportKind("outlook.msg", "garbled binary payload with no markers")).toBe("email");
  });
  it("not email: a syslog with no email-only header stays 'log'", () => {
    expect(detectImportKind("auth.log", "From: someone\nNote: this is not an email\nrandom line")).toBe("log");
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
