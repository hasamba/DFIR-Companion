import { describe, it, expect } from "vitest";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { detectImportWithCustom, buildDetectContext } from "../../src/analysis/importDetect.js";
import { buildImporter } from "../../src/analysis/declarativeImporter.js";
import { EXAMPLE_IMPORTER_SPEC, parseImporterSpec } from "../../src/analysis/importerSpec.js";

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
  it("velociraptor: Elastic-indexed push (artifact_* index / flattened Detection.* keys)", () => {
    expect(detectImportKind("elastic.json", j([{ _index: "artifact_detectraptor_windows_detection_mft", "@timestamp": "t", "Detection.StringHit": "PsExec.exe", "Artifact.keyword": "X" }]))).toBe("velociraptor");
    // No artifact_ index, but flattened Detection.* keys still mark it Velociraptor.
    expect(detectImportKind("e.json", j([{ _index: "logs-foo", "Detection.StringHit": "x", "Artifact.keyword": "Y" }]))).toBe("velociraptor");
  });
  it("NOT velociraptor: a non-artifact Elastic index (MemProcFS mp_timeline) stays SIEM", () => {
    expect(detectImportKind("mp.json", j([{ _index: "mp_timeline", "@timestamp": "t", desc: "x", action: "MOD", type: "REG" }]))).toBe("siem");
  });
  it("securityonion: extension push (_Source 'Security Onion …') wins over the velociraptor _Source rule", () => {
    expect(detectImportKind("so.json", j([{
      _id: "1", _index: "so:.ds-logs-suricata-so-2026.06.19-000001", _Source: "Security Onion Alerts",
      "@timestamp": "t", "event.module": "suricata", "event.severity_label": "high", "rule.name": "ET MALWARE x",
    }]))).toBe("securityonion");
  });
  it("securityonion: raw SOC API export (SO data-stream _index, no _Source stamp)", () => {
    expect(detectImportKind("so.json", j([{
      _index: ".ds-logs-suricata-so-2026.06.19-000001", "@timestamp": "t", "event.module": "suricata", "rule.name": "ET SCAN x",
    }]))).toBe("securityonion");
  });
  it("NOT securityonion: a generic Elastic alert without SO markers stays SIEM", () => {
    expect(detectImportKind("e.json", j([{ _index: "logs-generic", "@timestamp": "t", "rule.name": "x", message: "y" }]))).toBe("siem");
  });
  it("securityonion: SO bundled-Kibana push (ECS event.severity_label, no top-level event_type)", () => {
    // The real shape pushed by the elastic adapter from SO's Kibana: flattened ECS dotted keys, the
    // raw eve only inside a `message` string. event.severity_label is the Security Onion tell.
    expect(detectImportKind("elastic.json", j([{
      _id: "OHjM", _index: ".ds-logs-import-so-2026.06.07-000001", "@timestamp": "t",
      "event.module": "suricata", "event.dataset": "suricata.alert", "event.severity_label": "high",
      "event.severity": 3, "rule.name": "ET MALWARE Agent Tesla CnC Exfil via TCP",
      "source.ip": "10.2.3.101", "destination.ip": "162.241.123.75", "import.id": "0f42",
      message: "{\"event_type\":\"alert\",\"alert\":{\"severity\":1}}",
    }]))).toBe("securityonion");
  });
  it("NOT securityonion: a raw Suricata eve.json record still routes to the network importer", () => {
    expect(detectImportKind("eve.json", j([{ timestamp: "t", event_type: "alert", src_ip: "10.0.0.1", dest_ip: "1.2.3.4", alert: { signature: "x", severity: 1 } }]))).toBe("network");
  });
  it("socrates: extension push stamped _Source SO-CRATES (not velociraptor)", () => {
    expect(detectImportKind("socrates-1.json", j([{ _Source: "SO-CRATES", event_type: "alert", alert: { signature: "ET x" } }]))).toBe("socrates");
  });
  it("socrates: YARA filealerts record", () => {
    expect(detectImportKind("fa.json", j([{ event_type: "filealerts", filealerts: { rule_name: "X", sha256: "a" } }]))).toBe("socrates");
  });
  it("socrates: Sigma alert record", () => {
    expect(detectImportKind("sig.json", j([{ rule_title: "Suspicious PowerShell", rule_id: "r1", level: "high" }]))).toBe("socrates");
  });
  it("network: a plain Suricata eve.json alert (no SO-CRATES markers) stays network", () => {
    expect(detectImportKind("eve.json", j([{ event_type: "alert", src_ip: "1.2.3.4", alert: { signature: "ET x", severity: 1 } }]))).toBe("network");
  });
  it("siem: a generic Windows event (no SO-CRATES markers) is not claimed by socrates", () => {
    expect(detectImportKind("evt.json", j([{ EventID: 4624, message: "An account was successfully logged on", "@timestamp": "2024-01-01T00:00:00Z" }]))).toBe("siem");
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
  it("memory: Volatility 3 TEXT/grid renderer (banner + tab-separated header)", () => {
    const txt = "Volatility 3 Framework 2.28.0\n\nPID\tProcess\tProtection\tTag\n7352\tSearchHost.exe\tPAGE_EXECUTE_READWRITE\tVadS\t";
    expect(detectImportKind("malfind.txt", txt)).toBe("memory");
  });
  it("memory: MemProcFS findevil report (space-separated finding table)", () => {
    const findevil = [
      "   #    PID Process        Type            Address          Description",
      "-----------------------------------------------------------------------",
      "0000   8684 Velociraptor.e HIGH_ENTROPY    000000c001c00000 Entropy:[8.00]",
      "0004   6416 svchost.exe    YR_HACKTOOL     0000022a7a0b804e Windows_Hacktool_SharpDump_7c17d8b1 [0]",
    ].join("\n");
    expect(detectImportKind("findevil.txt", findevil)).toBe("memory");
  });
  it("memory: MemProcFS timeline_all.csv (Time,Type,Action,PID,Value32,Value64,Text,Pad)", () => {
    const csv = 'Time,Type,Action,PID,Value32,Value64,Text,Pad\n"2026-06-03 08:57:15",NTFS,MOD,0,0x0,0x233820000,\\1\\Windows\\foo.etl,"  "';
    expect(detectImportKind("timeline_all.csv", csv)).toBe("memory");
  });
  it("memory: MemProcFS findevil.csv (PID,ProcessName,Type,Address,Description)", () => {
    const csv = 'PID,ProcessName,Type,Address,Description\n6416,svchost.exe,YR_HACKTOOL,0x22a7a0b804e,"Windows_Hacktool_SharpDump_7c17d8b1 [0]"';
    expect(detectImportKind("findevil.csv", csv)).toBe("memory");
  });
  it("memory: MemProcFS yara.csv (MatchIndex,...,MemoryType,MemoryTag,...,ProcessName,...)", () => {
    const csv = 'MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,ObjectAddress,PID,ProcessName,ProcessPath,CommandLine,User,Created,AddressCount,String0,Address0\n0,"","","Elastic Security","","Virtual Memory (VAD)","HEAP-00",22a7a000000,"",6416,svchost.exe,\\path,cmd,SYSTEM,"2026-06-03 08:31:44",1,abc,22a7a0b804e';
    expect(detectImportKind("yara.csv", csv)).toBe("memory");
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
  it("velociraptor: Elastic Discover CSV export of DetectRaptor data", () => {
    const header = '"@timestamp",Artifact,"Artifact.keyword","Detection.Name","Detection.StringHit",_index,_Source';
    const row = '"May 7, 2026 @ 16:31:04.000",DetectRaptor.Windows.Detection.Amcache,DetectRaptor.Windows.Detection.Amcache,"Execution - PsExec",PsExec.exe,artifact_detectraptor_windows_detection_amcache,"-"';
    expect(detectImportKind("Untitled Discover session.csv", `${header}\n${row}`)).toBe("velociraptor");
  });
  it("csv: a generic Elastic CSV without Velociraptor columns stays the AI CSV importer", () => {
    expect(detectImportKind("e.csv", '"@timestamp",message,_index\nt,hi,logs-app')).toBe("csv");
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

describe("detectImportKind — Linux evidence sources (#62)", () => {
  it("auditd: raw audit.log / ausearch record format", () => {
    const log = 'type=SYSCALL msg=audit(1490451217.272:270): arch=c000003e syscall=59 comm="cat" exe="/usr/bin/cat"\ntype=EXECVE msg=audit(1490451217.272:270): argc=2 a0="cat" a1="/etc/shadow"';
    expect(detectImportKind("audit.log", log)).toBe("auditd");
  });
  it("auditd: with ausearch separators / interpreted header", () => {
    const log = "----\ntime->Sat Mar 25 13:53:37 2017\ntype=USER_LOGIN msg=audit(1490451217.000:600): pid=1 uid=0 msg='op=login acct=\"root\" res=failed'";
    expect(detectImportKind("ausearch.txt", log)).toBe("auditd");
  });
  it("journald: journalctl -o json (claimed ahead of the SIEM message catch-all)", () => {
    expect(detectImportKind("journal.json", ndjson(
      { __REALTIME_TIMESTAMP: "1717200000000000", PRIORITY: "6", MESSAGE: "Failed password for root from 1.2.3.4", SYSLOG_IDENTIFIER: "sshd", _HOSTNAME: "h" },
    ))).toBe("journald");
  });
  it("sysdig: Falco alert JSON", () => {
    expect(detectImportKind("falco.json", ndjson(
      { time: "2024-06-01T00:00:00Z", rule: "Terminal shell in container", priority: "Warning", output: "shell spawned", output_fields: {} },
    ))).toBe("sysdig");
  });
  it("sysdig: sysdig -j event JSON (dotted evt.* keys)", () => {
    expect(detectImportKind("capture.json", ndjson(
      { "evt.num": 1, "evt.rawtime": 1717200000000000000, "proc.name": "curl", "evt.type": "connect" },
    ))).toBe("sysdig");
  });
  it("not auditd: a plain syslog with no audit records stays 'log'", () => {
    expect(detectImportKind("auth.log", "Jan  1 00:00:01 host sshd[1]: Failed password for root")).toBe("log");
  });
});

describe("detectImportKind — Wazuh", () => {
  it("wazuh: JSON array of alerts (rule.level + rule.description + agent)", () => {
    expect(detectImportKind("alerts.json", j([{
      timestamp: "2024-01-15T10:30:00.000+0000",
      rule: { level: 10, description: "Authentication failure", id: "5503", groups: ["authentication"] },
      agent: { id: "001", name: "web-server-01" },
    }]))).toBe("wazuh");
  });
  it("wazuh: NDJSON alerts", () => {
    expect(detectImportKind("wazuh-alerts.json", ndjson({
      timestamp: "2024-01-15T10:30:00.000+0000",
      rule: { level: 7, description: "Suspicious activity", id: "9999" },
      agent: { id: "002", name: "linux-host" },
    }))).toBe("wazuh");
  });
  it("wazuh: API export envelope { data: { affected_items: [...] } }", () => {
    expect(detectImportKind("export.json", j({
      data: {
        affected_items: [{
          timestamp: "2024-01-15T10:30:00.000+0000",
          rule: { level: 12, description: "Malware detected", id: "87105" },
          agent: { id: "003", name: "endpoint-01" },
        }],
        total_affected_items: 1,
      },
    }))).toBe("wazuh");
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
  it("thehive: single case object", () => {
    expect(detectImportKind("case.json", j({ _type: "case", title: "Incident", severity: 3 }))).toBe("thehive");
  });
  it("thehive: array of alerts", () => {
    expect(detectImportKind("alerts.json", j([{ _type: "alert", title: "TOR login", severity: 2 }]))).toBe("thehive");
  });
  it("thehive: search result container { data: [...] }", () => {
    expect(detectImportKind("search.json", j({ data: [{ _type: "case", title: "x", severity: 1 }] }))).toBe("thehive");
  });
  it("thehive: observable array (dataType+data, ioc:true)", () => {
    expect(detectImportKind("obs.json", j([{ dataType: "ip", data: "1.2.3.4", ioc: true }]))).toBe("thehive");
  });
  it("NOT thehive: Elasticsearch hit wrapper with _source is skipped", () => {
    // An ES hit carrying a TheHive-like `_type` must NOT be detected as thehive.
    const esHit = { _type: "case", _source: { title: "x" }, _index: "thehive_cases", _id: "abc123" };
    expect(detectImportKind("es.json", j([esHit]))).not.toBe("thehive");
  });
});

describe("detectImportKind — Windows Event Log XML", () => {
  const evtxXml = `<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>
  <Channel>Security</Channel><Computer>DC01</Computer><TimeCreated SystemTime="2024-05-14T12:00:00Z"/></System>
  <EventData><Data Name="TargetUserName">jdoe</Data></EventData>
</Event></Events>`;
  it("evtxxml: Event Viewer / wevtutil XML export", () => {
    expect(detectImportKind("windows_event_security.xml", evtxXml)).toBe("evtxxml");
  });
  it("evtxxml: namespace-stripped envelope still detected", () => {
    expect(detectImportKind("sysmon.xml", "<Events><Event><System><EventID>1</EventID></System></Event></Events>")).toBe("evtxxml");
  });
  it("NOT evtxxml: arbitrary HTML/XML is left to the log fallback", () => {
    expect(detectImportKind("page.xml", "<note><to>You</to><from>Me</from></note>")).toBe("log");
  });
});

describe("detectImportKind — shell history", () => {
  it("bashhistory: by filename", () => {
    expect(detectImportKind("nina.kapoor.bash_history", "ls\nid\nwhoami")).toBe("bashhistory");
    expect(detectImportKind("0001_root.zsh_history", "ls")).toBe("bashhistory");
  });
  it("bashhistory: by #epoch content signature", () => {
    expect(detectImportKind("dump.txt", "#1715688062\ncat /etc/fstab\n#1715691267\nls -la")).toBe("bashhistory");
  });
  it("NOT bashhistory: a plain syslog stays a log", () => {
    expect(detectImportKind("auth.log", "Jan  1 00:00:01 host sshd[1]: Failed password for root\nJan  1 00:00:02 host sshd[1]: Failed password for admin")).toBe("log");
  });
});

function exampleImporter() {
  const r = parseImporterSpec(EXAMPLE_IMPORTER_SPEC);
  if (!r.ok) throw new Error("bad example");
  return buildImporter(r.spec);
}
const MDE = "Timestamp,DeviceName,ActionType,FileName,Severity\n2026-06-10T12:00:00Z,H,A,f.exe,High";

describe("detectImportWithCustom precedence", () => {
  const imps = new Map([["mde-advanced-hunting", exampleImporter()]]);

  it("builtin-first: a custom importer claims a file that would otherwise fall back to csv", () => {
    expect(detectImportKind("ah.csv", MDE)).toBe("csv"); // built-in fallback today
    expect(detectImportWithCustom("ah.csv", MDE, imps, "builtin-first")).toBe("mde-advanced-hunting");
  });

  it("builtin-first: a confident built-in still wins over a custom importer", () => {
    const siem = JSON.stringify([{ EventID: 4624, Channel: "Security" }]);
    expect(detectImportWithCustom("x.json", siem, imps, "builtin-first")).toBe("siem");
  });

  it("velociraptor: pslist/pstree NDJSON (CallChain + Pid, no _Source)", () => {
    const row = { Pid: "1004", Ppid: "592", Name: "svchost.exe", Exe: "C:\\Windows\\System32\\svchost.exe", CommandLine: "svchost.exe -k netsvcs", StartTime: "2026-06-12T11:12:45Z", EndTime: "0001-01-01T00:00:00Z", CallChain: "svchost.exe", PSTree: null };
    expect(detectImportKind("F.D8M0V5UIO64QE.H.json", ndjson(row))).toBe("velociraptor");
  });

  it("velociraptor: netstat NDJSON (Laddr + Lport + Status, no _Source)", () => {
    const row = { Pid: "1004", Name: "svchost.exe", Family: "TCP", Type: "SOCK_STREAM", Laddr: "0.0.0.0", Lport: "445", Raddr: "", Rport: "0", Status: "LISTEN", Timestamp: "2026-06-12T11:15:00Z" };
    expect(detectImportKind("Netstat.json", ndjson(row))).toBe("velociraptor");
  });

  it("external-first: a custom importer can override even a specific built-in", () => {
    const r = parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, id: "my-evtx", match: { format: "json", requireKeys: ["EventID"], priority: 1 } });
    if (!r.ok) throw new Error("bad");
    const m = new Map([["my-evtx", buildImporter(r.spec)]]);
    const siem = JSON.stringify([{ EventID: 4624, Channel: "Security" }]);
    expect(detectImportWithCustom("x.json", siem, m, "external-first")).toBe("my-evtx");
  });
});
