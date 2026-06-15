import { describe, it, expect } from "vitest";
import { parseSiemExport, extractRecords } from "../../src/analysis/siemImport.js";

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
    User: "NT AUTHORITY\\SYSTEM",
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

  it("flags LSASS process-access (Sysmon EID 10) as High with credential-dumping MITRE", () => {
    const lsass = {
      "@timestamp": "2017-03-20T10:02:00Z", log_name: "Microsoft-Windows-Sysmon/Operational", computer_name: "WS1",
      event_id: 10, event_data: { SourceImage: "C:\\Temp\\mim.exe", TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1410" },
    };
    const r = parseSiemExport(elastic(lsass));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1003.001");
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
