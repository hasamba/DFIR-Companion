import { describe, it, expect } from "vitest";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";

// ── A Hayabusa json-timeline record (Sysmon process-create matched by a Sigma rule).
function jsonProc(): object {
  return {
    Timestamp: "2021-12-12 12:00:00.000 +00:00",
    Computer: "FS01.corp.local",
    Channel: "Sysmon",
    EventID: 1,
    Level: "high",
    MitreTactics: ["Execution"],
    MitreTags: ["t1059.001"],
    RuleTitle: "PowerShell Download Cradle",
    Details: {
      Proc: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      CmdLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
      ParentProc: "C:\\Program Files\\Microsoft Office\\winword.exe",
      Hashes:
        "SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899,MD5=00112233445566778899aabbccddeeff",
    },
    ExtraFieldInfo: { TgtIP: "10.0.0.9", User: "CORP\\bob" },
  };
}

// ── Build a Hayabusa csv-timeline (quoted Details cell with " ¦ " field separators).
function csvTimeline(rows: string[][]): string {
  const header = [
    "Timestamp",
    "Computer",
    "Channel",
    "EventID",
    "Level",
    "RuleTitle",
    "Details",
    "MitreTags",
  ];
  const esc = (v: string): string => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
}

describe("parseHayabusaTimeline — json-timeline", () => {
  it("maps verdict-first: title leads, level → severity, tags → MITRE", () => {
    const r = parseHayabusaTimeline(JSON.stringify([jsonProc()]));
    expect(r.format).toBe("json");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Hayabusa: PowerShell Download Cradle");
    expect(e.description).toContain("(EID 1 Sysmon)");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1059.001");
    expect(e.asset).toBe("FS01.corp.local");
    expect(e.sources).toEqual(["Hayabusa"]);
    expect(e.processName).toBe("powershell.exe");
    expect(e.parentName).toBe("winword.exe");
    expect(e.sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(e.timestamp).toBe("2021-12-12T12:00:00.000Z"); // +00:00 offset → UTC
  });

  it("extracts IOCs (hash, ip, process) from the detail + extra fields", () => {
    const r = parseHayabusaTimeline(JSON.stringify([jsonProc()]));
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("10.0.0.9"); // from ExtraFieldInfo TgtIP
    expect(r.iocs.find((i) => i.type === "process")?.value).toBe("powershell.exe");
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });

  it("reads NDJSON (json-timeline -J)", () => {
    const text = [JSON.stringify(jsonProc()), JSON.stringify(jsonProc())].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.format).toBe("json");
    expect(r.events).toHaveLength(1); // two identical records aggregate
    expect(r.events[0].count).toBe(2);
  });

  // Regression: `hayabusa json-timeline` (without -J) emits PRETTY-PRINTED objects concatenated
  // with no array wrapper and no commas — neither valid JSON nor NDJSON. This used to import as
  // "0 records / unrecognized". See parseConcatenatedJson in siemImport.
  it("reads concatenated pretty-printed objects (json-timeline default output)", () => {
    const pretty = JSON.stringify(jsonProc(), null, 4);
    const text = `${pretty}\n${pretty}\n`; // two multi-line objects back to back, no commas/array
    const r = parseHayabusaTimeline(text);
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(1); // identical records aggregate
    expect(r.events[0].count).toBe(2);
    expect(r.events[0].description).toContain("Hayabusa: PowerShell Download Cradle");
    expect(r.events[0].severity).toBe("High");
  });
});

describe("parseHayabusaTimeline — csv-timeline", () => {
  it("parses the CSV header + the ' ¦ '-separated Details cell", () => {
    const text = csvTimeline([
      [
        "2021-12-12 09:00:00.000 +00:00",
        "WS02",
        "Sec",
        "4625",
        "medium",
        "Failed Logon",
        "SubjectUser: admin ¦ SrcIP: 192.168.1.50 ¦ LogonType: 3",
        "t1110",
      ],
    ]);
    const r = parseHayabusaTimeline(text);
    expect(r.format).toBe("csv");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("Hayabusa: Failed Logon (EID 4625 Sec)");
    expect(e.mitreTechniques).toContain("T1110");
    expect(e.asset).toBe("WS02");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("192.168.1.50");
    expect(e.timestamp).toBe("2021-12-12T09:00:00.000Z");
  });

  it("aggregates identical rows into a counted row", () => {
    const row = [
      "2021-12-12 09:00:00.000 +00:00",
      "WS02",
      "Sec",
      "4625",
      "medium",
      "Failed Logon",
      "SrcIP: 192.168.1.50",
      "t1110",
    ];
    const r = parseHayabusaTimeline(csvTimeline([row, row]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("#27: preserves an ASCII pipe inside a Cmd value (doesn't split on |, only on ¦)", () => {
    // A shell pipeline in a CmdLine value: `echo hello | grep foo`. The previous regex `[¦|]`
    // split on the ASCII pipe too, truncating the command line and dropping IOCs in the tail.
    const text = csvTimeline([
      [
        "2021-12-12 09:00:00.000 +00:00",
        "WS02",
        "Sec",
        "1",
        "high",
        "Pipe Test",
        "Cmd: ls ¦ Args: echo hello | grep foo",
        "t1059",
      ],
    ]);
    const r = parseHayabusaTimeline(text);
    expect(r.events).toHaveLength(1);
    // The full command line survives — the ASCII pipe is part of the value, not a separator.
    expect(r.events[0].description).toContain("echo hello | grep foo");
  });
});

// Velociraptor's `Windows.Hayabusa.Rules` artifact emits Hayabusa verdict rows in NDJSON with
// `Title` (not `RuleTitle`), `EID` (not `EventID`), no Mitre columns, and `Details` rendered as a
// single " ¦ "-separated STRING rather than an object.
describe("parseHayabusaTimeline — Velociraptor Windows.Hayabusa.Rules variant", () => {
  const vrRow = (o: object): string => JSON.stringify(o);

  it("maps Title/EID/string-Details rows verdict-first (never 'SIEM event')", () => {
    const text = [
      vrRow({
        Timestamp: "2026-06-03T08:27:33.651497602Z",
        Computer: "WIN11.windomain.local",
        Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        EID: 21,
        Level: "informational",
        Title: "RDP Logon",
        RecordID: 123,
        Details: "TgtUser: WIN11\\vagrant ¦ SessID: 1 ¦ SrcIP: LOCAL",
      }),
      vrRow({
        Timestamp: "2026-06-03T08:41:00.000000000Z",
        Computer: "WIN11.windomain.local",
        Channel: "Microsoft-Windows-Sysmon/Operational",
        EID: 3,
        Level: "medium",
        Title: "Net Conn (Sysmon Alert)",
        RecordID: 200,
        Details: "Proc: C:\\Windows\\System32\\cmd.exe ¦ DstIP: 45.77.12.34 ¦ DstPort: 4444",
      }),
    ].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.format).toBe("json");
    expect(r.events).toHaveLength(2);
    expect(r.events.some((e) => /SIEM event/i.test(e.description))).toBe(false);

    const rdp = r.events.find((e) => e.description.includes("RDP Logon"))!;
    expect(rdp.description).toContain("Hayabusa: RDP Logon");
    expect(rdp.description).toContain("(EID 21"); // EID read despite the `EID` (not `EventID`) key
    expect(rdp.severity).toBe("Info"); // from Level
    expect(rdp.sources).toEqual(["Hayabusa"]);
    expect(rdp.asset).toBe("WIN11.windomain.local");
    expect(rdp.timestamp).toMatch(/^2026-06-03T08:27:33/);

    const net = r.events.find((e) => e.description.includes("Net Conn"))!;
    expect(net.severity).toBe("Medium");
    expect(net.processName).toBe("cmd.exe"); // parsed out of the string Details cell
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("45.77.12.34");
  });
});

describe("parseHayabusaTimeline — levels, floor & edges", () => {
  it("accepts both abbreviated and spelled-out levels", () => {
    const mk = (level: string): object => ({ ...jsonProc(), Level: level, RuleTitle: `R-${level}` });
    const r = parseHayabusaTimeline(JSON.stringify([mk("crit"), mk("med"), mk("informational")]));
    const sev = (t: string): string | undefined =>
      r.events.find((e) => e.description.includes(`R-${t}`))?.severity;
    expect(sev("crit")).toBe("Critical");
    expect(sev("med")).toBe("Medium");
    expect(sev("informational")).toBe("Info");
  });

  it("maps Hayabusa's emergency level (abbreviated emer) to Critical, not the Medium fallback (#1433)", () => {
    const mk = (level: string): object => ({ ...jsonProc(), Level: level, RuleTitle: `R-${level}` });
    const r = parseHayabusaTimeline(JSON.stringify([mk("emergency"), mk("emer")]));
    const sev = (t: string): string | undefined =>
      r.events.find((e) => e.description.includes(`R-${t}`))?.severity;
    expect(sev("emergency")).toBe("Critical");
    expect(sev("emer")).toBe("Critical");
  });

  it("applies a minSeverity floor", () => {
    const hi = jsonProc();
    const lo = { ...jsonProc(), Level: "low", RuleTitle: "Noise" };
    const r = parseHayabusaTimeline(JSON.stringify([hi, lo]), { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });

  it("reports empty for a non-timeline file", () => {
    const r = parseHayabusaTimeline("not a timeline");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

// Hayabusa reports each PowerShell 4104 fragment as its own detection row. Fragments sharing a
// ScriptBlockId are one compiled script — see the matching Velociraptor suite.
describe("parseHayabusaTimeline — PowerShell 4104 script-block fragments", () => {
  const SBID = "9c440b78-a34f-40b3-99d6-dca98173b1ce";
  const CHUNKS = ["function Invoke-Mimi { $x = 'AAA", "BBB'; Write-Output $x }"];

  const frag = (part: number, chunk: string, title = "Malicious PowerShell Keywords"): string =>
    JSON.stringify({
      Timestamp: `2026-05-07T16:31:0${part}.000000000Z`,
      Computer: "WS-01",
      Channel: "Microsoft-Windows-PowerShell/Operational",
      EID: 4104,
      Level: "high",
      Title: title,
      RecordID: 900 + part,
      Details: `ScriptBlock: ${chunk} ¦ ScriptBlockID: ${SBID} ¦ MessageNumber: ${part} ¦ MessageTotal: ${CHUNKS.length}`,
    });

  it("collapses fragments of one block into ONE alert carrying the whole script", () => {
    const r = parseHayabusaTimeline(CHUNKS.map((c, i) => frag(i + 1, c)).join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
    expect(r.dropped).toBe(0);
    expect(r.events[0].severity).toBe("High");
  });

  it("keeps two DIFFERENT rules over the same block as two alerts", () => {
    const text = [frag(1, CHUNKS[0]), frag(2, CHUNKS[1], "AMSI Bypass")].join("\n");
    expect(parseHayabusaTimeline(text).events).toHaveLength(2);
  });

  // Hayabusa renders only the first 120 characters of each detail field into the description, and
  // sets no full-detail message of its own. Collapsing the fragments without persisting the joined
  // script would therefore SHOW LESS than the split rows did — the merged alert would hold 120
  // characters of the script where three rows previously held 120 each.
  it("persists the whole joined script, not just the 120 chars the description shows", () => {
    const long = ["A".repeat(200), "B".repeat(200)];
    const r = parseHayabusaTimeline(long.map((c, i) => frag(i + 1, c)).join("\n"));
    expect(r.events).toHaveLength(1);
    const message = r.events[0].message ?? "";
    expect(message).toContain(long[0]); // fragment 1 survives in full
    expect(message).toContain(long[1]); // and so does fragment 2, past the description cut-off
  });

  // Hayabusa joins detail fields with " ¦ ". Trimming each value discarded the script's OWN edge
  // whitespace along with that padding, so a block Windows split right after "Write-Output " came
  // back glued as "Write-Outputvalue" — a script that never ran.
  it("keeps the whitespace at a fragment boundary instead of gluing the halves together", () => {
    const text = ["Write-Output ", "value"].map((c, i) => frag(i + 1, c)).join("\n");
    const message = parseHayabusaTimeline(text).events[0].message ?? "";
    expect(message).toContain("Write-Output value");
    expect(message).not.toContain("Write-Outputvalue");
  });

  it("still trims the padding around ordinary detail fields", () => {
    const r = parseHayabusaTimeline(
      JSON.stringify({
        Timestamp: "2026-06-03T08:27:33.000000000Z",
        Computer: "WS-01",
        Channel: "Microsoft-Windows-Sysmon/Operational",
        EID: 3,
        Level: "medium",
        Title: "Net Conn",
        Details: "Proc: C:\\Windows\\System32\\cmd.exe ¦ DstIP: 45.77.12.34",
      }),
    );
    expect(r.events[0].processName).toBe("cmd.exe"); // no stray spaces in the parsed value
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("45.77.12.34");
  });

  it("adds no message to an ordinary single-part Hayabusa row", () => {
    const r = parseHayabusaTimeline(
      JSON.stringify({
        Timestamp: "2026-06-03T08:27:33.000000000Z",
        Computer: "WS-01",
        Channel: "Microsoft-Windows-Sysmon/Operational",
        EID: 3,
        Level: "medium",
        Title: "Net Conn",
        Details: "Proc: cmd.exe ¦ DstIP: 45.77.12.34",
      }),
    );
    expect(r.events[0].message).toBeUndefined();
  });
});

// The rendered subject cuts every detail value at 120 characters, and the collector-deployment
// rules (collectorDeployment.ts) read the command line and the destination to recognise the case's
// own Velociraptor install. So the row carries both as STRUCTURED fields, whole (#1471).
describe("parseHayabusaTimeline — structured commandLine and dstIp", () => {
  const LONG_MSI = `C:\\Users\\it\\Downloads\\${"a".repeat(130)}\\velociraptor-0.72.msi`;
  const CMD = `C:\\Windows\\System32\\msiexec.exe /i ${LONG_MSI} /qn`;

  it("CSV: Cmdline arrives whole past the 120-char subject cut, and TgtIP becomes dstIp", () => {
    const text = csvTimeline([
      [
        "2026-01-01 09:00:00.000 +00:00",
        "WS01",
        "Sysmon",
        "1",
        "medium",
        "Msiexec Install",
        `Cmdline: ${CMD} ¦ Proc: C:\\Windows\\System32\\msiexec.exe ¦ TgtIP: 10.20.30.40`,
        "t1218.007",
      ],
    ]);
    const e = parseHayabusaTimeline(text).events[0];
    expect(e.commandLine).toBe(CMD);
    expect(e.commandLine!.length).toBeGreaterThan(120);
    expect(e.description).not.toContain("velociraptor-0.72.msi"); // the subject is cut; the field is not
    expect(e.dstIp).toBe("10.20.30.40");
  });

  it("JSON: CommandLine / DstIP aliases set the same fields; loopback and a missing key set nothing", () => {
    const row = (details: object): object => ({
      ...jsonProc(),
      Details: details,
      ExtraFieldInfo: {},
    });
    const r = parseHayabusaTimeline(
      [
        JSON.stringify({
          ...row({ Proc: "C:\\x.exe", CommandLine: CMD, DstIP: "10.20.30.40" }),
          RuleTitle: "A",
        }),
        JSON.stringify({ ...row({ Proc: "C:\\x.exe", DestinationIp: "127.0.0.1" }), RuleTitle: "B" }),
      ].join("\n"),
    );
    const a = r.events.find((e) => e.description.includes("Hayabusa: A"))!;
    expect(a.commandLine).toBe(CMD);
    expect(a.dstIp).toBe("10.20.30.40");
    const b = r.events.find((e) => e.description.includes("Hayabusa: B"))!;
    expect(b.commandLine).toBeUndefined();
    expect(b.dstIp).toBeUndefined();
  });
});

// ── #1726: Velociraptor's Windows.Hayabusa.Rules export in artifact-map form. Auto-detect routes it
// here by name; the rows sit under the artifact key, with Details as the "Key: value ¦ …" string.
function veloHayabusaRow(i: number, extra: object = {}): object {
  return {
    Timestamp: `2026-01-02T03:04:0${i}.000Z`,
    Computer: "WS01.example.com",
    Channel: "Security",
    EID: 4720 + i,
    Level: "high",
    Title: `Rule number ${i}`,
    RecordID: 100 + i,
    Details: `User: alice${i} ¦ Proc: C:\\Windows\\System32\\net${i}.exe`,
    ...extra,
  };
}

describe("parseHayabusaTimeline — Velociraptor artifact-map export (#1726)", () => {
  it("reads the rows under the Windows.Hayabusa.Rules key instead of one root record", () => {
    const text = JSON.stringify({
      "Windows.Hayabusa.Rules": [veloHayabusaRow(1), veloHayabusaRow(2), veloHayabusaRow(3)],
    });
    const r = parseHayabusaTimeline(text, { aggregate: false });
    expect(r.total).toBe(3);
    expect(r.events).toHaveLength(3);
    const e = r.events.find((x) => x.description.includes("Rule number 2"));
    expect(e).toBeDefined();
    expect(e!.severity).toBe("High");
    expect(e!.asset).toBe("WS01.example.com");
    expect(e!.description).toContain("(EID 4722 Security)");
    expect(e!.processName).toBe("net2.exe");
  });

  it("reads a pretty-printed map and merges ExtraFieldInfo into the details", () => {
    const row = veloHayabusaRow(4, { ExtraFieldInfo: { TgtIP: "203.0.113.7" } });
    const text = JSON.stringify({ "Windows.Hayabusa.Rules": [row] }, null, 2);
    const r = parseHayabusaTimeline(text, { aggregate: false });
    expect(r.events).toHaveLength(1);
    expect(r.iocs.map((i) => i.value)).toContain("203.0.113.7");
  });

  it("never maps rows from another artifact in the same map as Hayabusa detections", () => {
    const foreign = {
      Timestamp: "2026-01-02T03:05:00.000Z",
      EID: 4624,
      Title: "Not a Hayabusa rule",
      Computer: "WS01.example.com",
    };
    const text = JSON.stringify({
      "Windows.Hayabusa.Rules": [veloHayabusaRow(1)],
      "Windows.EventLogs.Evtx": [foreign],
    });
    const r = parseHayabusaTimeline(text, { aggregate: false });
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
    expect(r.events.some((x) => x.description.includes("Not a Hayabusa rule"))).toBe(false);
  });

  it("keeps rows that carry their own _Source (the real export stamps Windows.Sigma.Base)", () => {
    const text = JSON.stringify({
      "Windows.Hayabusa.Rules": [
        veloHayabusaRow(1, { _Source: "Windows.Sigma.Base" }),
        veloHayabusaRow(2, { _Source: "Windows.Sigma.Base" }),
      ],
    });
    const r = parseHayabusaTimeline(text, { aggregate: false });
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
  });

  it("reads a generic wrapper that also holds a Hayabusa-named array as before", () => {
    const text = JSON.stringify({ data: [jsonProc()], hayabusa: [] });
    expect(parseHayabusaTimeline(text, { aggregate: false }).events).toHaveLength(1);
  });

  it("reads a single native record with a Hayabusa-named array field as one event", () => {
    const text = JSON.stringify({ ...jsonProc(), HayabusaTags: ["x"] });
    expect(parseHayabusaTimeline(text, { aggregate: false }).events).toHaveLength(1);
  });
});

// #1905: the aggregation key masks digit runs so rotating ids collapse, but it used to mask the HOST
// too. WS01/WS02/WS03 then shared one key and three hosts came back as one event on WS01 — the
// lateral-movement scope the detections exist to show was gone from the forensic timeline.
describe("parseHayabusaTimeline — per-host aggregation (#1905)", () => {
  const psexecRow = (host: string, detail = "Svc: PSEXESVC"): string[] => [
    "2021-12-12 10:00:00.000 +00:00",
    host,
    "Sys",
    "7045",
    "high",
    "PsExec Service Installation",
    detail,
    "t1021.002",
  ];

  it("keeps hosts that differ only by digits as separate events (CSV)", () => {
    const r = parseHayabusaTimeline(
      csvTimeline([
        psexecRow("WS01.example.com"),
        psexecRow("WS02.example.com"),
        psexecRow("WS03.example.com"),
      ]),
    );
    expect(r.events).toHaveLength(3);
    expect(r.events.map((e) => e.asset).sort()).toEqual([
      "WS01.example.com",
      "WS02.example.com",
      "WS03.example.com",
    ]);
    for (const e of r.events) expect(e.count ?? 1).toBe(1);
  });

  it("keeps hosts that differ only by digits as separate events (JSONL)", () => {
    const rec = (host: string): string => JSON.stringify({ ...jsonProc(), Computer: host });
    const r = parseHayabusaTimeline([rec("WS01.example.com"), rec("WS02.example.com")].join("\n"));
    expect(r.events.map((e) => e.asset).sort()).toEqual(["WS01.example.com", "WS02.example.com"]);
  });

  it("still aggregates one host's rows that differ only by a digit in the details", () => {
    const r = parseHayabusaTimeline(
      csvTimeline([psexecRow("WS01.example.com", "Pid: 1234"), psexecRow("WS01.example.com", "Pid: 5678")]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("treats a host's case as the same host", () => {
    const r = parseHayabusaTimeline(
      csvTimeline([psexecRow("WS01.example.com"), psexecRow("ws01.EXAMPLE.com")]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("keeps two long subjects apart when they differ past the key's length bound", () => {
    const pad = "a".repeat(110);
    const detail = (tail: string): string =>
      [1, 2, 3, 4, 5].map((i) => `F${"x".repeat(i)}: ${pad}`).join(" ¦ ") + ` ¦ Last: ${pad}${tail}`;
    const r = parseHayabusaTimeline(
      csvTimeline([
        psexecRow("WS01.example.com", detail("alpha")),
        psexecRow("WS01.example.com", detail("bravo")),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });
});

// #1922: Hayabusa renders a Sysmon EID 3 with the peer and the image AFTER the sixth detail field,
// and the key masked every digit, so a C2 connection aggregated into another image's group.
describe("parseHayabusaTimeline — Net Conn aggregation keeps each peer and each image apart (#1922)", () => {
  const PROC = "C:\\Users\\Public\\updater.exe";
  let seq = 0;
  function netConn(
    tgtIp: string,
    tgtPort: number,
    proto: string,
    proc = PROC,
    srcPort = 50000 + seq,
  ): object {
    seq++;
    return {
      Timestamp: `2026-10-01 10:00:${String(seq % 60).padStart(2, "0")}.000 +00:00`,
      Computer: "WKS-ALPHA",
      Channel: "Sysmon",
      EventID: 3,
      Level: "medium",
      RuleTitle: "Net Conn (Sysmon Alert)",
      RecordID: 7000 + seq,
      Details: {
        Initiated: true,
        Proto: proto,
        SrcIP: "192.0.2.10",
        SrcPort: srcPort,
        SrcHost: "WKS-ALPHA",
        TgtIP: tgtIp,
        TgtPort: tgtPort,
        TgtHost: "-",
        User: "EXAMPLE\\analyst",
        Proc: proc,
        PID: 1000 + seq,
        PGUID: `0f0e0d0c-0000-1111-2222-${String(seq).padStart(12, "0")}`,
      },
    };
  }
  const parse = (recs: object[]) =>
    parseHayabusaTimeline(recs.map((r) => JSON.stringify(r)).join("\n"), { aggregate: true }).events;

  it("keeps a TCP connection apart from the image's mDNS multicasts, with its port", () => {
    const evs = parse([
      netConn("224.0.0.251", 5353, "udp"),
      netConn("192.0.2.10", 5353, "udp"),
      netConn("ff02::fb", 5353, "udp"),
      netConn("198.51.100.7", 8888, "tcp"),
    ]);
    const tcp = evs.filter((e) => e.dstIp === "198.51.100.7");
    expect(tcp).toHaveLength(1);
    expect(tcp[0].port).toBe(8888);
    expect(tcp[0].count ?? 1).toBe(1);
  });

  it("keeps two servers contacted by one image apart", () => {
    const evs = parse([netConn("198.51.100.7", 8888, "tcp"), netConn("203.0.113.9", 443, "tcp")]);
    expect(evs).toHaveLength(2);
  });

  it("keeps the same connection from two images apart", () => {
    const evs = parse([
      netConn("198.51.100.7", 443, "tcp", "C:\\Program Files\\Sync\\sync.exe"),
      netConn("198.51.100.7", 443, "tcp", PROC),
    ]);
    expect(evs).toHaveLength(2);
  });

  it("still aggregates a repeat of one connection whose source port, pid and guid rotate", () => {
    const evs = parse([
      netConn("198.51.100.7", 8888, "tcp", PROC, 51001),
      netConn("198.51.100.7", 8888, "tcp", PROC, 52002),
    ]);
    expect(evs).toHaveLength(1);
    expect(evs[0].count).toBe(2);
  });
});

// An unparseable stamp used to pass through unchanged as the event time (#2063): `9999-…` sorted
// last and time-window code silently dropped the event. The row is kept with an empty time instead.
describe("parseHayabusaTimeline — malformed timestamp (#2063)", () => {
  it("keeps a JSONL row with an impossible ISO stamp but leaves its time empty", () => {
    const rec = { ...jsonProc(), Timestamp: "9999-99-99T99:99:99.000+00:00" };
    const r = parseHayabusaTimeline(JSON.stringify(rec));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toBe("");
  });

  it.each([["9999-99-99 99:99:99.000 +00:00"], ["2026-13-45 10:00:00"], ["not a date"]])(
    "keeps a CSV row stamped %s but leaves its time empty",
    (stamp) => {
      const text = csvTimeline([
        [stamp, "WS02", "Sec", "4625", "medium", "Failed Logon", "SrcIP: 192.168.1.50", ""],
      ]);
      const r = parseHayabusaTimeline(text);
      expect(r.events).toHaveLength(1);
      expect(r.events[0].timestamp).toBe("");
    },
  );

  it("still normalizes a valid offset stamp to UTC", () => {
    const text = csvTimeline([
      [
        "2026-05-01 10:00:00.123 +02:00",
        "WS02",
        "Sec",
        "4625",
        "medium",
        "Failed Logon",
        "SrcIP: 192.168.1.50",
        "",
      ],
    ]);
    expect(parseHayabusaTimeline(text).events[0].timestamp).toBe("2026-05-01T08:00:00.123Z");
  });
});
