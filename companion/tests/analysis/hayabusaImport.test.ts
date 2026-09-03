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

// ── Investigator-workflow regressions (2026-09 codebase review) ─────────────────────────────────

const HAYABUSA_CSV_HEADER =
  '"Timestamp","Computer","Channel","EventID","Level","MitreTactics","MitreTags","OtherTags","RuleTitle","Details","ExtraFieldInfo","RuleFile","EvtxFile"';

function csvRow(
  ts: string,
  computer: string,
  eid: string,
  level: string,
  title: string,
  details: string,
): string {
  return `"${ts}","${computer}","Sec","${eid}","${level}","","","","${title}","${details}","","${title}.yml","${computer}.evtx"`;
}

describe("Hayabusa level vocabulary", () => {
  it("maps the emergency level (Hayabusa's highest, abbreviated 'emer') to Critical, not the Medium fallback", () => {
    const text = [
      HAYABUSA_CSV_HEADER,
      csvRow("2026-05-12 18:00:00.000 +00:00", "WS-01", "4624", "emer", "Mimikatz Emergency", "x: y"),
      csvRow("2026-05-12 18:01:00.000 +00:00", "WS-02", "4624", "emergency", "Spelled Emergency", "x: y"),
    ].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.events.map((e) => e.severity)).toEqual(["Critical", "Critical"]);
    // With the import-time severity floor the manual recommends, the emergency rows must survive.
    expect(parseHayabusaTimeline(text, { minSeverity: "High" }).events).toHaveLength(2);
  });
});

describe("Hayabusa aggregation key", () => {
  it("does not fold the same rule on hosts that differ only by a number into one row on the first host", () => {
    const text = [
      HAYABUSA_CSV_HEADER,
      csvRow(
        "2026-05-12 08:00:00.000 +00:00",
        "WS-01.acme.local",
        "4624",
        "high",
        "RDP Logon",
        "Type: 10 ¦ TgtUser: j.rivera ¦ SrcIP: 10.20.30.44",
      ),
      csvRow(
        "2026-05-13 21:30:00.000 +00:00",
        "WS-02.acme.local",
        "4624",
        "high",
        "RDP Logon",
        "Type: 10 ¦ TgtUser: j.rivera ¦ SrcIP: 10.20.30.44",
      ),
    ].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.events).toHaveLength(2);
    expect(r.events.map((e) => e.asset).sort()).toEqual(["WS-01.acme.local", "WS-02.acme.local"]);
    expect(r.events.map((e) => e.count ?? 1)).toEqual([1, 1]);
  });

  it("does not fold a logon success (4624) with a logon failure (4625) on the same host", () => {
    const text = [
      HAYABUSA_CSV_HEADER,
      csvRow(
        "2026-05-14 02:00:00.000 +00:00",
        "SRV17",
        "4624",
        "high",
        "RDP Logon",
        "TgtUser: j.rivera ¦ SrcIP: 10.20.30.99",
      ),
      csvRow(
        "2026-05-14 02:10:00.000 +00:00",
        "SRV17",
        "4625",
        "high",
        "RDP Logon",
        "TgtUser: j.rivera ¦ SrcIP: 10.20.30.99",
      ),
    ].join("\n");
    expect(parseHayabusaTimeline(text).events).toHaveLength(2);
  });

  it("still folds repeats of one rule on one host that differ only by volatile numbers", () => {
    const text = [
      HAYABUSA_CSV_HEADER,
      csvRow(
        "2026-05-12 08:00:00.000 +00:00",
        "WS-01",
        "4688",
        "med",
        "Whoami Execution",
        "Proc: whoami.exe ¦ PID: 4001",
      ),
      csvRow(
        "2026-05-12 08:05:00.000 +00:00",
        "WS-01",
        "4688",
        "med",
        "Whoami Execution",
        "Proc: whoami.exe ¦ PID: 4077",
      ),
    ].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});
