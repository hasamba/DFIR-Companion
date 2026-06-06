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
      Hashes: "SHA256=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899,MD5=00112233445566778899aabbccddeeff",
    },
    ExtraFieldInfo: { TgtIP: "10.0.0.9", User: "CORP\\bob" },
  };
}

// ── Build a Hayabusa csv-timeline (quoted Details cell with " ¦ " field separators).
function csvTimeline(rows: string[][]): string {
  const header = ["Timestamp", "Computer", "Channel", "EventID", "Level", "RuleTitle", "Details", "MitreTags"];
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
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("10.0.0.9");      // from ExtraFieldInfo TgtIP
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
});

describe("parseHayabusaTimeline — csv-timeline", () => {
  it("parses the CSV header + the ' ¦ '-separated Details cell", () => {
    const text = csvTimeline([
      ["2021-12-12 09:00:00.000 +00:00", "WS02", "Sec", "4625", "medium", "Failed Logon", "SubjectUser: admin ¦ SrcIP: 192.168.1.50 ¦ LogonType: 3", "t1110"],
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
    const row = ["2021-12-12 09:00:00.000 +00:00", "WS02", "Sec", "4625", "medium", "Failed Logon", "SrcIP: 192.168.1.50", "t1110"];
    const r = parseHayabusaTimeline(csvTimeline([row, row]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});

// Velociraptor's `Windows.Hayabusa.Rules` artifact emits Hayabusa verdict rows in NDJSON with
// `Title` (not `RuleTitle`), `EID` (not `EventID`), no Mitre columns, and `Details` rendered as a
// single " ¦ "-separated STRING rather than an object.
describe("parseHayabusaTimeline — Velociraptor Windows.Hayabusa.Rules variant", () => {
  const vrRow = (o: object): string => JSON.stringify(o);

  it("maps Title/EID/string-Details rows verdict-first (never 'SIEM event')", () => {
    const text = [
      vrRow({ Timestamp: "2026-06-03T08:27:33.651497602Z", Computer: "WIN11.windomain.local", Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", EID: 21, Level: "informational", Title: "RDP Logon", RecordID: 123, Details: "TgtUser: WIN11\\vagrant ¦ SessID: 1 ¦ SrcIP: LOCAL" }),
      vrRow({ Timestamp: "2026-06-03T08:41:00.000000000Z", Computer: "WIN11.windomain.local", Channel: "Microsoft-Windows-Sysmon/Operational", EID: 3, Level: "medium", Title: "Net Conn (Sysmon Alert)", RecordID: 200, Details: "Proc: C:\\Windows\\System32\\cmd.exe ¦ DstIP: 45.77.12.34 ¦ DstPort: 4444" }),
    ].join("\n");
    const r = parseHayabusaTimeline(text);
    expect(r.format).toBe("json");
    expect(r.events).toHaveLength(2);
    expect(r.events.some((e) => /SIEM event/i.test(e.description))).toBe(false);

    const rdp = r.events.find((e) => e.description.includes("RDP Logon"))!;
    expect(rdp.description).toContain("Hayabusa: RDP Logon");
    expect(rdp.description).toContain("(EID 21");            // EID read despite the `EID` (not `EventID`) key
    expect(rdp.severity).toBe("Info");                       // from Level
    expect(rdp.sources).toEqual(["Hayabusa"]);
    expect(rdp.asset).toBe("WIN11.windomain.local");
    expect(rdp.timestamp).toMatch(/^2026-06-03T08:27:33/);

    const net = r.events.find((e) => e.description.includes("Net Conn"))!;
    expect(net.severity).toBe("Medium");
    expect(net.processName).toBe("cmd.exe");                 // parsed out of the string Details cell
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("45.77.12.34");
  });
});

describe("parseHayabusaTimeline — levels, floor & edges", () => {
  it("accepts both abbreviated and spelled-out levels", () => {
    const mk = (level: string): object => ({ ...jsonProc(), Level: level, RuleTitle: `R-${level}` });
    const r = parseHayabusaTimeline(JSON.stringify([mk("crit"), mk("med"), mk("informational")]));
    const sev = (t: string): string | undefined => r.events.find((e) => e.description.includes(`R-${t}`))?.severity;
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
