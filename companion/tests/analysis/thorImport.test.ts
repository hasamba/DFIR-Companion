import { describe, it, expect } from "vitest";
import { parseThorReport } from "../../src/analysis/thorImport.js";

// A few representative THOR JSON-Lines: lifecycle/info noise + real findings.
const INIT = { time: "2026-06-03T09:39:24Z", hostname: "WIN11", level: "Notice", module: "Init", message: "Lite version" };
const STARTUP = { time: "2026-06-03T09:39:25Z", hostname: "WIN11", level: "Info", module: "Startup", message: "module loaded" };
const AUTORUN_INFO = { time: "2026-06-03T09:40:00Z", hostname: "WIN11", level: "Info", module: "Autoruns", message: "autorun entry", file: "C:\\x.exe" };
const PROC_ALERT = {
  time: "2026-06-03T09:43:07Z", hostname: "WIN11", level: "Alert", module: "ProcessCheck",
  message: "Malicious process found", pid: 8684, process_name: "evil.exe", owner: "NT AUTHORITY\\SYSTEM",
  created: "2026-06-03T08:35:23Z", image_file: "C:\\Tools\\evil.exe",
  image_sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
  reason_1: "YARA rule Powerkatz_DLL / Detects Mimikatz",
};
const FILE_WARN = {
  time: "2026-06-03T09:43:30Z", hostname: "WIN11", level: "Warning", module: "Filescan",
  message: "Possibly Dangerous file found", file: "C:\\Users\\srv\\Trigona.ps1",
  modified: "2025-03-14T21:18:18Z", reason_1: "YARA rule SUSP_PS1 / Suspicious PowerShell",
  md5: "9ac54dafda6bff96fb37f805d59dbf98",
};

function jsonl(...rows: object[]): string {
  return rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
}

describe("parseThorReport", () => {
  it("drops Info level and lifecycle modules by default, keeps real findings", () => {
    const r = parseThorReport(jsonl(INIT, STARTUP, AUTORUN_INFO, PROC_ALERT, FILE_WARN));
    expect(r.total).toBe(5);
    expect(r.kept).toBe(2);                 // only the Alert + Warning
    expect(r.dropped).toBe(3);              // Init(Notice but lifecycle), Startup(Info), Autoruns(Info)
    expect(r.hostname).toBe("WIN11");
    expect(r.events.map((e) => e.severity)).toEqual(["Critical", "High"]); // Alert→Critical sorts first
    // Each event carries its scanned host as the affected asset (for the asset graph).
    expect(r.events.every((e) => e.asset === "WIN11")).toBe(true);
  });

  it("maps THOR level to severity (Alert→Critical, Warning→High, Notice→Medium)", () => {
    const notice = { time: "t", hostname: "H", level: "Notice", module: "Filescan", message: "noteworthy", file: "C:\\n.txt" };
    const r = parseThorReport(jsonl(PROC_ALERT, FILE_WARN, notice));
    const sev = Object.fromEntries(r.events.map((e) => [e.severity, true]));
    expect(sev).toMatchObject({ Critical: true, High: true, Medium: true });
  });

  it("reads the artifact's own time (process created / file modified), not the scan time", () => {
    const r = parseThorReport(jsonl(PROC_ALERT, FILE_WARN));
    const proc = r.events.find((e) => e.description.includes("evil.exe"))!;
    const file = r.events.find((e) => e.description.includes("Trigona"))!;
    expect(proc.timestamp).toBe("2026-06-03T08:35:23Z"); // process create, not 09:43 scan
    expect(file.timestamp).toBe("2025-03-14T21:18:18Z"); // file mtime
  });

  it("extracts hashes / files / processes as IOCs", () => {
    const r = parseThorReport(jsonl(PROC_ALERT, FILE_WARN));
    const vals = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(vals).toContain("hash:4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef");
    expect(vals).toContain("hash:9ac54dafda6bff96fb37f805d59dbf98");
    expect(vals).toContain("process:evil.exe");
    expect(vals.some((v) => v.startsWith("file:C:\\Tools\\evil.exe"))).toBe(true);
  });

  it("builds a self-describing description with module, message, subject and rule", () => {
    const r = parseThorReport(jsonl(PROC_ALERT));
    expect(r.events[0].description).toContain("THOR Alert [ProcessCheck]");
    expect(r.events[0].description).toContain("Malicious process found");
    expect(r.events[0].description).toContain("evil.exe");
    expect(r.events[0].description).toContain("Powerkatz_DLL");
  });

  it("collapses identical findings with a count", () => {
    const r = parseThorReport(jsonl(PROC_ALERT, PROC_ALERT, PROC_ALERT));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });

  it("minLevel floor: 'Warning' drops Notice, 'Alert' keeps only Alerts", () => {
    const notice = { time: "t", hostname: "H", level: "Notice", module: "Filescan", message: "noteworthy", file: "C:\\n.txt" };
    const all = jsonl(PROC_ALERT, FILE_WARN, notice);

    expect(parseThorReport(all).kept).toBe(3);                       // default: Alert+Warning+Notice
    const warn = parseThorReport(all, { minLevel: "Warning" });
    expect(warn.kept).toBe(2);                                        // Notice dropped
    expect(warn.events.map((e) => e.severity).sort()).toEqual(["Critical", "High"]);
    const alert = parseThorReport(all, { minLevel: "Alert" });
    expect(alert.kept).toBe(1);                                       // only the Alert
    expect(alert.events[0].severity).toBe("Critical");
  });

  it("keeps Info / lifecycle when filters are disabled", () => {
    const r = parseThorReport(jsonl(INIT, STARTUP, PROC_ALERT), { dropInfo: false, dropLifecycleModules: false });
    expect(r.kept).toBe(3);
  });

  it("captures process + parent basenames from a ProcessCheck row (for chain validation)", () => {
    const proc = {
      time: "2026-06-03T09:43:07Z", hostname: "WIN11", level: "Alert", module: "ProcessCheck",
      message: "Malicious process found", process_name: "powershell.exe",
      parent: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    };
    const r = parseThorReport(jsonl(proc));
    expect(r.events[0].processName).toBe("powershell.exe");
    expect(r.events[0].parentName).toBe("EXCEL.EXE");        // basename of the parent path
  });

  it("ignores unparseable lines without throwing", () => {
    const r = parseThorReport("not json\n" + JSON.stringify(PROC_ALERT) + "\n{bad\n");
    expect(r.kept).toBe(1);
    expect(r.dropped).toBeGreaterThanOrEqual(2);
  });
});
