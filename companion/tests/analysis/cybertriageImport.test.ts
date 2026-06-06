import { describe, it, expect } from "vitest";
import { parseCybertriage } from "../../src/analysis/cybertriageImport.js";

// ── A scored "Bad" file item: lsass dump (real Cyber Triage shape).
function lsassRow(): object {
  return {
    ctType: "File", datetime: "2026-01-28T01:47:37", epoch_timestamp: 1769593657,
    event_timestamp: "2026-01-28T01:47:37", hostName: "win11", message: "/trigonasim/logs/lsass.dmp",
    path: "/trigonasim/logs/lsass.dmp", score: "Notable_Normal",
    scoreDescription: "Output from dumping lsass memory for passwords",
    threat_type: "File", timestamp_desc: "File Created, Modified",
  };
}

// ── A scored "Suspicious" process: unexpected parent (LikelyNotable_Normal verdict).
function suspProcRow(): object {
  return {
    ctType: "process", datetime: "2026-01-28T01:51:05", epoch_timestamp: 1769593865,
    event_timestamp: "2026-01-28T01:51:05", hostName: "win11", message: "/windows/system32/cmd.exe ",
    path: "/windows/system32/cmd.exe", parentProcess: "cscript.exe", parentPath: "/Windows/System32/cscript.exe",
    pid: 7912, ppid: 5904, score: "LikelyNotable_Normal", scoreDescription: "Had unexpected parent",
    timestamp_desc: "Process Created",
  };
}

// ── A scored "Suspicious" scheduled task carrying a UAC-bypass action.
function taskRow(): object {
  return {
    ctType: "Configuration Item", datetime: "2026-01-28T01:47:34", epoch_timestamp: 1769593654,
    event_timestamp: "2026-01-28T01:47:34", hostName: "win11",
    message: "powershell.exe -windowstyle hidden -command \"& 'c:\\trigonasim\\tools\\uac-bypass.ps1'\"",
    name: "\\SystemConfigManager", score: "LikelyNotable_Normal", scoreDescription: "Was created within past 30 days",
    actions: [{ args: "-WindowStyle Hidden -Command \"& 'C:\\TrigonaSim\\tools\\uac-bypass.ps1'\"", path: "powershell.exe" }],
    subType: "Scheduled Task", type: "Scheduled Task", timestamp_desc: "Task Modified",
  };
}

// ── Unscored telemetry: a plain process execution (base fields only).
function telemetryProcRow(): object {
  return {
    datetime: "2026-01-28T01:50:00", epoch_timestamp: 1769593800, event_timestamp: "2026-01-28T01:50:00",
    hostName: "win11", message: "/windows/system32/svchost.exe ", score: "None", timestamp_desc: "Process Created",
  };
}

// ── Unscored bulk File row (the MFT super-timeline — dropped by default).
function fileTelemetryRow(): object {
  return {
    datetime: "2026-01-28T01:52:03", epoch_timestamp: 1769593923, event_timestamp: "2026-01-28T01:52:03",
    hostName: "win11", message: "/programdata/microsoft/network/downloader", score: "None",
    threat_type: "File", timestamp_desc: "File Modified",
  };
}

// ── A network Active Connection (telemetry → IOC only): carries the remote IP.
function activeConnRow(): object {
  return {
    datetime: "2026-01-28T01:48:00", epoch_timestamp: 1769593680, event_timestamp: "2026-01-28T01:48:00",
    hostName: "win11", message: "To 192.168.128.134:8000, Local Port: 49853", score: "None", timestamp_desc: "Active Connection",
  };
}

const jsonl = (...objs: object[]): string => objs.map((o) => JSON.stringify(o)).join("\n");

describe("parseCybertriage — verdict-first scored rows", () => {
  it("maps a Bad lsass-dump file as Critical with T1003.001", () => {
    const r = parseCybertriage(jsonl(lsassRow()));
    expect(r.notable).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Cyber Triage [Bad]");
    expect(e.description).toContain("Output from dumping lsass memory");
    expect(e.severity).toBe("Critical");
    expect(e.mitreTechniques).toContain("T1003.001");
    expect(e.asset).toBe("win11");
    expect(e.path).toBe("/trigonasim/logs/lsass.dmp");
    expect(e.sources).toEqual(["Cyber Triage"]);
    expect(r.iocs.some((i) => i.type === "file" && i.value === "/trigonasim/logs/lsass.dmp")).toBe(true);
  });

  it("maps a Suspicious process with its parent chain at Medium", () => {
    const r = parseCybertriage(jsonl(suspProcRow()));
    const e = r.events[0];
    expect(e.description).toContain("Cyber Triage [Suspicious]");
    expect(e.description).toContain("Had unexpected parent");
    expect(e.severity).toBe("Medium");
    expect(e.processName).toBe("cmd.exe");
    expect(e.parentName).toBe("cscript.exe");
  });

  it("maps a scheduled task with its action command and persistence MITRE", () => {
    const r = parseCybertriage(jsonl(taskRow()));
    const e = r.events[0];
    expect(e.description).toContain("scheduled task \"\\SystemConfigManager\"");
    expect(e.description).toContain("uac-bypass.ps1");
    expect(e.mitreTechniques).toContain("T1053.005");
    expect(e.mitreTechniques).toContain("T1548.002"); // uac-bypass keyword
  });
});

describe("parseCybertriage — telemetry split", () => {
  it("keeps unscored process telemetry as Info evidence", () => {
    const r = parseCybertriage(jsonl(telemetryProcRow()));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].processName).toBe("svchost.exe");
  });

  it("drops unscored bulk File rows by default but keeps them with fileTelemetry", () => {
    expect(parseCybertriage(jsonl(fileTelemetryRow())).events).toHaveLength(0);
    const withFiles = parseCybertriage(jsonl(fileTelemetryRow()), { fileTelemetry: true });
    expect(withFiles.events).toHaveLength(1);
    expect(withFiles.events[0].severity).toBe("Info");
  });

  it("harvests the remote IP from an Active Connection as an IOC, not an event", () => {
    const r = parseCybertriage(jsonl(activeConnRow()));
    expect(r.events).toHaveLength(0);
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "192.168.128.134")).toBe(true);
  });

  it("counts notable vs total and reports the host", () => {
    const r = parseCybertriage(jsonl(lsassRow(), suspProcRow(), telemetryProcRow(), fileTelemetryRow()));
    expect(r.total).toBe(4);
    expect(r.notable).toBe(2);
    expect(r.hostname).toBe("win11");
  });
});

describe("parseCybertriage — CSV timeline", () => {
  it("parses the CSV form and recovers the verdict from threat_level", () => {
    const csv = [
      "event_timestamp,epoch_timestamp,message,timestamp_description,item_type,threat_level",
      "2026-01-28T01:47:37,1769593657,/trigonasim/logs/lsass.dmp,File Modified,File,Bad. Bad list item detected",
      "2026-01-28T01:52:03,1769593923,/programdata/microsoft/network/downloader,File Modified,File,None",
    ].join("\n");
    const r = parseCybertriage(csv);
    expect(r.format).toBe("csv");
    expect(r.total).toBe(2);
    expect(r.notable).toBe(1);
    const e = r.events.find((x) => x.severity !== "Info");
    expect(e?.description).toContain("Cyber Triage [Bad]");
    expect(e?.path).toBe("/trigonasim/logs/lsass.dmp");
  });
});
