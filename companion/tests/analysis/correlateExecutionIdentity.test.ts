import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1476 — correlation folded rows that describe DIFFERENT things into one row and the forensic
// timeline lost them: four renamed copies of cmd.exe (one hash, four paths) became one row, and
// three executions of one binary with three command lines (1 s apart) became one row. Every case
// here is the shape the real hunt produced, with lab-safe names.

const SHA = "9695cf4566ddf878a69c3d419e0da4eea87b0f24261ad8e79a3a9c4a9885429c";
const HOST = "WS-01.example.com";
const ROOT = "C:\\Users\\Public\\Sim\\";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-09-20T19:29:14.400Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...over,
  };
}

const rename = (id: string, name: string, dir = ROOT, t = "2026-09-20T19:29:08Z"): ForensicEvent =>
  ev({
    id,
    timestamp: t,
    description: `Velociraptor [DetectRaptor.Windows.Detection.BinaryRename]: Renamed binary — ${name} is really Cmd.Exe (Microsoft Corporation) at ${dir}${name}`,
    path: `${dir}${name}`,
    sha256: SHA,
    sources: ["Velociraptor"],
  });

const exec = (id: string, t: string, target: string, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    id,
    timestamp: t,
    description: `Velociraptor [Windows.Sigma.Base] Sigma: HackTool — NetExec Execution - Cmdline: "${ROOT}.nxc\\nxc.exe" /d /v:off /c echo CANARY nxc.exe smb ${target} -u U -p P --shares ¦ Proc: ${ROOT}.nxc\\nxc.exe`,
    path: `${ROOT}.nxc\\nxc.exe`,
    sources: ["Velociraptor"],
    ...over,
  });

describe("correlateEvents — same hash, different files (#1476)", () => {
  it("keeps four renamed copies of one binary as four rows", () => {
    const out = correlateEvents([
      rename("6e1", "netextender.exe", `${ROOT}sonic\\`),
      rename("6e2", "AnyDesk.exe", `${ROOT}host\\ProgramData\\`),
      rename("6e3", "nxc.exe", `${ROOT}.nxc\\`),
      rename("6e4", "python.exe", `${ROOT}host\\`),
    ]);
    expect(out).toHaveLength(4);
    expect(new Set(out.map((e) => e.path))).toEqual(
      new Set([
        `${ROOT}sonic\\netextender.exe`,
        `${ROOT}host\\ProgramData\\AnyDesk.exe`,
        `${ROOT}.nxc\\nxc.exe`,
        `${ROOT}host\\python.exe`,
      ]),
    );
  });

  it("still merges a hash-only row (no path) into the one file row that carries that hash", () => {
    const yara = ev({
      id: "y1",
      timestamp: "2026-09-20T19:29:08Z",
      description: `THOR Alert [Filescan]: renamed command processor — sha256 ${SHA}`,
      sources: ["THOR"],
    });
    const out = correlateEvents([rename("6e1", "netextender.exe", `${ROOT}sonic\\`), yara]);
    expect(out).toHaveLength(1);
    expect(out[0].sources).toEqual(expect.arrayContaining(["Velociraptor", "THOR"]));
  });

  it("leaves a hash-only row on its own when several paths claim the hash (no bridging)", () => {
    const yara = ev({
      id: "y1",
      timestamp: "2026-09-20T19:29:08Z",
      description: `THOR Alert [Filescan]: renamed command processor — sha256 ${SHA}`,
      sources: ["THOR"],
    });
    const out = correlateEvents([
      rename("6e1", "netextender.exe", `${ROOT}sonic\\`),
      rename("6e2", "AnyDesk.exe", `${ROOT}host\\ProgramData\\`),
      yara,
    ]);
    // Two files must not become one through the pathless row; the row that could belong to either
    // stays separate rather than picking one.
    expect(out).toHaveLength(3);
  });

  it("a multi-hash pathless row does not bridge two files that share only one hash each", () => {
    const MD5 = "c8b5d63042bc4bbb7f5c0f9e15b61f16";
    const a = ev({
      id: "a",
      path: `${ROOT}a.exe`,
      sha256: SHA,
      sources: ["Velociraptor"],
      description: "file a",
    });
    const b = ev({
      id: "b",
      path: `${ROOT}b.exe`,
      md5: MD5,
      sources: ["Velociraptor"],
      description: "file b",
    });
    const bridge = ev({ id: "x", sha256: SHA, md5: MD5, sources: ["THOR"], description: "hit" });
    const out = correlateEvents([a, b, bridge]);
    // The two files stay two rows whichever of them the hit joins.
    expect(out.filter((e) => e.path === `${ROOT}a.exe`)).toHaveLength(1);
    expect(out.filter((e) => e.path === `${ROOT}b.exe`)).toHaveLength(1);
  });
});

describe("correlateEvents — same path, different executions (#1476)", () => {
  const T = ["2026-09-20T19:29:14.418Z", "2026-09-20T19:29:15.482Z", "2026-09-20T19:29:16.506Z"];

  it("keeps three executions of one binary with three command lines as three rows", () => {
    const out = correlateEvents([
      exec("1e12", T[0], "DC01"),
      exec("1e13", T[1], "FILE01"),
      exec("1e14", T[2], "APP01"),
    ]);
    expect(out).toHaveLength(3);
  });

  it("unites each text-only detection with the pid-bearing row of the SAME command, never across commands", () => {
    // Chainsaw parsed the same three Sysmon records with pids; Hayabusa's rows came through text-only.
    const chainsaw = (id: string, t: string, target: string, pid: number) =>
      ev({
        id,
        timestamp: t,
        description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Potential Defense Evasion Via Binary Rename - Sysmon Process create (EID 1) - Image=${ROOT}.nxc\\nxc.exe - CommandLine="${ROOT}.nxc\\nxc.exe" /d /v:off /c echo CANARY nxc.exe smb ${target} -u U -p P --shares`,
        path: `${ROOT}.nxc\\nxc.exe`,
        pid,
        processName: "nxc.exe",
        parentName: "powershell.exe",
        sha256: SHA,
        sources: ["Chainsaw"],
        severity: "Medium",
      });
    const rows = [
      exec("1e12", T[0], "DC01"),
      chainsaw("2e54", T[0], "DC01", 416),
      exec("1e13", T[1], "FILE01"),
      chainsaw("2e55", T[1], "FILE01", 11404),
      exec("1e14", T[2], "APP01"),
      chainsaw("2e56", T[2], "APP01", 3568),
    ];
    // Order must not matter (DSU + pairwise chains are order-sensitive when done wrong).
    for (const input of [rows, [...rows].reverse(), [rows[1], rows[3], rows[5], rows[0], rows[2], rows[4]]]) {
      const out = correlateEvents(input);
      expect(out).toHaveLength(3);
      for (const target of ["DC01", "FILE01", "APP01"]) {
        const row = out.filter((e) => e.description.includes(`smb ${target}`));
        expect(row).toHaveLength(1);
        expect(row[0].sources).toEqual(expect.arrayContaining(["Velociraptor", "Chainsaw"]));
        expect(row[0].severity).toBe("High");
      }
    }
  });

  it("does not let a file-write row on the path bridge two executions", () => {
    const write = ev({
      id: "2e22",
      timestamp: "2026-09-20T19:29:14.394Z",
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Windows Shell/Scripting Application File Write to Suspicious Folder - Sysmon File created (EID 11) - TargetFilename=${ROOT}.nxc\\nxc.exe`,
      path: `${ROOT}.nxc\\nxc.exe`,
      sources: ["Chainsaw"],
    });
    const out = correlateEvents([write, exec("1e12", T[0], "DC01"), exec("1e13", T[1], "FILE01")]);
    // The write may join one execution or stand alone; the two executions must stay two rows.
    const ids = new Set(out.map((e) => e.id));
    expect(out.length).toBeGreaterThanOrEqual(2);
    expect(ids.has("1e12") || ids.has("2e22")).toBe(true); // the DC01 launch, or the write it merged into
    expect(ids.has("1e13")).toBe(true);
    expect(
      ids.has("1e12") && ids.has("1e13")
        ? true
        : out.some((e) => e.sources?.includes("Chainsaw") && e.sources.includes("Velociraptor")),
    ).toBe(true);
  });

  it("a file-write that merges with a launch keeps the launch's command line as the shown text", () => {
    const write = ev({
      id: "w",
      timestamp: "2026-09-20T19:29:14.394Z",
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Windows Shell/Scripting Application File Write to Suspicious Folder - Sysmon File created (EID 11) - Image=C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - TargetFilename=${ROOT}.nxc\\nxc.exe`,
      path: `${ROOT}.nxc\\nxc.exe`,
      sources: ["Chainsaw"],
    });
    const out = correlateEvents([write, exec("1e12", T[0], "DC01")]);
    expect(out).toHaveLength(1);
    expect(out[0].description).toContain("smb DC01");
  });

  it("still merges a file-write detection with the one execution of that path in the window", () => {
    const write = ev({
      id: "w",
      timestamp: "2026-09-20T19:29:14.394Z",
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: File Write to Suspicious Folder - TargetFilename=${ROOT}.nxc\\nxc.exe`,
      path: `${ROOT}.nxc\\nxc.exe`,
      sources: ["Chainsaw"],
    });
    const out = correlateEvents([write, exec("1e12", T[0], "DC01")]);
    expect(out).toHaveLength(1);
    expect(out[0].sources).toEqual(expect.arrayContaining(["Velociraptor", "Chainsaw"]));
  });

  it("keeps the cross-tool same-command different-pid merge (#68)", () => {
    const sysmon = ev({
      id: "sm",
      description:
        "Sysmon Process create (EID 1) - powershell.exe - CommandLine=powershell.exe -nop -w hidden -enc SQBFAFgA",
      pid: 5292,
      processName: "powershell.exe",
      parentName: "explorer.exe",
      sources: ["Sysmon"],
      timestamp: "2024-05-14T13:29:39.6Z",
    });
    const edr = ev({
      id: "ec",
      description: "Process created powershell.exe (encoded) under explorer.exe",
      commandLine:
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden -enc SQBFAFgA",
      pid: 8123,
      processName: "powershell.exe",
      parentName: "explorer.exe",
      sources: ["EDR (ECAR)"],
      timestamp: "2024-05-14T13:29:40.2Z",
    });
    expect(correlateEvents([sysmon, edr])).toHaveLength(1);
  });

  it("treats a head-truncated command line (…) as the same command as its full form", () => {
    const full = exec("1e12", T[0], "DC01");
    const truncated = ev({
      id: "2e54",
      timestamp: T[0],
      description: `[Windows.EventLogs.Chainsaw] Chainsaw/Sigma: Binary Rename - Sysmon Process create (EID 1) - Image=${ROOT}.nxc\\nxc.exe - CommandLine=… /d /v:off /c echo CANARY nxc.exe smb DC01 -u U -p P --shares`,
      path: `${ROOT}.nxc\\nxc.exe`,
      pid: 416,
      sources: ["Chainsaw"],
      severity: "Medium",
    });
    expect(correlateEvents([full, truncated])).toHaveLength(1);
  });
});
