import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// #1476 — a Windows.Hayabusa.Rules hunt row carries the parsed Windows event under `_Event`
// (System + EventData + Message), not under `System` / `Event.System`. The mapper never looked
// there, so every Hayabusa detection came through text-only: no pid, no command line, no path, no
// record identity. Correlation then had only the file path to join on and folded distinct
// executions of one binary into one row. Shape mirrors the real row; values are lab-safe.

const IMAGE = "C:\\Users\\Public\\Sim\\tools\\helper.exe";
const SHA = "9695CF4566DDF878A69C3D419E0DA4EEA87B0F24261AD8E79A3A9C4A9885429C";

function hayabusaRow(label: string, pid: number, recordId: number, seconds: number): object {
  const cmd = `"${IMAGE}" /d /c echo LAB ${label}`;
  return {
    Timestamp: `2026-09-20T19:29:${String(seconds).padStart(2, "0")}.4187872Z`,
    Computer: "WS-01",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EID: "1",
    Level: "high",
    Title: "Renamed Helper Execution",
    RecordID: String(recordId),
    Details: `Cmdline: ${cmd} ¦ Proc: ${IMAGE} ¦ User: WS-01\\lab ¦ LID: 196764`,
    _Event: {
      System: {
        Provider: { Name: "Microsoft-Windows-Sysmon" },
        EventID: { Value: 1 },
        TimeCreated: { SystemTime: 1789932554.4187872 + (seconds - 14) },
        EventRecordID: recordId,
        Execution: { ProcessID: 3556, ThreadID: 4844 },
        Channel: "Microsoft-Windows-Sysmon/Operational",
        Computer: "WS-01",
      },
      EventData: {
        RuleName: "-",
        UtcTime: `2026-09-20 19:29:${String(seconds).padStart(2, "0")}.415`,
        ProcessId: pid,
        Image: IMAGE,
        OriginalFileName: "Cmd.Exe",
        CommandLine: cmd,
        User: "WS-01\\lab",
        Hashes: `MD5=C8B5D63042BC4BBB7F5C0F9E15B61F16,SHA256=${SHA}`,
        ParentProcessId: 8636,
        ParentImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      },
      Message: `Process Create:\nImage: ${IMAGE}\nCommandLine: ${cmd}`,
    },
    Enrichment: "None",
    _Source: "Windows.Sigma.Base",
    FlowId: "F.TEST.H",
    ClientId: "C.test",
    _OrgId: "root",
    Fqdn: "WS-01.example.com",
  };
}

describe("parseVelociraptorJson — Hayabusa row with the event under _Event (#1476)", () => {
  it("maps pid, command line, path, hash and record identity from _Event", () => {
    const r = parseVelociraptorJson(JSON.stringify([hayabusaRow("one", 416, 1170, 14)]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.pid).toBe(416);
    expect(e.commandLine).toContain("echo LAB one");
    expect((e.path ?? "").toLowerCase()).toBe(IMAGE.toLowerCase());
    expect(e.sha256).toBe(SHA.toLowerCase());
    expect(e.sourceRecordId).toMatch(/1170/);
    expect(e.asset).toMatch(/^WS-01/);
  });

  it("keeps the Hayabusa verdict on top of the parsed event", () => {
    const e = parseVelociraptorJson(JSON.stringify([hayabusaRow("one", 416, 1170, 14)])).events[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("Renamed Helper Execution");
    expect(e.description).toContain("echo LAB one");
  });

  it("three launches of one image with three command lines stay three events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        hayabusaRow("one", 416, 1170, 14),
        hayabusaRow("two", 11404, 1171, 15),
        hayabusaRow("three", 3568, 1172, 16),
      ]),
    );
    expect(r.events).toHaveLength(3);
    expect(new Set(r.events.map((e) => e.pid))).toEqual(new Set([416, 11404, 3568]));
  });
});

describe("BinaryRename rename note survives a long row (#1476)", () => {
  it("keeps the complete [renamed binary: …] note when name, original and path are all long", () => {
    const longName = "a".repeat(110) + ".exe";
    const longOriginal = "B".repeat(110) + ".Exe";
    const longPath = "C:\\Users\\lab\\AppData\\Local\\Temp\\" + "sub\\".repeat(30) + longName;
    const row = {
      OSPath: longPath,
      Name: longName,
      Size: "344064",
      VersionInformation: {
        CompanyName: "V".repeat(80),
        FileDescription: "x",
        OriginalFilename: longOriginal,
      },
      Hash: { MD5: "c8b5d63042bc4bbb7f5c0f9e15b61f16", SHA256: SHA.toLowerCase() },
      Mtime: "2025-12-05T02:54:10Z",
      Btime: "2026-09-20T19:29:08Z",
      Fqdn: "WS-01.example.com",
    };
    const e = parseVelociraptorJson(JSON.stringify([row]), {
      artifact: "DetectRaptor.Windows.Detection.BinaryRename",
    }).events[0];
    const m = /\[renamed binary: ([^\]]+)\]$/.exec(e.description);
    expect(m, e.description).not.toBeNull();
    expect(m![1]).toContain(longName.slice(0, 40));
    expect(m![1]).toContain("is really");
    expect(m![1]).toContain(longOriginal.slice(0, 40));
  });
});
