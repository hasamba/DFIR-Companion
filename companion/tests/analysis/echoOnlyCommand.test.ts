import { describe, it, expect } from "vitest";
import { echoOnlyEvidence, isEchoOnlyCommand } from "../../src/analysis/echoOnlyCommand.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: "x",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}
const proc = (commandLine: string, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({ commandLine, processName: "cmd.exe", ...over });

describe("isEchoOnlyCommand (#1948)", () => {
  it.each([
    "cmd /c echo canary marker",
    "cmd.exe /c echo canary marker",
    "CMD.EXE /C ECHO canary",
    '"C:\\Windows\\System32\\cmd.exe" /c echo canary',
    "C:\\Windows\\System32\\cmd.exe /q /c echo canary",
    "cmd /c echo",
    'cmd /c echo "quoted text"',
  ])("accepts %s", (cl) => {
    expect(isEchoOnlyCommand(proc(cl))).toBe(true);
  });

  it.each([
    "cmd /c echo x & whoami",
    "cmd /c echo x && whoami",
    "cmd /c echo x || whoami",
    "cmd /c echo x > C:\\Users\\Public\\f.txt",
    "cmd /c echo x | clip",
    "cmd /c echo x < in.txt",
    "cmd /c echo %X%",
    "cmd /v:on /c echo !X!",
    "cmd /c echo x ^& whoami",
    "cmd /c (echo x)",
    "cmd /c echo x\nwhoami",
    "cmd /k echo x",
    "cmd /c echoX",
    "cmd /c whoami",
    "cmd echo x",
  ])("rejects %j", (cl) => {
    expect(isEchoOnlyCommand(proc(cl))).toBe(false);
  });

  it("rejects a row with no command line", () => {
    expect(isEchoOnlyCommand(ev({ processName: "cmd.exe" }))).toBe(false);
  });

  it("accepts another first word only when the row identifies the file as cmd.exe", () => {
    // No cmd identity anywhere: the first word is adversary-chosen text.
    expect(isEchoOnlyCommand(proc("wmiexec.exe /c echo x", { processName: "wmiexec.exe" }))).toBe(false);
    expect(isEchoOnlyCommand(proc("powershell /c echo x", { processName: "powershell.exe" }))).toBe(false);
    // The image field names cmd.exe.
    expect(
      isEchoOnlyCommand(proc("svc.exe /c echo x", { processName: "C:\\Windows\\System32\\cmd.exe" })),
    ).toBe(true);
    // A trusted rename note (Velociraptor + T1036) says the file is really cmd.exe.
    const renamed = proc("wmiexec.exe /c echo x", {
      processName: "wmiexec.exe",
      description: "Process wmiexec.exe [renamed binary: wmiexec.exe is really Cmd.Exe]",
      sources: ["velociraptor"],
      mitreTechniques: ["T1036"],
    });
    expect(isEchoOnlyCommand(renamed)).toBe(true);
    // The same note typed into an untrusted row does not count.
    expect(isEchoOnlyCommand({ ...renamed, sources: ["hayabusa"] })).toBe(false);
    // A rename onto powershell.exe is not cmd.exe.
    expect(
      isEchoOnlyCommand({
        ...renamed,
        description: "Process wmiexec.exe [renamed binary: wmiexec.exe is really powershell.exe]",
      }),
    ).toBe(false);
  });
});

describe("echoOnlyEvidence (#1948)", () => {
  const echo = proc("cmd.exe /c echo canary", { id: "a" });
  const echo2 = proc("cmd /c echo canary two", { id: "b" });

  it("fires when every cited row is an echo-only process row", () => {
    const out = echoOnlyEvidence([echo, echo2]);
    expect(out).not.toBeNull();
    expect(out?.rows).toBe(2);
  });

  it("allows a file-presence trace of the same file", () => {
    const mft = ev({ id: "m", artifactName: "Windows.NTFS.MFT", path: "C:\\Windows\\System32\\cmd.exe" });
    expect(echoOnlyEvidence([echo, mft])?.rows).toBe(1);
  });

  it("keeps the rename fact of a renamed copy", () => {
    const renamed = proc("wmiexec.exe /c echo x", {
      id: "r",
      processName: "wmiexec.exe",
      description: "Process wmiexec.exe [renamed binary: wmiexec.exe is really Cmd.Exe]",
      sources: ["velociraptor"],
      mitreTechniques: ["T1036"],
    });
    const prefetch = ev({
      id: "p",
      artifactName: "Prefetch",
      path: "C:\\Windows\\Prefetch\\WMIEXEC.EXE-1A2B3C4D.pf",
    });
    expect(echoOnlyEvidence([renamed, prefetch])?.renamed).toEqual(["wmiexec.exe"]);
  });

  it("does not fire on mixed evidence", () => {
    const net = ev({ id: "n", dstIp: "203.0.113.5", port: 445 });
    const write = ev({ id: "w", processName: "cmd.exe", path: "C:\\Users\\Public\\f.txt" });
    const otherMft = ev({ id: "o", artifactName: "MFT", path: "C:\\Temp\\payload.exe" });
    const chained = proc("cmd /c echo x & whoami", { id: "c" });
    expect(echoOnlyEvidence([echo, net])).toBeNull();
    expect(echoOnlyEvidence([echo, write])).toBeNull();
    expect(echoOnlyEvidence([echo, otherMft])).toBeNull();
    expect(echoOnlyEvidence([echo, chained])).toBeNull();
  });

  it("does not fire with no echo row", () => {
    expect(echoOnlyEvidence([])).toBeNull();
    const mft = ev({ id: "m", artifactName: "MFT", path: "C:\\Windows\\System32\\cmd.exe" });
    expect(echoOnlyEvidence([mft])).toBeNull();
  });
});
