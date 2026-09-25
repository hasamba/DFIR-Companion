import { describe, it, expect } from "vitest";
import {
  noteSessionCommands,
  pruneSessionCommands,
  SESSION_GAP_MS,
} from "../../src/analysis/ai/sessionCommandNotes.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// Fixture: the five quiet steps of the INC-2026-005 ransomware simulation (#1594), sanitized. Each has
// a raw process (or file-create) row in the forensic timeline; the synthesis named only the loud
// steps (credential dumping, log clearing) around them.
const HOST = "ws01.example.com";
const at = (hms: string): string => `2026-05-11T${hms}.000Z`;

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: at("09:00:00"),
    description: `row ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...over,
  };
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
    firstSeen: at("09:00:00"),
    lastUpdated: at("09:00:00"),
    status: "open",
    ...over,
  };
}

const quiet: ForensicEvent[] = [
  ev("e-netsh", {
    timestamp: at("08:58:09"),
    severity: "Medium",
    sources: ["Chainsaw"],
    processName: "netsh.exe",
    commandLine: 'netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes',
    description: "Chainsaw: Firewall rule group enabled",
  }),
  ev("e-subst", {
    timestamp: at("08:58:31"),
    processName: "subst.exe",
    commandLine: "subst E: C:\\e",
    description: "Hayabusa: Proc Exec (EID 1 Sysmon)",
  }),
  ev("e-startcmd", {
    timestamp: at("08:58:31"),
    severity: "High",
    processName: "powershell.exe",
    path: "c:\\e\\!start.cmd",
    description: "Hayabusa: File Created (EID 11 Sysmon) — TgtFile=C:\\e\\!start.cmd",
  }),
  ev("e-netview", {
    timestamp: at("09:04:22"),
    sources: ["Chainsaw"],
    processName: "net.exe",
    commandLine: "net view /all",
  }),
  ev("e-tasklist", {
    timestamp: at("09:04:39"),
    processName: "tasklist.exe",
    commandLine: "tasklist /v",
    description: "Hayabusa: Suspicious Tasklist Discovery Command (EID 1 Sysmon)",
  }),
];

const loud: ForensicEvent[] = [
  ev("e-mimi", {
    timestamp: at("09:00:00"),
    severity: "Critical",
    commandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
  }),
  ev("e-clear", {
    timestamp: at("09:10:00"),
    severity: "High",
    description: "Security log cleared (EID 1102)",
  }),
];

const mimikatz = finding("f-cred", {
  severity: "Critical",
  title: "Credential dumping with Mimikatz",
  description: "mimikatz privilege::debug sekurlsa::logonpasswords ran on WS01.",
  relatedEventIds: ["e-mimi"],
});
const logClear = finding("f-clear", {
  title: "Security event log cleared",
  description: "The Security log was cleared (1102).",
  relatedEventIds: ["e-clear"],
});

function caseState(events: ForensicEvent[], findings: Finding[]): InvestigationState {
  return { ...emptyState("INC-TEST"), forensicTimeline: events, findings };
}

function run(events: ForensicEvent[], findings: Finding[], hostOf?: (raw: string) => string) {
  const state = caseState(events, findings);
  return noteSessionCommands(state, { scopedEvents: events, ...(hostOf ? { hostOf } : {}) });
}

const notedIds = (s: InvestigationState): string[] =>
  s.findings.flatMap((f) => (f.sessionCommands ?? []).map((c) => c.eventId)).sort();

describe("noteSessionCommands (#1594)", () => {
  it("notes each of the five quiet INC-2026-005 commands on the closest finding", () => {
    const out = run([...quiet, ...loud], [mimikatz, logClear]);
    expect(notedIds(out)).toEqual(["e-netsh", "e-netview", "e-startcmd", "e-subst", "e-tasklist"]);
    const cred = out.findings.find((f) => f.id === "f-cred")!;
    expect(cred.sessionCommands!.map((c) => c.text)).toEqual([
      'netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes',
      "subst E: C:\\e",
      "powershell.exe wrote c:\\e\\!start.cmd",
      "net view /all",
      "tasklist /v",
    ]);
    expect(cred.sessionCommands![2].kind).toBe("file-write");
    // The note is not evidence: citations and the description are untouched.
    expect(cred.relatedEventIds).toEqual(["e-mimi"]);
    expect(cred.description).toBe(mimikatz.description);
  });

  it("attaches a command to the finding nearest in time", () => {
    const late = ev("e-whoami", { timestamp: at("09:09:00"), commandLine: "whoami /all" });
    const out = run([...loud, late], [mimikatz, logClear]);
    expect(out.findings.find((f) => f.id === "f-clear")!.sessionCommands!.map((c) => c.eventId)).toEqual([
      "e-whoami",
    ]);
    expect(out.findings.find((f) => f.id === "f-cred")!.sessionCommands).toBeUndefined();
  });

  it("does not note a command a finding already names (full text, core, or a cmd /c wrapper)", () => {
    const named = finding("f-disc", {
      severity: "Medium",
      title: "Discovery",
      description:
        "The actor ran `net view /all`, then TASKLIST.EXE /v, and enabled Network Discovery with netsh advfirewall firewall set rule. They mapped a drive with subst E: C:\\e and dropped !start.cmd.",
      relatedEventIds: ["e-mimi"],
    });
    const wrapped = ev("e-wrapped", { timestamp: at("09:01:00"), commandLine: "cmd.exe /c net view /all" });
    const out = run([...quiet, ...loud, wrapped], [mimikatz, logClear, named]);
    expect(notedIds(out)).toEqual([]);
  });

  it("counts a finding that cites the row and names its program", () => {
    const f = finding("f-t", {
      title: "Process discovery",
      description: "tasklist enumerated running processes.",
      relatedEventIds: ["e-mimi", "e-tasklist"],
    });
    const out = run([...quiet, ...loud], [mimikatz, f]);
    expect(notedIds(out)).not.toContain("e-tasklist");
  });

  it("ignores Info rows, rows on another host, undated rows, and rows with no command", () => {
    const extra = [
      ev("e-info", { severity: "Info", commandLine: "ipconfig /all", timestamp: at("09:01:00") }),
      ev("e-other", {
        asset: "srv02.example.com",
        commandLine: "net group /domain",
        timestamp: at("09:01:00"),
      }),
      ev("e-undated", { timestamp: "", commandLine: "systeminfo" }),
      ev("e-plain", { timestamp: at("09:01:00"), description: "a detection with no command line" }),
    ];
    expect(notedIds(run([...loud, ...extra], [mimikatz]))).toEqual([]);
  });

  it("keeps the session tight: nothing between two incidents hours apart, nothing past the pad", () => {
    const afternoon = ev("e-pm", {
      timestamp: at("15:00:00"),
      severity: "High",
      commandLine: "vssadmin delete shadows /all",
    });
    const pmFinding = finding("f-pm", {
      title: "Shadow copies deleted",
      description: "vssadmin deleted every shadow copy.",
      relatedEventIds: ["e-pm"],
    });
    const between = ev("e-noon", { timestamp: at("12:00:00"), commandLine: "net user admin /add" });
    const tooEarly = ev("e-early", { timestamp: at("08:40:00"), commandLine: "hostname" });
    expect(15 * 3600_000 - 9 * 3600_000).toBeGreaterThan(SESSION_GAP_MS);
    const out = run([...loud, afternoon, between, tooEarly], [mimikatz, pmFinding]);
    expect(notedIds(out)).toEqual([]);
  });

  it("does not anchor on a dismissed, build-baseline or Low finding", () => {
    const events = [...quiet, ...loud];
    const out = run(events, [
      { ...mimikatz, status: "dismissed" },
      { ...logClear, buildBaseline: true },
      finding("f-low", { severity: "Low", relatedEventIds: ["e-mimi"] }),
    ]);
    expect(notedIds(out)).toEqual([]);
  });

  it("reads only the rows it is given — a row outside scopedEvents is never noted", () => {
    const state = caseState([...quiet, ...loud], [mimikatz]);
    const scoped = [...loud, quiet[3]];
    const out = noteSessionCommands(state, { scopedEvents: scoped });
    expect(notedIds(out)).toEqual(["e-netview"]);
  });

  it("joins host spellings through the alias resolver", () => {
    const short = quiet.map((e) => ({ ...e, asset: "WS01" }));
    const hostOf = (raw: string) => (raw.toLowerCase().startsWith("ws01") ? HOST : raw.toLowerCase());
    expect(notedIds(run([...short, ...loud], [mimikatz], hostOf))).toHaveLength(5);
  });

  it("recognises a file write by action and by a typed file envelope", () => {
    const byAction = ev("e-w1", {
      timestamp: at("09:01:00"),
      action: "write",
      path: "c:\\users\\public\\run.ps1",
      processName: "cmd.exe",
    });
    const doc = ev("e-w2", {
      timestamp: at("09:01:00"),
      action: "write",
      path: "c:\\users\\public\\notes.txt",
    });
    const out = run([...loud, byAction, doc], [mimikatz]);
    expect(notedIds(out)).toEqual(["e-w1"]);
  });

  it("lists one entry per distinct command on a host, earliest first", () => {
    const again = ev("e-netview-2", { timestamp: at("09:05:00"), commandLine: "NET  view /ALL" });
    const out = run([...quiet, ...loud, again], [mimikatz]);
    expect(notedIds(out)).not.toContain("e-netview-2");
  });

  it("is idempotent and clears a stale note once a finding names the command", () => {
    const once = run([...quiet, ...loud], [mimikatz, logClear]);
    const twice = noteSessionCommands(once, { scopedEvents: [...quiet, ...loud] });
    expect(twice.findings).toEqual(once.findings);
    const renamed = twice.findings.map((f) =>
      f.id === "f-clear"
        ? {
            ...f,
            description: `${f.description} Before it: netsh advfirewall firewall, subst E: C:\\e, !start.cmd, net view /all, tasklist /v.`,
          }
        : f,
    );
    const after = noteSessionCommands({ ...twice, findings: renamed }, { scopedEvents: [...quiet, ...loud] });
    expect(after.findings.every((f) => f.sessionCommands === undefined)).toBe(true);
  });

  it("flattens a multi-line command and caps its length", () => {
    const long = ev("e-long", {
      timestamp: at("09:01:00"),
      commandLine: `powershell -c "a\nb" ${"x".repeat(400)}`,
    });
    const out = run([...loud, long], [mimikatz]);
    const text = out.findings[0].sessionCommands![0].text;
    expect(text).not.toMatch(/\n/);
    expect(text.length).toBeLessThanOrEqual(300);
  });
});

describe("pruneSessionCommands (#1594)", () => {
  it("drops entries whose row is outside the projected timeline", () => {
    const noted = run([...quiet, ...loud], [mimikatz]);
    const visible = { ...noted, forensicTimeline: noted.forensicTimeline.filter((e) => e.id !== "e-subst") };
    const pruned = pruneSessionCommands(visible);
    expect(notedIds(pruned)).toEqual(["e-netsh", "e-netview", "e-startcmd", "e-tasklist"]);
    const none = pruneSessionCommands({ ...noted, forensicTimeline: loud });
    expect(none.findings[0].sessionCommands).toBeUndefined();
  });

  it("returns the same state when no finding carries a note", () => {
    const s = caseState(loud, [mimikatz]);
    expect(pruneSessionCommands(s)).toBe(s);
  });
});
