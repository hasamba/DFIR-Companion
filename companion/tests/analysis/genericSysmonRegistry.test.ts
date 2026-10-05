// #1958 — the registry twin of #1530. Hayabusa and Windows.Sigma.Base both ship a generic rule,
// "Reg Key Value Set (Sysmon Alert)", that fires on every Sysmon registry write the config tags,
// at medium. Thousands of routine writes (CompatTelRunner's inventory, svchost, OneDrive) landed in
// the forensic timeline. Every clause that keeps the grade is a clause an intruder would want past.
import { describe, it, expect } from "vitest";
import {
  downgradeGenericSysmonRegistry,
  genericSysmonRegistryNote,
  isKeptRegistryKey,
  readRegistryKey,
} from "../../src/analysis/genericSysmonRegistry.js";
import { isSetAsideRow } from "../../src/analysis/setAsideRows.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ORDINARY_KEY =
  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Foo";
const RUN_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";

function hayabusaRow(p: Partial<ForensicEvent> & { key?: string; title?: string } = {}): ForensicEvent {
  const { key = ORDINARY_KEY, title = "Reg Key Value Set (Sysmon Alert)", ...rest } = p;
  return {
    id: "h1",
    timestamp: "2026-08-30T15:02:40.005Z",
    description: `Hayabusa: ${title} (EID 13 Sysmon) — EventType=SetValue TgtObj=${key} Details=DWORD (0x00000001) Proc=C:\\Windows\\System32\\CompatTelRunner.exe @ HOST-01`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Hayabusa"],
    ...rest,
  };
}

function veloRow(p: Partial<ForensicEvent> & { key?: string; title?: string } = {}): ForensicEvent {
  const { key = ORDINARY_KEY, title = "Reg Key Value Set (Sysmon Alert)", ...rest } = p;
  return {
    id: "v1",
    timestamp: "2026-08-30T15:02:40.005Z",
    description: `Velociraptor [Windows.Sigma.Base] Sigma: ${title} - Sysmon Registry value set (EID 13) - Image=C:\\Windows\\System32\\CompatTelRunner.exe - TargetObject=${key} @ HOST-01`,
    severity: "Medium",
    mitreTechniques: ["T1112"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Velociraptor"],
    canonical: {
      schemaVersion: "1.0.0",
      event: { category: "registry", type: "change" },
      registry: { key, valueData: "DWORD (0x00000001)" },
    },
    ...rest,
  } as ForensicEvent;
}

describe("genericSysmonRegistryNote — the rows it lowers", () => {
  it("lowers a Hayabusa row on an ordinary key", () => {
    expect(genericSysmonRegistryNote(hayabusaRow())).toContain("generic Sysmon alert");
  });

  it("lowers a Windows.Sigma.Base row on an ordinary key, carrying the rule's own T1112", () => {
    expect(genericSysmonRegistryNote(veloRow())).toContain("generic Sysmon alert");
  });

  it("lowers the Create/Delete twin", () => {
    expect(
      genericSysmonRegistryNote(hayabusaRow({ title: "Reg Key Create/Delete (Sysmon Alert)" })),
    ).not.toBe("");
  });

  it("lowers a Low row too", () => {
    expect(genericSysmonRegistryNote(hayabusaRow({ severity: "Low" }))).not.toBe("");
  });
});

describe("genericSysmonRegistryNote — the keep-list never lowers persistence or defence evasion", () => {
  it.each([
    ["Run", RUN_KEY],
    ["RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\x"],
    ["Wow6432Node Run", "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\x"],
    [
      "IFEO",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
    ],
    [
      "SilentProcessExit",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe\\MonitorProcess",
    ],
    ["Winlogon", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"],
    ["AppInit_DLLs", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"],
    ["Lsa", "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages"],
    ["Defender policy", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"],
    ["Defender exclusion", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp"],
    ["Defender service Start", "HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\Start"],
    ["Firewall service Start", "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\mpssvc\\Start"],
    ["service ImagePath", "HKLM\\System\\CurrentControlSet\\Services\\evilsvc\\ImagePath"],
    ["ServiceDll", "HKLM\\System\\CurrentControlSet\\Services\\evilsvc\\Parameters\\ServiceDll"],
    ["Terminal Server", "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections"],
    ["logon script", "HKCU\\Environment\\UserInitMprLogonScript"],
    ["Office add-in", "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Addins\\x"],
    ["COM hijack", "HKCU\\Software\\Classes\\CLSID\\{0000-1111}\\InprocServer32\\(Default)"],
    ["a trailing render artefact", "HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\Start!s!"],
  ])("keeps %s", (_family, key) => {
    expect(isKeptRegistryKey(key)).toBe(true);
    expect(genericSysmonRegistryNote(hayabusaRow({ key }))).toBe("");
    expect(genericSysmonRegistryNote(veloRow({ key }))).toBe("");
  });

  it.each([
    ["an ordinary service Start", "HKLM\\System\\CurrentControlSet\\Services\\bam\\Start"],
    ["the application inventory", "\\REGISTRY\\A\\{1}\\Root\\InventoryApplicationFile\\x"],
    ["Explorer state", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"],
  ])("does not keep %s", (_label, key) => {
    expect(isKeptRegistryKey(key)).toBe(false);
  });
});

describe("genericSysmonRegistryNote — every other clause that keeps the grade", () => {
  it.each<[string, ForensicEvent]>([
    ["a specific Sigma title on the same key", veloRow({ title: "Autorun Keys Modification" })],
    [
      "a Defender-tamper rule",
      hayabusaRow({ title: "Disable Windows Defender Functionalities Via Registry" }),
    ],
    ["a High row", hayabusaRow({ severity: "High" })],
    ["a Critical row", veloRow({ severity: "Critical" })],
    ["an Info row (nothing to lower)", hayabusaRow({ severity: "Info" })],
    ["an analyst-promoted row", hayabusaRow({ promotedAt: "2026-09-01T00:00:00Z" })],
    ["a row with an origin", hayabusaRow({ origin: "lab" })],
    ["a manual event", hayabusaRow({ id: "manual-abc" })],
    ["a row naming another technique", veloRow({ mitreTechniques: ["T1112", "T1547.001"] })],
    ["a two-parser merge", hayabusaRow({ sources: ["Hayabusa", "Chainsaw"] })],
    [
      "the title in the subject, not at the start",
      hayabusaRow({
        description: `Hayabusa: Suspicious Thing (EID 13 Sysmon) — Note=Reg Key Value Set (Sysmon Alert) TgtObj=${ORDINARY_KEY} Details=x @ H`,
      }),
    ],
  ])("keeps %s", (_label, row) => {
    expect(genericSysmonRegistryNote(row)).toBe("");
  });
});

describe("readRegistryKey — fail closed when the key is missing or cut", () => {
  it("reads the full key from the canonical registry block", () => {
    expect(readRegistryKey(veloRow())).toBe(ORDINARY_KEY);
  });

  it("reads a Hayabusa TgtObj token up to the next field", () => {
    expect(readRegistryKey(hayabusaRow())).toBe(ORDINARY_KEY);
  });

  it("reads a Sysmon-rendered message line", () => {
    const row = hayabusaRow({
      description:
        "Velociraptor Sigma: Reg Key Value Set (Sysmon Alert) - Sysmon Registry value set (EID 13)",
      message: `Registry value set:\r\nRuleName: -\r\nEventType: SetValue\r\nTargetObject: ${ORDINARY_KEY}\r\nDetails: DWORD (0x00000001)\r\nUser: SYSTEM`,
    });
    expect(readRegistryKey(row)).toBe(ORDINARY_KEY);
  });

  it("treats a Hayabusa token at the 120-character cap as cut, and keeps the grade", () => {
    const cut = `\\REGISTRY\\A\\{01234567-89ab-cdef-0123-456789abcdef}\\Root\\InventoryApplicationFile\\sysmon64.exe|be53290cb8665cd\\LowerCaseL`;
    expect(cut).toHaveLength(120);
    const row = hayabusaRow({ key: cut });
    expect(readRegistryKey(row)).toBe("");
    expect(genericSysmonRegistryNote(row)).toBe("");
  });

  it("treats a key clipped with an ellipsis as cut", () => {
    expect(readRegistryKey(veloRow({ key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVer…" }))).toBe("");
  });

  it("treats a description that ends inside the key as cut", () => {
    const row = hayabusaRow({
      description: `Hayabusa: Reg Key Value Set (Sysmon Alert) (EID 13 Sysmon) — TgtObj=HKLM\\SOFTWARE\\Micro`,
    });
    expect(readRegistryKey(row)).toBe("");
  });

  it("keeps the grade when the row names no key at all", () => {
    const row = hayabusaRow({
      description: "Hayabusa: Reg Key Value Set (Sysmon Alert) (EID 13 Sysmon) @ HOST-01",
    });
    expect(readRegistryKey(row)).toBe("");
    expect(genericSysmonRegistryNote(row)).toBe("");
  });
});

describe("downgradeGenericSysmonRegistry", () => {
  it("lowers only the qualifying rows, to Info, with the reason appended", () => {
    const rows = [hayabusaRow({ id: "a" }), hayabusaRow({ id: "b", key: RUN_KEY }), veloRow({ id: "c" })];
    const { events, downgraded } = downgradeGenericSysmonRegistry(rows);
    expect(downgraded).toEqual(["a", "c"]);
    expect(events.map((e) => e.severity)).toEqual(["Info", "Medium", "Info"]);
    expect(events[0].description).toMatch(
      /\[generic Sysmon alert — no specific rule matched this registry write\]$/,
    );
    expect(isSetAsideRow(events[0])).toBe(true);
  });

  it("is idempotent", () => {
    const once = downgradeGenericSysmonRegistry([hayabusaRow()]);
    const twice = downgradeGenericSysmonRegistry(once.events);
    expect(twice.downgraded).toEqual([]);
    expect(twice.events[0].description).toBe(once.events[0].description);
  });

  it("does not mutate its input", () => {
    const rows = [hayabusaRow()];
    const snapshot = JSON.stringify(rows);
    downgradeGenericSysmonRegistry(rows);
    expect(JSON.stringify(rows)).toBe(snapshot);
  });

  it("clips the base, never the note, on a 1,200-character description", () => {
    const row = veloRow();
    const long = { ...row, description: `${row.description} ${"x".repeat(1400)}` };
    const { events, downgraded } = downgradeGenericSysmonRegistry([long]);
    expect(downgraded).toHaveLength(1);
    expect(events[0].description.length).toBeLessThanOrEqual(1200);
    expect(events[0].description.endsWith("this registry write]")).toBe(true);
    expect(isSetAsideRow(events[0])).toBe(true);
  });
});

// The importers' real output: the pass must read the row shape each one actually produces.
describe("the real importers' rows, end to end", () => {
  it("lowers a parsed Hayabusa row on an ordinary key and keeps the Run-key row", () => {
    const rec = (key: string, RecordID: number) => ({
      Timestamp: "2026-08-30 15:02:40.005 +00:00",
      Computer: "HOST-01",
      Channel: "Sysmon",
      EventID: 13,
      Level: "med",
      RuleTitle: "Reg Key Value Set (Sysmon Alert)",
      RecordID,
      Details: {
        EventType: "SetValue",
        TgtObj: key,
        Details: "DWORD (0x00000001)",
        Proc: "C:\\Windows\\System32\\svchost.exe",
      },
    });
    const parsed = parseHayabusaTimeline(JSON.stringify([rec(ORDINARY_KEY, 1), rec(RUN_KEY, 2)]));
    const rows = parsed.events.map((e, i) => ({
      ...e,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));
    expect(rows.map((e) => e.severity)).toEqual(["Medium", "Medium"]);
    const { events } = downgradeGenericSysmonRegistry(rows);
    const byKey = (k: string) => events.find((e) => e.description.includes(k));
    expect(byKey("Compatibility Assistant")?.severity).toBe("Info");
    expect(byKey("CurrentVersion\\Run\\")?.severity).toBe("Medium");
  });

  it("lowers a parsed Windows.Sigma.Base row and keeps the Run-key row", () => {
    const row = (key: string, RecordID: number) => ({
      Timestamp: "2026-08-30T15:02:40.005Z",
      Computer: "HOST-01",
      Channel: "Microsoft-Windows-Sysmon/Operational",
      EID: 13,
      Level: "medium",
      Title: "Reg Key Value Set (Sysmon Alert)",
      Tags: ["attack.defense-evasion", "attack.t1112"],
      RecordID,
      _Event: {
        System: {
          Provider: { Name: "Microsoft-Windows-Sysmon" },
          EventID: { Value: 13 },
          Channel: "Microsoft-Windows-Sysmon/Operational",
          Computer: "HOST-01",
        },
        EventData: {
          EventType: "SetValue",
          UtcTime: "2026-08-30 15:02:40.005",
          Image: "C:\\Windows\\System32\\svchost.exe",
          TargetObject: key,
          Details: "DWORD (0x00000001)",
        },
      },
      _Source: "Windows.Sigma.Base",
    });
    const parsed = parseVelociraptorJson(
      JSON.stringify({ "Windows.Sigma.Base": [row(ORDINARY_KEY, 1), row(RUN_KEY, 2)] }),
      { aggregate: false },
    );
    const rows = parsed.events.map((e, i) => ({
      ...e,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));
    expect(rows.every((e) => e.severity === "Medium" && e.mitreTechniques.includes("T1112"))).toBe(true);
    const { events } = downgradeGenericSysmonRegistry(rows);
    const byKey = (k: string) => events.find((e) => e.description.includes(k));
    expect(byKey("Compatibility Assistant")?.severity).toBe("Info");
    expect(byKey("CurrentVersion\\Run\\")?.severity).toBe("Medium");
  });
});
