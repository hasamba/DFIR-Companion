import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { huntFieldsOf, huntItemKey } from "../../src/analysis/huntArtifactFields.js";
import { EMPTY_INVENTORY, recordObservations } from "../../src/analysis/huntInventory.js";
import { itemVerdict } from "../../src/analysis/huntApprovalMatch.js";
import { EMPTY_BASELINE, type BaselineMark } from "../../src/analysis/clientProfile.js";
import { deltaSchema, stripAiExtractedFrom } from "../../src/analysis/responseSchema.js";
import { upsertForensicEvents } from "../../src/analysis/stateMerge.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// StartupItems and scheduled tasks form autorun hunt items keyed on the program they run, or on the
// script / DLL a script host or built-in tool runs (#2748). Column names follow the repo fixtures
// (Windows.Sys.StartupItems: Name/OSPath/Details/Enabled; Windows.System.TaskScheduler/Analysis:
// TaskName/Command/Arguments/UserId/RunLevel/OSPath). All values are synthetic.
const rows = (list: object[]): ForensicEvent[] =>
  parseVelociraptorJson(JSON.stringify(list), { aggregate: true }).events.map((e) => ({
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...e,
  }));

const startup = (host: string, extra: Record<string, unknown> = {}) => ({
  _Source: "Windows.Sys.StartupItems",
  Fqdn: host,
  Name: "Updater",
  OSPath: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
  Details: '"C:\\Program Files\\Upd\\upd.exe" /bg',
  Enabled: "enable",
  ...extra,
});

const task = (host: string, name: string, command: string, args = "") => ({
  _Source: "Windows.System.TaskScheduler/Analysis",
  Fqdn: host,
  TaskName: `\\${name}`,
  Mtime: "2026-06-03T08:41:08Z",
  Command: command,
  Arguments: args,
  UserId: "S-1-5-18",
  RunLevel: "LeastPrivilege",
  OSPath: `C:\\Windows\\System32\\Tasks\\${name}`,
});

const keys = (ev: ForensicEvent[]): string[] => ev.map((e) => huntItemKey(huntFieldsOf(e)!));

const inventoryOf = (ev: ForensicEvent[]) =>
  recordObservations(
    EMPTY_INVENTORY,
    ev.map((e) => ({
      fields: huntFieldsOf(e)!,
      host: { key: `srv/${e.asset}`, basis: "client" as const, hostname: e.asset! },
      at: e.timestamp,
    })),
    "now",
  );

const notAllowed = (p: Partial<BaselineMark>): BaselineMark => ({
  id: "na",
  verdict: "not-allowed",
  family: "autorun",
  program: "",
  pathPattern: "",
  sha256: [],
  note: "",
  source: "client email",
  recordedBy: "admin",
  recordedAt: "2026-01-01T00:00:00Z",
  ...p,
});

describe("StartupItems form an autorun item keyed on the program they launch (#2748)", () => {
  it("a quoted Run value with spaces gives one item across hosts and the full file IOC", () => {
    const r = parseVelociraptorJson(JSON.stringify([startup("WS-01"), startup("WS-02")]), {
      aggregate: true,
    });
    const ev = rows([startup("WS-01"), startup("WS-02")]);
    expect(new Set(keys(ev))).toEqual(new Set(["autorun|upd.exe|\\program files\\upd"]));
    const files = r.iocs.filter((i) => i.type === "file").map((i) => i.value);
    expect(files).toContain("C:\\Program Files\\Upd\\upd.exe");
    expect(files).not.toContain("C:\\Program");
  });

  it("a script host Run value is keyed on the script", () => {
    const ev = rows([startup("WS-01", { Details: 'wscript "c:\\Program Files\\sysinternals\\bginfo.vbs"' })]);
    expect(keys(ev)).toEqual(["autorun|bginfo.vbs|\\program files\\sysinternals"]);
  });

  it("no clear target: the entry name keys the item", () => {
    const ev = rows([startup("WS-01", { Details: "powershell -enc SQBFAFgA" })]);
    expect(keys(ev)).toEqual(["autorun|updater|"]);
  });

  it("keeps the event's description, severity and no path (the tagger input is unchanged)", () => {
    const [e] = rows([startup("WS-01")]);
    expect(e.severity).toBe("Low");
    expect(e.path).toBeUndefined();
    expect(e.processName).toBeUndefined();
    expect(e.description).toContain("Startup [Updater]");
  });
});

describe("scheduled tasks are keyed on the program or the script they run (#2748)", () => {
  it("two hosts running the same exe from differently named tasks give ONE item", () => {
    const ev = rows([
      task("WS-01", "A_Task", "C:\\Tools\\same.exe"),
      task("WS-02", "B_Task_S-1-5-21-1", "C:\\Tools\\same.exe"),
    ]);
    expect(new Set(keys(ev))).toEqual(new Set(["autorun|same.exe|\\tools"]));
    const item = Object.values(inventoryOf(ev).items)[0];
    expect(item.entries?.map((x) => x.program).sort()).toEqual(["a_task", "b_task_s-1-5-21-1"]);
  });

  it("keeps the task file as the event path and the description unchanged", () => {
    const [e] = rows([task("WS-01", "A_Task", "C:\\Tools\\same.exe")]);
    expect(e.path).toBe("C:\\Windows\\System32\\Tasks\\A_Task");
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("Scheduled Task [\\A_Task] — C:\\Tools\\same.exe");
    const [odd] = rows([{ ...task("WS-01", "A_Task", "C:\\Tools\\same.exe"), UserId: "constructor" }]);
    expect(odd.description).toContain("(constructor, LeastPrivilege)");
  });

  it("a regsvr32 task loading a rare payload stays its own item (icedid fixture)", () => {
    const ev = rows([
      task(
        "WS-01",
        "SystemUpdate_BK24XM32",
        "regsvr32.exe",
        "/s /u /i:C:\\TrigonaSim\\payloads\\icedid_artifact.bin scrobj.dll",
      ),
      task("WS-02", "Vendor", "regsvr32.exe", "/s C:\\Program Files\\Vendor\\vendor.dll"),
    ]);
    expect(keys(ev)).toEqual([
      "autorun|icedid_artifact.bin|\\trigonasim\\payloads",
      "autorun|vendor.dll|\\program files\\vendor",
    ]);
  });

  it("a script host with no clear target keeps the old task-file key", () => {
    const ev = rows([task("WS-01", "Odd_Task", "powershell.exe", "-enc SQBFAFgA")]);
    expect(keys(ev)).toEqual(["autorun|odd_task|\\windows\\system32\\tasks"]);
  });

  it("a stored task event with no target keys exactly as before", () => {
    const stored: ForensicEvent = {
      id: "old",
      timestamp: "2026-01-01T00:00:00Z",
      description: "Velociraptor: Scheduled Task [\\A_Task] — C:\\Tools\\same.exe (SYSTEM) - @ WS-01",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      artifactName: "Windows.System.TaskScheduler/Analysis",
      path: "C:\\Windows\\System32\\Tasks\\A_Task",
      asset: "WS-01",
    };
    expect(keys([stored])).toEqual(["autorun|a_task|\\windows\\system32\\tasks"]);
  });

  it("a client Not-allowed mark saved on a task name still flags the re-keyed item", () => {
    const ev = rows([task("WS-01", "evil_task", "C:\\Tools\\same.exe")]);
    const item = Object.values(inventoryOf(ev).items)[0];
    const baseline = {
      ...EMPTY_BASELINE,
      marks: [notAllowed({ program: "evil_task", pathPattern: "\\windows\\system32\\tasks" })],
    };
    expect(itemVerdict(baseline, item, "2026-06-01T00:00:00Z").verdict).toBe("not-allowed");
    const other = { ...baseline, marks: [notAllowed({ program: "other_task" })] };
    expect(itemVerdict(other, item, "2026-06-01T00:00:00Z").verdict).toBe("unknown");
  });

  it("an Autoruns row and a task row for one image on one host: one item, still hash-covered", () => {
    const autoruns = (host: string) => ({
      _Source: "Windows.Sysinternals.Autoruns",
      Fqdn: host,
      Time: "20260105-101500",
      "Entry Location": "Task Scheduler",
      Entry: "\\A_Task",
      Enabled: "enabled",
      Signer: "",
      "Image Path": "c:\\tools\\same.exe",
      "Launch String": "C:\\Tools\\same.exe",
      "SHA-256": "e".repeat(64),
    });
    for (const order of [
      [
        autoruns("WS-01"),
        task("WS-01", "A_Task", "C:\\Tools\\same.exe"),
        task("WS-02", "A_Task", "C:\\Tools\\same.exe"),
      ],
      [
        task("WS-01", "A_Task", "C:\\Tools\\same.exe"),
        task("WS-02", "A_Task", "C:\\Tools\\same.exe"),
        autoruns("WS-01"),
      ],
    ]) {
      const inv = inventoryOf(rows(order));
      const items = Object.values(inv.items);
      expect(items).toHaveLength(1);
      expect(items[0].sha256).toEqual(["e".repeat(64)]);
      expect(items[0].unhashedHosts).toEqual(["srv/WS-02"]);
    }
  });

  it("the target survives the delta schema and the merge; a model delta loses it", () => {
    const [e] = rows([task("WS-01", "A_Task", "C:\\Tools\\same.exe")]);
    const delta = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
      forensicEvents: [{ ...e, id: "v1" }],
    });
    const timeline: ForensicEvent[] = [];
    upsertForensicEvents(timeline, delta, { sourceScreenshots: ["x"], timestamp: "t" });
    expect(keys(timeline)).toEqual(["autorun|same.exe|\\tools"]);
    expect(stripAiExtractedFrom(delta).forensicEvents?.[0].fileIdentity).toBeUndefined();
  });
});
