import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// A Sysmon file write (EID 11) and the launch of that file (EID 1) a few milliseconds later are two
// facts. correlateEvents keeps them apart only when BOTH rows say which act they record (#1557).
// Chainsaw and the Velociraptor Windows mapper say it; the native Hayabusa importer did not, so a
// Hayabusa write folded the Chainsaw launch into itself. The High write's text won the row, and the
// launch (its command line, pid and "ran as cmd.exe /c echo ...") survived only in side fields the
// model never reads. A real case lost three renamed-binary launches this way.

const HOST = "WS-01";
const FQDN = `${HOST}.example.com`;
const DROP = "C:\\Users\\Public\\Sim\\App\\Reader.exe";
const PS = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const CMD = `"${DROP}" /d /v:off /c echo LAB-CANARY `;
const WRITE_TIME = "2026-09-22T14:37:51.830322Z";
const LAUNCH_TIME = "2026-09-22T14:37:51.894584Z";
const SYSMON = "Microsoft-Windows-Sysmon/Operational";

// The shape a plain Hayabusa json timeline has: no `_Event`, no `_Source`, just the rendered Details.
const hayabusa = (eid: number, channel: string, title: string, time: string, details: string) => ({
  Timestamp: time,
  Computer: HOST,
  Channel: channel,
  EID: eid,
  Level: "high",
  Title: title,
  RecordID: 1000 + eid,
  Details: details,
});

const hayabusaWrite = hayabusa(
  11,
  SYSMON,
  "Suspicious Binaries and Scripts in Public Folder",
  WRITE_TIME,
  `Path: ${DROP} ¦ Proc: ${PS} ¦ PID: 10756 ¦ PGUID: 6FEF6725-92A4-6AB2-1501-000000000A00`,
);

const chainsawLaunch = {
  EventTime: LAUNCH_TIME,
  Detection: "Potential Defense Evasion Via Binary Rename",
  Severity: "medium",
  "Rule Group": "Sigma",
  Computer: HOST,
  Channel: SYSMON,
  EventID: 1,
  SystemData: {
    Channel: SYSMON,
    Computer: HOST,
    EventID: 1,
    EventRecordID: 1002,
    TimeCreated_attributes: { SystemTime: LAUNCH_TIME },
  },
  EventData: {
    CommandLine: CMD,
    Image: DROP,
    OriginalFileName: "Cmd.Exe",
    ParentImage: PS,
    ParentProcessId: 10756,
    ProcessGuid: "6FEF6725-92BF-6AB2-2B01-000000000A00",
    ProcessId: 1112,
    User: `${HOST}\\lab`,
    UtcTime: "2026-09-22 14:37:51.871",
  },
  Fqdn: FQDN,
};

type Parsed = { events: object[] };

function asEvents(parsed: Parsed, prefix: string, source: string): ForensicEvent[] {
  return parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e as ForensicEvent & { aggKey?: string };
    void aggKey;
    return {
      ...rest,
      id: `${prefix}e${i + 1}`,
      mitreTechniques: rest.mitreTechniques ?? [],
      relatedFindingIds: rest.relatedFindingIds ?? [],
      sourceScreenshots: rest.sourceScreenshots ?? [],
      sources: rest.sources?.length ? rest.sources : [source],
    };
  });
}

const parseHaya = (rows: object[]) => asEvents(parseHayabusaTimeline(JSON.stringify(rows)), "1", "Hayabusa");
const parseChainsaw = (rows: object[]) =>
  asEvents(
    parseVelociraptorJson(JSON.stringify(rows), { artifact: "Windows.EventLogs.Chainsaw" }),
    "2",
    "Chainsaw",
  );

describe("native Hayabusa rows state which act they record", () => {
  it("types Sysmon EID 11 as a file write", () => {
    const [row] = parseHaya([hayabusaWrite]);
    expect(row.canonical?.event).toMatchObject({ category: "file", type: "create" });
  });

  it("types Sysmon EID 1 as a process start", () => {
    const [row] = parseHaya([
      hayabusa(
        1,
        SYSMON,
        "Proc Exec",
        LAUNCH_TIME,
        `Cmdline: ${CMD} ¦ Proc: ${DROP} ¦ PID: 1112 ¦ ParentCmdline: ${PS}`,
      ),
    ]);
    expect(row.canonical?.event).toMatchObject({ category: "process", type: "start" });
  });

  it("types Security 4688 as a process start", () => {
    const [row] = parseHaya([
      hayabusa(4688, "Security", "Proc Exec", LAUNCH_TIME, `Cmdline: ${CMD} ¦ Proc: ${DROP} ¦ PID: 0x458`),
    ]);
    expect(row.canonical?.event).toMatchObject({ category: "process", type: "start" });
  });

  it("does not type an EID 11 from a channel where that id means something else", () => {
    const [row] = parseHaya([
      hayabusa(11, "Microsoft-Windows-DNS-Client/Operational", "Other", WRITE_TIME, "Path: x"),
    ]);
    expect(row.canonical?.event?.type).not.toBe("create");
    expect(row.canonical?.event?.category).not.toBe("file");
  });

  it("does not type a Sysmon EID 3 connection as a write or a launch", () => {
    const [row] = parseHaya([
      hayabusa(
        3,
        SYSMON,
        "Net Conn",
        WRITE_TIME,
        `Proc: ${PS} ¦ PID: 10756 ¦ TgtIP: 203.0.113.9 ¦ TgtPort: 443`,
      ),
    ]);
    expect(row.canonical?.event?.type).not.toBe("create");
    expect(row.canonical?.event?.type).not.toBe("start");
  });
});

describe("correlateEvents — a Hayabusa file write and a Chainsaw launch of that file stay two rows", () => {
  it("keeps both rows, and the launch keeps its command line, pid and process name", () => {
    const rows = [...parseHaya([hayabusaWrite]), ...parseChainsaw([chainsawLaunch])];
    expect(new Set(rows.map((e) => e.path))).toEqual(new Set([DROP]));

    for (const input of [rows, [...rows].reverse()]) {
      const out = correlateEvents(input);
      const launches = out.filter((e) => e.canonical?.event?.type === "start");
      const writes = out.filter((e) => e.canonical?.event?.type === "create");
      expect(out).toHaveLength(2);
      expect(launches).toHaveLength(1);
      expect(writes).toHaveLength(1);
      // The launch row states what ran. The write row does not borrow it.
      expect(launches[0].commandLine).toBe(CMD);
      expect(launches[0].pid).toBe(1112);
      expect(launches[0].description).toMatch(/Binary Rename/);
      expect(writes[0].commandLine).toBeUndefined();
      expect(writes[0].pid).toBeUndefined();
    }
  });
});
