import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { deltaSchema } from "../../src/analysis/responseSchema.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { executionIdentity } from "../../src/analysis/chainSignature.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1476 — a hunt imports one artifact after another. The first (large) file takes the bulk path and
// APPENDS its graded rows to the forensic table; every later file loads the state, merges through
// correlation and saves. Ten High rows written by the first step were gone from the forensic table
// before the hunt finished, and one artifact's four rows reached neither timeline. The cause was
// correlation folding distinct files (one hash, four paths) and distinct launches (one path, three
// command lines) into one row at those later merges — this test walks the real store through the
// same sequence with lab-safe rows of the real shapes and asserts the facts, not the ids.

const ROOT = "C:\\Users\\Public\\Sim\\";
const HOST = "WS-01";
const SHA = "9695CF4566DDF878A69C3D419E0DA4EEA87B0F24261AD8E79A3A9C4A9885429C";
const MD5 = "C8B5D63042BC4BBB7F5C0F9E15B61F16";
const TOOL = `${ROOT}tools\\helper.exe`;
const LAUNCHES = ["alpha", "bravo", "charlie"] as const;
const FILES = [
  `${ROOT}vpn\\vpnclient.exe`,
  `${ROOT}host\\remote.exe`,
  `${ROOT}tools\\helper.exe`,
  `${ROOT}host\\python.exe`,
];

function launchRow(seq: number, label: string, pid: number, recordId: number, parsed: boolean): object {
  const cmd = `"${TOOL}" /d /c echo LAB ${label}`;
  const time = `2026-09-20T19:29:${14 + seq}.418Z`;
  const eventData = {
    ProcessId: pid,
    Image: TOOL,
    OriginalFileName: "Cmd.Exe",
    CommandLine: cmd,
    User: `${HOST}\\lab`,
    Hashes: `MD5=${MD5},SHA256=${SHA}`,
    ParentImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  };
  const system = {
    EventID: { Value: 1 },
    TimeCreated: { SystemTime: time },
    EventRecordID: recordId,
    Channel: "Microsoft-Windows-Sysmon/Operational",
    Computer: HOST,
  };
  return parsed
    ? {
        _Source: "Windows.EventLogs.Chainsaw",
        Timestamp: time,
        Computer: HOST,
        Channel: "Microsoft-Windows-Sysmon/Operational",
        EventID: 1,
        Detection: "Potential Defense Evasion Via Binary Rename",
        Severity: "medium",
        System: system,
        EventData: eventData,
        Fqdn: `${HOST}.example.com`,
      }
    : {
        _Source: "Windows.Sigma.Base",
        Timestamp: time,
        Computer: HOST,
        Channel: "Microsoft-Windows-Sysmon/Operational",
        EID: "1",
        Level: "high",
        Title: "Renamed Helper Execution",
        RecordID: String(recordId),
        Details: `Cmdline: ${cmd} ¦ Proc: ${TOOL}`,
        _Event: { System: system, EventData: eventData },
        Fqdn: `${HOST}.example.com`,
      };
}

function renameRow(path: string): object {
  const name = path.split("\\").pop()!;
  return {
    OSPath: path,
    Name: name,
    Size: "344064",
    VersionInformation: {
      CompanyName: "Microsoft Corporation",
      FileDescription: "Windows Command Processor",
      OriginalFilename: "Cmd.Exe",
    },
    Hash: {
      MD5: MD5.toLowerCase(),
      SHA1: "a6adf6ac0983b094941dce8881e97cf252a68d9f",
      SHA256: SHA.toLowerCase(),
    },
    Mtime: "2025-12-05T02:54:10.1128473Z",
    Atime: "2026-09-20T19:29:08.4368508Z",
    Ctime: "2025-12-05T02:54:10.1128473Z",
    Btime: "2026-09-20T19:29:08.3842178Z",
    FlowId: "F.TEST.H",
    ClientId: "C.test",
    _OrgId: "root",
    Fqdn: `${HOST}.example.com`,
  };
}

function toEvents(rows: object[], artifact: string, prefix: string): ForensicEvent[] {
  return parseVelociraptorJson(JSON.stringify(rows), { artifact }).events.map((e, i) => {
    const { aggKey, ...rest } = e as ForensicEvent & { aggKey?: string };
    void aggKey;
    return {
      ...rest,
      id: `${prefix}e${i + 1}`,
      mitreTechniques: rest.mitreTechniques ?? [],
      relatedFindingIds: rest.relatedFindingIds ?? [],
      sourceScreenshots: rest.sourceScreenshots ?? [],
      sources: rest.sources?.length ? rest.sources : ["Velociraptor"],
    };
  });
}

describe("hunt import sequence keeps every distinct file and launch (#1476)", () => {
  it("bulk-appended rows survive the whole-file merges that follow", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-hunt-seq-"));
    const cases = new CaseStore(root);
    const stateStore = new StateStore(cases);
    const caseId = "SEQ-1";
    await cases.createCase({ caseId, name: "seq", investigator: "t", aiProvider: null });

    // 1) The Hayabusa artifact took the bulk path: graded rows appended straight to the table.
    const hayabusa = toEvents(
      LAUNCHES.map((l, i) => launchRow(i, l, 400 + i, 1170 + i, false)),
      "Windows.Hayabusa.Rules",
      "1",
    );
    expect(hayabusa).toHaveLength(3);
    await stateStore.appendForensicEvents(caseId, hayabusa);

    // 2) Every later artifact: load → merge → save, as the whole-file driver does.
    const later: Array<[object[], string, string]> = [
      [LAUNCHES.map((l, i) => launchRow(i, l, 400 + i, 1170 + i, true)), "Windows.EventLogs.Chainsaw", "2"],
      [FILES.map(renameRow), "DetectRaptor.Windows.Detection.BinaryRename", "6"],
    ];
    for (const [rows, artifact, prefix] of later) {
      const events = toEvents(rows, artifact, prefix);
      expect(events.length).toBe(rows.length);
      const delta = deltaSchema.parse({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        forensicEvents: events,
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: `import ${artifact}`,
        summary: "",
      });
      const state = await stateStore.load(caseId);
      const next = mergeDelta(state, delta, {
        windowSequence: -1,
        timestamp: new Date().toISOString(),
        sourceScreenshots: [artifact],
      });
      await stateStore.save(next);
    }

    const final = await stateStore.load(caseId);
    const ft = final.forensicTimeline;

    // Three launches, three rows — each carrying both parsers' readings of its one record.
    for (const label of LAUNCHES) {
      const rows = ft.filter((e) => executionIdentity(e).includes(`echo lab ${label}`));
      expect(rows, label).toHaveLength(1);
      expect(rows[0].sources).toEqual(expect.arrayContaining(["Velociraptor", "Chainsaw"]));
      expect(rows[0].severity).toBe("High");
    }
    // Four renamed copies of one binary: the fact "<name> is really Cmd.Exe" is stated for every
    // path, on whichever row the merge kept for that file (a Sysmon row may out-rank the rename row
    // and win the description; the registered note rides along, correlate.ts mergeGroup).
    for (const path of FILES) {
      const name = path.split("\\").pop()!;
      const rows = ft.filter((e) =>
        new RegExp(`\\[renamed binary: ${name.replace(".", "\\.")} is really Cmd\\.Exe`, "i").test(
          e.description,
        ),
      );
      expect(rows, path).toHaveLength(1);
    }
  });
});
