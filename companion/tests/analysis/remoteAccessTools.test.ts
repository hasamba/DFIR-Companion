import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { prefetchSignal } from "../../src/analysis/prefetchExecution.js";
import { REMOTE_ACCESS_TOOLS } from "../../src/analysis/attackToolNames.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Remote-access (RMM) tools were graded only from a process COMMAND LINE (tradecraftRules.ts), so an
// AnyDesk or ScreenConnect run seen only in Prefetch or Amcache stayed Info and never reached the AI.
// Installing one is the most common operator persistence path; on its own it is still a lead, so the
// grade is Medium with T1219, the same grade a dual-use binary's bare execution gets. These tests run
// the REAL importers and the SHIPPED ruleset.

const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const AMCACHE_RULE = "amcache_remote_access_tool";
const SHA1 = "e8dcddb302f01d51da3bcbfa6707d025a896aa57";

// One executable name per tool family, as each ships. ScreenConnect's service name is 31 characters,
// longer than the 29 a Prefetch file keeps, so its Prefetch spelling is the truncated one.
const TOOLS = [
  "AnyDesk.exe",
  "rustdesk.exe",
  "TeamViewer.exe",
  "TeamViewer_Service.exe",
  "LogMeIn.exe",
  "LMIGuardianSvc.exe",
  "AteraAgent.exe",
  "MeshAgent.exe",
  "tacticalrmm.exe",
  "dwagent.exe",
  "rutserv.exe",
  "rfusclient.exe",
  "Supremo.exe",
  "ScreenConnect.ClientService.exe",
  "ScreenConnect.WindowsClient.exe",
];
const PREFETCH_TRUNCATED = "SCREENCONNECT.CLIENTSERVICE.E";

const CONTROLS = ["notepad.exe", "anydesk_setup_notes.txt", "myteamviewer.exe", "meshagent.exe.bak"];

type Graded = { severity: string; mitre: string[]; ruleIds: string[] };

function tag(mapped: Partial<ForensicEvent>): Graded {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, mitre: after.mitreTechniques ?? [], ruleIds: proposal?.ruleIds ?? [] };
}

function kapePrefetch(exe: string): Graded {
  const csv = [
    "ExecutableName,SourceFilename,RunCount,LastRun",
    `${exe},C:\\Windows\\Prefetch\\${exe}-1A2B3C4D.pf,3,2026-09-22 14:37:51`,
  ].join("\n");
  return tag(parseKapeCsv(csv).events[0]);
}

function veloPrefetch(exe: string): Graded {
  const rows = [
    {
      _Source: "Windows.Forensics.Prefetch",
      Executable: exe,
      RunCount: 2,
      LastRunTimes: ["2026-09-22T14:37:51Z"],
    },
  ];
  return tag(parseVelociraptorJson(JSON.stringify(rows)).events[0]);
}

function kapeAmcache(path: string): Graded {
  const csv = [
    "ApplicationName,FullPath,FileKeyLastWriteTimestamp,SHA1,Size",
    `x,${path},2026-09-22 14:37:51,0000${SHA1},2048`,
  ].join("\n");
  return tag(parseKapeCsv(csv).events[0]);
}

function veloAmcache(path: string): Graded {
  const name = path.split("\\").pop() ?? path;
  const rows = [
    {
      _Source: "Windows.Forensics.Amcache/InventoryApplicationFile",
      Name: name,
      OriginalFileName: name,
      FullPath: path,
      SHA1,
      Timestamp: "2026-09-22T14:37:51Z",
    },
  ];
  return tag(parseVelociraptorJson(JSON.stringify(rows)).events[0]);
}

describe("remote-access tools in Prefetch", () => {
  for (const exe of [...TOOLS.map((t) => t.toUpperCase()), PREFETCH_TRUNCATED]) {
    it(`grades ${exe} Medium with T1219 (KAPE and Velociraptor)`, () => {
      for (const r of [kapePrefetch(exe), veloPrefetch(exe)]) {
        expect(r.severity).toBe("Medium");
        expect(r.mitre).toContain("T1219");
      }
    });
  }

  for (const exe of CONTROLS) {
    it(`leaves ${exe} alone`, () => {
      expect(prefetchSignal(exe)).toBeNull();
    });
  }
});

describe("bundled data/tags.yaml — remote-access tools in Amcache", () => {
  it("loads the rule as Medium with T1219", () => {
    const rule = RULES.rules.find((r) => r.id === AMCACHE_RULE);
    expect(rule?.severity).toBe("Medium");
    expect(rule?.mitre).toEqual(["T1219"]);
  });

  for (const exe of TOOLS) {
    const path = `C:\\Users\\a\\Downloads\\${exe}`;
    it(`grades ${exe} Medium with T1219 (KAPE and Velociraptor)`, () => {
      for (const r of [kapeAmcache(path), veloAmcache(path)]) {
        expect(r.ruleIds).toContain(AMCACHE_RULE);
        expect(r.severity).toBe("Medium");
        expect(r.mitre).toContain("T1219");
      }
    });
  }

  for (const exe of CONTROLS) {
    it(`leaves ${exe} alone`, () => {
      expect(kapeAmcache(`C:\\tools\\${exe}`).ruleIds).not.toContain(AMCACHE_RULE);
    });
  }

  it("does not grade an MFT listing of the same file — presence on disk is not a run", () => {
    const csv = [
      "EntryNumber,ParentPath,FileName,Extension,Created0x10,InUse,IsDirectory",
      "5,.\\Users\\a\\Downloads,AnyDesk.exe,.exe,2026-09-22 14:37:51,True,False",
    ].join("\n");
    expect(tag(parseKapeCsv(csv).events[0]).ruleIds).not.toContain(AMCACHE_RULE);
  });

  // Both lists are checked against the same names AND against each other's misses, so a name added
  // to one and not the other fails here rather than silently grading one artifact and not the other.
  it("keeps the Amcache rule and the Prefetch list naming the same tools", () => {
    const yamlPath = RULES.rules.find((r) => r.id === AMCACHE_RULE)?.all.find((c) => c.field === "path");
    if (yamlPath?.op.kind !== "regex") throw new Error(`${AMCACHE_RULE} has no path regex`);
    const yamlRe = yamlPath.op.re;
    for (const exe of [...TOOLS, ...CONTROLS]) {
      const inTs = REMOTE_ACCESS_TOOLS.re.test(exe.toLowerCase());
      const inYaml = yamlRe.test(`C:\\x\\${exe}`);
      expect(inYaml, exe).toBe(inTs);
    }
  });
});
