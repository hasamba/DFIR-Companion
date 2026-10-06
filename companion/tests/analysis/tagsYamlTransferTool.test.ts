import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1970 part 2: an Amcache row for a bulk-transfer tool (rclone, restic, MEGAsync, MEGAcmd) was Info
// in both importers, so an rclone run seen only in Amcache was demoted and never reached the AI.
// Prefetch already grades these names Medium with T1567.002. These tests run the REAL importers and
// the SHIPPED ruleset, so a change to either importer's Amcache description breaks them.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const RULE = "amcache_transfer_tool";

type Tagged = { severity: string; ruleIds: string[]; mitre: string[] };

function apply(mapped: Partial<ForensicEvent>): Tagged {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, ruleIds: proposal?.ruleIds ?? [], mitre: after.mitreTechniques ?? [] };
}

const SHA1 = "e8dcddb302f01d51da3bcbfa6707d025a896aa57";

function kape(path: string): Tagged {
  const csv = [
    "ApplicationName,FullPath,FileKeyLastWriteTimestamp,SHA1,Size",
    `x,${path},2026-09-22 14:37:51,0000${SHA1},2048`,
  ].join("\n");
  const r = parseKapeCsv(csv);
  expect(r.artifact).toBe("Amcache");
  return apply(r.events[0]);
}

function velociraptor(path: string): Tagged {
  const name = path.split("\\").pop() ?? path;
  const r = parseVelociraptorJson(
    JSON.stringify([
      {
        _Source: "Windows.Forensics.Amcache/InventoryApplicationFile",
        Name: name,
        OriginalFileName: name,
        FullPath: path,
        SHA1,
        Timestamp: "2026-09-22T14:37:51Z",
      },
    ]),
  );
  expect(r.events[0].description).toContain("Program file present (Amcache)");
  return apply(r.events[0]);
}

const TOOLS = [
  "C:\\Users\\Public\\Music\\rclone.exe",
  "C:\\Program Files\\MEGAsync\\MEGAsync.exe",
  "C:\\ProgramData\\restic.exe",
  "C:\\Users\\a\\AppData\\Local\\MEGAcmd\\MEGAcmd.exe",
];

const CONTROLS = ["C:\\Windows\\notepad.exe", "C:\\tools\\rclone.exe.bak", "C:\\tools\\myrclone.exe"];

describe("bundled data/tags.yaml — transfer tools in Amcache (#1970)", () => {
  it("loads the rule as Medium with T1567.002", () => {
    const rule = RULES.rules.find((r) => r.id === RULE);
    expect(rule?.severity).toBe("Medium");
    expect(rule?.mitre).toEqual(["T1567.002"]);
  });

  for (const [shape, run] of [
    ["KAPE", kape],
    ["Velociraptor", velociraptor],
  ] as const) {
    describe(`${shape} Amcache rows`, () => {
      it.each(TOOLS)("grades Medium with T1567.002: %s", (path) => {
        const r = run(path);
        expect(r.ruleIds).toContain(RULE);
        expect(r.severity).toBe("Medium");
        expect(r.mitre).toContain("T1567.002");
      });

      it.each(CONTROLS)("leaves a control Info: %s", (path) => {
        const r = run(path);
        expect(r.ruleIds).not.toContain(RULE);
        expect(r.severity).toBe("Info");
      });
    });
  }

  it("does not match a non-Amcache row for the same file", () => {
    const r = apply({
      description: "MFT: C:\\Users\\Public\\Music\\rclone.exe created",
      path: "C:\\Users\\Public\\Music\\rclone.exe",
      severity: "Info",
      sources: ["MFT"],
    });
    expect(r.ruleIds).not.toContain(RULE);
    expect(r.severity).toBe("Info");
  });

  // The rule restates the Prefetch grader's T1567.002 names. Every one must match.
  it("covers every T1567.002 name in prefetchExecution.ts", () => {
    const src = readFileSync(
      fileURLToPath(new URL("../../src/analysis/prefetchExecution.ts", import.meta.url)),
      "utf8",
    );
    const names = [...src.matchAll(/"([a-z0-9_.-]+\.exe)":\s*\["T1567\.002"\]/g)].map((m) => m[1]);
    expect(names.length).toBeGreaterThanOrEqual(4);
    for (const n of names) expect(kape(`C:\\x\\${n}`).ruleIds).toContain(RULE);
  });
});
