import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ReportGeneration } from "../../src/reports/reportGeneration.js";
import { isAtomicWriteTempPath } from "../../src/storage/atomicWrite.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// A report is eight files written over the previous report's eight. Any interruption between them
// left NEW artifacts beside OLD ones — each individually readable, which is what makes it dangerous:
// a report directory presenting a findings CSV from one generation and a narrative from another,
// with provenance for a run that never finished.

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-reportgen-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  const state = emptyState("c1");
  state.lastSummary = "first generation";
  await stateStore.save(state);
});

describe("ReportGeneration", () => {
  it("makes nothing visible until publish", async () => {
    const dir = caseStore.reportsDir("c1");
    const target = join(dir, "report.md");
    const generation = new ReportGeneration();

    await generation.stage(target, "staged content");
    expect((await readdir(dir)).includes("report.md")).toBe(false);

    await generation.publish();
    expect(await readFile(target, "utf8")).toBe("staged content");
  });

  it("stages under names the rest of the system reads as a write in progress", async () => {
    const dir = caseStore.reportsDir("c1");
    const generation = new ReportGeneration();
    await generation.stage(join(dir, "report.md"), "x");

    // Every staged file must match atomicWrite's temp shape, which caseTransientPaths.ts skips —
    // otherwise a concurrent export would seal a half-built report into an archive.
    const staged = await readdir(dir);
    expect(staged.length).toBeGreaterThan(0);
    expect(staged.every((name) => isAtomicWriteTempPath(name))).toBe(true);

    await generation.discard();
  });

  it("leaves no debris behind when discarded", async () => {
    const dir = caseStore.reportsDir("c1");
    const generation = new ReportGeneration();
    await generation.stage(join(dir, "report.md"), "a");
    await generation.stage(join(dir, "findings.csv"), "b");

    await generation.discard();
    expect(await readdir(dir)).toEqual([]);
  });

  it("treats discard after publish as a no-op, so the published files survive", async () => {
    const dir = caseStore.reportsDir("c1");
    const generation = new ReportGeneration();
    await generation.stage(join(dir, "report.md"), "published");

    await generation.publish();
    await generation.discard();

    expect(await readFile(join(dir, "report.md"), "utf8")).toBe("published");
  });
});

describe("ReportWriter — generation is all-or-nothing", () => {
  // The exact interruption the fix exists for: the artifacts render fine, then the provenance
  // record fails. That used to leave a NEW report.md, HTML and CSVs beside the OLD
  // analysis-runs.json — a directory whose narrative and provenance disagreed, with nothing to
  // indicate it.
  it("keeps the previous report intact when provenance fails mid-generation", async () => {
    const paths = await new ReportWriter(caseStore, stateStore).writeAll("c1");
    const before = {
      markdown: await readFile(paths.markdown, "utf8"),
      findings: await readFile(paths.findingsCsv, "utf8"),
      runs: await readFile(paths.analysisRuns, "utf8"),
    };
    expect(before.markdown).toContain("first generation");

    const state = await stateStore.load("c1");
    state.lastSummary = "second generation";
    await stateStore.save(state);

    const failing = new ReportWriter(caseStore, stateStore, {
      analysisRuns: {
        list: async () => [],
        record: async () => {
          throw new Error("disk full");
        },
      } as unknown as NonNullable<ConstructorParameters<typeof ReportWriter>[2]>["analysisRuns"],
    });

    await expect(failing.writeAll("c1")).rejects.toThrow(/disk full/);

    // Not one artifact of the failed generation reached the directory, and no staging survived.
    expect(await readFile(paths.markdown, "utf8")).toBe(before.markdown);
    expect(await readFile(paths.markdown, "utf8")).not.toContain("second generation");
    expect(await readFile(paths.findingsCsv, "utf8")).toBe(before.findings);
    expect(await readFile(paths.analysisRuns, "utf8")).toBe(before.runs);
    expect((await readdir(caseStore.reportsDir("c1"))).some(isAtomicWriteTempPath)).toBe(false);
  });

  it("replaces every artifact together on a successful regeneration", async () => {
    const writer = new ReportWriter(caseStore, stateStore);
    await writer.writeAll("c1");

    const state = await stateStore.load("c1");
    state.lastSummary = "second generation";
    await stateStore.save(state);
    const paths = await writer.writeAll("c1");

    expect(await readFile(paths.markdown, "utf8")).toContain("second generation");
    expect(await readFile(paths.markdown, "utf8")).not.toContain("first generation");
    // No staging left over on the happy path either.
    expect((await readdir(caseStore.reportsDir("c1"))).some(isAtomicWriteTempPath)).toBe(false);
  });

  it("does not disturb unrelated files that legitimately live in reports/", async () => {
    const dir = caseStore.reportsDir("c1");
    const sidecar = join(dir, "chain-of-custody.json");
    await writeFile(sidecar, '{"kept":true}', "utf8");

    await new ReportWriter(caseStore, stateStore).writeAll("c1");

    expect(await readFile(sidecar, "utf8")).toBe('{"kept":true}');
  });
});
