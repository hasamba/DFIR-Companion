// #1715: the written report reads a hypothesis the way the dashboard does — a link to an event
// correlation folded into another counts the survivor — and the case lineage itself never reaches the
// report's state export.
import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-05-28T09:00:00Z",
  description: `THOR alert ${id}`,
  severity: "Critical",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

async function writeReport() {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1715-report-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [ev("t2e5")],
    eventAliases: { m1e1: "t2e5" },
  });
  const hypothesisStore = new HypothesisStore(cases);
  await hypothesisStore.add("c1", { title: "Malware was dropped", relatedEventIds: ["m1e1"] });
  const paths = await new ReportWriter(cases, stateStore, { hypothesisStore }).writeAll("c1");
  return {
    md: await readFile(paths.markdown, "utf8"),
    exported: JSON.parse(await readFile(join(paths.markdown, "..", "state-export.json"), "utf8")),
  };
}

describe("hypotheses in the written report after a fold (#1715)", () => {
  it("counts the surviving event, not a missing observation", async () => {
    const { md } = await writeReport();
    const section = md.slice(md.indexOf("## Hypotheses"));
    expect(section).toContain("Malware was dropped");
    expect(section).not.toContain("m1e1");
    expect(section).not.toContain("not counted");
  });

  it("keeps the lineage out of the state export", async () => {
    const { exported } = await writeReport();
    expect(exported.eventAliases).toBeUndefined();
    expect(exported.forensicTimeline.map((e: ForensicEvent) => e.id)).toEqual(["t2e5"]);
  });
});
