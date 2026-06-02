import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { LegitimateStore, markerId } from "../../src/analysis/legitimate.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  const state = emptyState("c1");
  state.lastSummary = "summary text";
  await stateStore.save(state);
});

describe("ReportWriter", () => {
  it("writes all report files and returns their paths", async () => {
    const writer = new ReportWriter(caseStore, stateStore);
    const paths = await writer.writeAll("c1");

    expect(paths.markdown).toMatch(/report\.md$/);
    const md = await readFile(paths.markdown, "utf8");
    expect(md).toContain("summary text");

    const findings = await readFile(paths.findingsCsv, "utf8");
    expect(findings).toContain("id,severity,title");

    const exported = JSON.parse(await readFile(paths.stateJson, "utf8"));
    expect(exported.caseId).toBe("c1");
  });

  it("excludes client-confirmed legitimate forensic events from the report", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker beacon callout", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance window", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(state);

    const legitimate = new LegitimateStore(caseStore);
    await legitimate.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's maintenance", markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance window" },
    ]);

    const writer = new ReportWriter(caseStore, stateStore, undefined, legitimate);
    const paths = await writer.writeAll("c1");

    const forensic = await readFile(paths.forensicTimelineCsv, "utf8");
    expect(forensic).toContain("attacker beacon callout");          // kept
    expect(forensic).not.toContain("client admin maintenance window"); // legit event excluded

    const md = await readFile(paths.markdown, "utf8");
    expect(md).not.toContain("client admin maintenance window");
  });
});
