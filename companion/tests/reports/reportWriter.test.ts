import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
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
});
