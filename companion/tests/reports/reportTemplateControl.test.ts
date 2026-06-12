import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ReportTemplateControlStore, DEFAULT_REPORT_TEMPLATE_CONTROL } from "../../src/reports/reportTemplateControl.js";

describe("ReportTemplateControlStore", () => {
  let store: ReportTemplateControlStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-template-control-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "case-1", name: "n", investigator: "i", aiProvider: null });
    store = new ReportTemplateControlStore(cases);
  });

  it("defaults to the standard template when no file exists", async () => {
    expect(await store.load("case-1")).toEqual(DEFAULT_REPORT_TEMPLATE_CONTROL);
  });

  it("persists and reloads the selected template id", async () => {
    const saved = await store.set("case-1", { templateId: "executive-brief" });
    expect(saved.templateId).toBe("executive-brief");
    expect((await store.load("case-1")).templateId).toBe("executive-brief");
  });

  it("falls back to the default when set to a blank id", async () => {
    const saved = await store.set("case-1", { templateId: "   " });
    expect(saved.templateId).toBe(DEFAULT_REPORT_TEMPLATE_CONTROL.templateId);
  });
});
