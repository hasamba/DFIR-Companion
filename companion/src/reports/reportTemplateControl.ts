import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { DEFAULT_TEMPLATE_ID } from "./reportTemplate.js";

// Per-case selection of which report template (issue #60) renders the case's report. The templates
// themselves are global (ReportTemplateStore); this just records the chosen id per case in
// `state/report-template.json`. Default = the shipped "standard" template, so an un-configured case
// renders exactly as before. If the selected template was later deleted, the ReportWriter falls back
// to the default — so a dangling id never breaks report generation.

export interface ReportTemplateControl {
  templateId: string;
}

export const DEFAULT_REPORT_TEMPLATE_CONTROL: ReportTemplateControl = { templateId: DEFAULT_TEMPLATE_ID };

const reportTemplateControlSchema = z
  .object({ templateId: z.string().catch(DEFAULT_TEMPLATE_ID) })
  .catch(DEFAULT_REPORT_TEMPLATE_CONTROL);

export class ReportTemplateControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-template.json");
  }

  async load(caseId: string): Promise<ReportTemplateControl> {
    try {
      const parsed = reportTemplateControlSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
      const templateId = parsed.templateId.trim() || DEFAULT_TEMPLATE_ID;
      return { templateId };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT_REPORT_TEMPLATE_CONTROL };
      throw err;
    }
  }

  async set(caseId: string, patch: Partial<ReportTemplateControl>): Promise<ReportTemplateControl> {
    const next: ReportTemplateControl = {
      ...(await this.load(caseId)),
      ...(typeof patch.templateId === "string" ? { templateId: patch.templateId.trim() || DEFAULT_TEMPLATE_ID } : {}),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}
