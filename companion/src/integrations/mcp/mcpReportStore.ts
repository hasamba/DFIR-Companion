import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

export interface McpImportCounts {
  addedFindings: number;
  updatedFindings: number;
  addedEvents: number;
  updatedEvents: number;
  addedIocs: number;
  updatedIocs: number;
}

export interface McpAnalysisReport {
  id: string;
  importedAt: string;
  server: string;
  tool: string;
  label: string;
  kind: string;
  text: string;
  counts: McpImportCounts;
}

type NewReport = Omit<McpAnalysisReport, "id" | "importedAt">;

const REPORT_ID_RE = /^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const countsSchema = z.object({
  addedFindings: z.number().int().nonnegative(),
  updatedFindings: z.number().int().nonnegative(),
  addedEvents: z.number().int().nonnegative(),
  updatedEvents: z.number().int().nonnegative(),
  addedIocs: z.number().int().nonnegative(),
  updatedIocs: z.number().int().nonnegative(),
});
const reportSchema = z.object({
  id: z.string().regex(REPORT_ID_RE),
  importedAt: z.string().datetime(),
  server: z.string(),
  tool: z.string(),
  label: z.string(),
  kind: z.string(),
  text: z.string(),
  counts: countsSchema,
});

const isReportId = (value: string): boolean => REPORT_ID_RE.test(value);

/**
 * Append-only MCP analysis reports. These live inside the case so exports and archives retain the
 * exact reviewed output rather than only the structured records derived from it.
 */
export class McpReportStore {
  constructor(private readonly cases: CaseStore) {}

  private dir(caseId: string): string {
    return join(this.cases.caseDir(caseId), "mcp-reports");
  }

  private path(caseId: string, reportId: string): string {
    return join(this.dir(caseId), `${reportId}.json`);
  }

  async save(caseId: string, input: NewReport): Promise<McpAnalysisReport> {
    const report: McpAnalysisReport = {
      ...input,
      id: `mcp-${randomUUID()}`,
      importedAt: new Date().toISOString(),
    };
    await mkdir(this.dir(caseId), { recursive: true });
    await atomicWrite(this.path(caseId, report.id), JSON.stringify(report, null, 2));
    return report;
  }

  async get(caseId: string, reportId: string): Promise<McpAnalysisReport | null> {
    if (!isReportId(reportId)) return null;
    try {
      const parsed = reportSchema.safeParse(JSON.parse(await readFile(this.path(caseId, reportId), "utf8")));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  async list(caseId: string): Promise<McpAnalysisReport[]> {
    let names: string[];
    try {
      names = (await readdir(this.dir(caseId))).filter((name) => isReportId(name.slice(0, -5)) && name.endsWith(".json"));
    } catch {
      return [];
    }
    const reports = await Promise.all(names.map((name) => this.get(caseId, name.slice(0, -5))));
    return reports
      .filter((report): report is McpAnalysisReport => report !== null)
      .sort((a, b) => b.importedAt.localeCompare(a.importedAt));
  }
}
