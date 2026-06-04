import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";

// Human-authored report metadata. The investigation pipeline derives the technical
// sections (timelines, findings, IOCs, MITRE), but an incident report following the
// AnttiKurittu template (https://github.com/AnttiKurittu/incident-report-template) also
// needs sections only a human can write: the title page, distribution, business-impact
// analysis, investigation limitations, glossary, recommendations, etc. Those live here,
// persisted per case in `state/report-meta.json`, edited from the dashboard, and merged
// into report.md on generation. Empty fields fall back to a derived value or a clearly
// marked "to be completed" placeholder so the analyst can see what still needs filling.

const revisionSchema = z.object({
  version: z.string().catch(""),
  date: z.string().catch(""),
  author: z.string().catch(""),
  comments: z.string().catch(""),
});

const distributionSchema = z.object({
  name: z.string().catch(""),
  role: z.string().catch(""),
  method: z.string().catch(""),
});

const glossarySchema = z.object({
  term: z.string().catch(""),
  explanation: z.string().catch(""),
});

// Every field is lenient (.catch) so a partial or slightly-malformed payload still
// normalizes instead of rejecting — same philosophy as the AI response schemas.
export const reportMetaSchema = z.object({
  // 0 Title page
  organization: z.string().catch(""),
  incidentId: z.string().catch(""),             // optional — omitted from the report when blank
  investigators: z.array(z.string()).catch([]), // one or more investigators
  reviewer: z.string().catch(""),               // optional report reviewer
  incidentManager: z.string().catch(""),        // optional incident manager
  restrictions: z.string().catch(""),          // e.g. "CONFIDENTIAL / TLP:AMBER"
  // 1.1 Report revisions
  revisions: z.array(revisionSchema).catch([]),
  // 1.2 Distribution list
  distribution: z.array(distributionSchema).catch([]),
  // 1.3 Disclaimer and reading guide (static block, on by default)
  includeDisclaimer: z.boolean().catch(true),
  // 1.4 Intended audience
  intendedAudience: z.string().catch(""),
  // 2 Executive summary (overrides the AI summary when set)
  executiveSummary: z.string().catch(""),
  // 2.1 Business Impact Analysis
  businessImpact: z.string().catch(""),
  // 2.2 Investigation limitations
  investigationLimitations: z.string().catch(""),
  // 2.3 Investigation goals and targets (research questions, freeform markdown)
  investigationGoals: z.string().catch(""),
  // 2.4 Glossary of terms — auto-derived from the report text when left empty (see
  // glossary.ts); a non-empty value here overrides the automatic glossary.
  glossary: z.array(glossarySchema).catch([]),
  // 5 Conclusions (overrides the derived conclusion when set) + recommendations
  conclusions: z.string().catch(""),
  recommendations: z.array(z.string()).catch([]),
});

export type ReportRevision = z.infer<typeof revisionSchema>;
export type DistributionEntry = z.infer<typeof distributionSchema>;
export type GlossaryEntry = z.infer<typeof glossarySchema>;
export type ReportMeta = z.infer<typeof reportMetaSchema>;

export function emptyReportMeta(): ReportMeta {
  return reportMetaSchema.parse({});
}

// Coerce untrusted input (file contents or a PUT body) into a valid ReportMeta. Unknown
// keys are dropped; wrong-typed fields fall back to their default. Never throws.
export function normalizeReportMeta(input: unknown): ReportMeta {
  const parsed = reportMetaSchema.safeParse(input ?? {});
  return parsed.success ? parsed.data : emptyReportMeta();
}

export class ReportMetaStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-meta.json");
  }

  async load(caseId: string): Promise<ReportMeta> {
    try {
      return normalizeReportMeta(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyReportMeta();
      throw err;
    }
  }

  // Persist atomically (temp-file + rename), like the other per-case stores. Returns the
  // normalized value actually written so callers can echo it back to the UI.
  async save(caseId: string, meta: unknown): Promise<ReportMeta> {
    const normalized = normalizeReportMeta(meta);
    const target = this.path(caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(normalized, null, 2), "utf8");
    await rename(tmp, target);
    return normalized;
  }
}
