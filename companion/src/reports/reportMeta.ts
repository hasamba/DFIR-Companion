import { readFile } from "node:fs/promises";
import { atomicWrite } from "../storage/atomicWrite.js";
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

// Optional report branding: the investigating firm's name and logo, shown at the top of the
// report's title page. The logo is carried inline as a base64 `data:` URI so the report stays
// self-contained (the HTML export has no external deps) and the existing report-meta plumbing
// transports it with no extra upload route or side file. Only raster formats are accepted —
// SVG is rejected so an analyst-supplied logo can never smuggle script into the rendered HTML
// report — and the URI is length-capped so report-meta.json stays small.
const LOGO_MAX_LEN = 1_000_000; // ~1 MB of data-URI text (~750 KB binary) — ample for a logo
const LOGO_DATA_URI = /^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/i;

// Coerce any input to a valid logo data URI or "". Never throws — non-strings, blanks,
// over-cap, or non-raster/malformed URIs all collapse to "" (no logo).
function normalizeLogo(value: unknown): string {
  if (typeof value !== "string") return "";
  const v = value.trim();
  if (v.length === 0 || v.length > LOGO_MAX_LEN) return "";
  return LOGO_DATA_URI.test(v) ? v : "";
}

// Every field is lenient (.catch) so a partial or slightly-malformed payload still
// normalizes instead of rejecting — same philosophy as the AI response schemas.
export const reportMetaSchema = z.object({
  // 0 Title page
  companyName: z.string().catch(""), // optional — the investigating firm, shown with the logo
  companyLogo: z.preprocess(normalizeLogo, z.string().catch("")), // optional — base64 image data URI
  organization: z.string().catch(""),
  incidentId: z.string().catch(""), // optional — omitted from the report when blank
  investigators: z.array(z.string()).catch([]), // one or more investigators
  reviewer: z.string().catch(""), // optional report reviewer
  incidentManager: z.string().catch(""), // optional incident manager
  restrictions: z.string().catch(""), // e.g. "CONFIDENTIAL / TLP:AMBER"
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

// The report text Watson may write (product decision D3): never the executive summary.
export const WATSON_REPORT_FIELDS = ["conclusions", "investigationLimitations"] as const;
export type WatsonReportField = (typeof WATSON_REPORT_FIELDS)[number];
export type WatsonFieldMarks = Partial<Record<WatsonReportField, { proposalId: string; at: string }>>;

// Bookkeeping kept beside the content, never part of it: the save version (`updatedAt`) and which
// fields hold Watson's text. Parsed only from the stored file, so a PUT body can never forge them,
// and left out of reportMetaSchema so the version diff and the version-dedupe hash ignore them.
const markSchema = z.object({ proposalId: z.string(), at: z.string() }).optional().catch(undefined);
const storedReportMetaSchema = reportMetaSchema.extend({
  updatedAt: z.string().optional().catch(undefined),
  watsonFields: z
    .object({ conclusions: markSchema, investigationLimitations: markSchema })
    .optional()
    .catch(undefined),
});

export type ReportRevision = z.infer<typeof revisionSchema>;
export type DistributionEntry = z.infer<typeof distributionSchema>;
export type GlossaryEntry = z.infer<typeof glossarySchema>;
export type ReportMeta = z.infer<typeof reportMetaSchema> & {
  /** Stamped on every save, strictly increasing: the version an analyst's form opened. */
  updatedAt?: string;
  /** Fields whose text Watson wrote (an approved proposal); an analyst edit removes the mark. */
  watsonFields?: WatsonFieldMarks;
};

export function emptyReportMeta(): ReportMeta {
  return reportMetaSchema.parse({});
}

// Coerce untrusted input (file contents or a PUT body) into a valid ReportMeta. Unknown
// keys are dropped; wrong-typed fields fall back to their default. Never throws. The
// bookkeeping (`updatedAt`, `watsonFields`) is dropped too: only the store sets it.
export function normalizeReportMeta(input: unknown): ReportMeta {
  const parsed = reportMetaSchema.safeParse(input ?? {});
  return parsed.success ? parsed.data : emptyReportMeta();
}

function normalizeStored(input: unknown): ReportMeta {
  const parsed = storedReportMetaSchema.safeParse(input ?? {});
  if (!parsed.success) return emptyReportMeta();
  const { updatedAt, watsonFields, ...content } = parsed.data;
  const marks = Object.fromEntries(Object.entries(watsonFields ?? {}).filter(([, m]) => m));
  return {
    ...content,
    ...(updatedAt ? { updatedAt } : {}),
    ...(Object.keys(marks).length ? { watsonFields: marks } : {}),
  };
}

/** A save named the version it opened, and the stored report details are newer (route → 409). */
export class ReportMetaStale extends Error {
  constructor() {
    super("Report details changed since you opened them — reload");
    this.name = "ReportMetaStale";
  }
}

/**
 * An analyst's (or a version restore's) full replace: the content of `input`, the Watson marks of
 * the fields whose text it leaves unchanged (a changed field is the analyst's text now).
 */
export function replaceReportMeta(current: ReportMeta, input: unknown): ReportMeta {
  const next = normalizeReportMeta(input);
  const marks = Object.fromEntries(
    WATSON_REPORT_FIELDS.flatMap((f) => {
      const mark = current.watsonFields?.[f];
      return mark && next[f] === current[f] ? [[f, mark]] : [];
    }),
  ) as WatsonFieldMarks;
  return Object.keys(marks).length ? { ...next, watsonFields: marks } : next;
}

/** A version stamp strictly after `prev`, so two saves in one millisecond still differ. */
function nextStamp(prev: string | undefined): string {
  const now = Date.now();
  const last = prev ? Date.parse(prev) : NaN;
  return new Date(Number.isNaN(last) || now > last ? now : last + 1).toISOString();
}

const UNKNOWN_INVESTIGATOR = "unknown";

export class ReportMetaStore {
  /** One promise chain per case: every save runs after the one before it. */
  private readonly chains = new Map<string, Promise<unknown>>();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-meta.json");
  }

  // Until Case Details is first saved, the investigator typed at case creation is the list (#1913):
  // it lives in case.json, and without this the form and every report said "(investigator not set)".
  // Only when the file is MISSING — a saved list, an empty one included, is the analyst's and is
  // returned as saved, so save → load round-trips and clearing the field sticks.
  async load(caseId: string): Promise<ReportMeta> {
    try {
      return normalizeStored(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      return { ...emptyReportMeta(), investigators: await this.creationInvestigators(caseId) };
    }
  }

  private async creationInvestigators(caseId: string): Promise<string[]> {
    // getCaseMeta is null for a missing case; a corrupt or unreadable case.json throws, visibly.
    const name = (await this.cases.getCaseMeta(caseId))?.investigator?.trim() ?? "";
    // "unknown" is POST /cases's own placeholder for a case created with no investigator.
    return name && name.toLowerCase() !== UNKNOWN_INVESTIGATOR ? [name] : [];
  }

  /**
   * The ONE write path: a per-case chain, so a read-check-write (the analyst's version check, a
   * Watson field write) can never interleave with another save. `fn` gets the stored meta and returns
   * the next one (spread its argument to keep the rest); a throw writes nothing and does not block
   * later saves. Persisted atomically with a new strictly-increasing `updatedAt`.
   */
  update(caseId: string, fn: (current: ReportMeta) => ReportMeta | Promise<ReportMeta>): Promise<ReportMeta> {
    const prev = this.chains.get(caseId) ?? Promise.resolve();
    const run = prev.then(async () => {
      const current = await this.load(caseId);
      const next = normalizeStored({ ...(await fn(current)), updatedAt: nextStamp(current.updatedAt) });
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return next;
    });
    const tail = run.catch(() => undefined);
    this.chains.set(caseId, tail);
    void tail.then(() => {
      if (this.chains.get(caseId) === tail) this.chains.delete(caseId);
    });
    return run;
  }

  /**
   * Replace the report details with `meta` (normalized), through update(). With `baseUpdatedAt`
   * (the version the analyst's form opened; "" for a never-saved case) a newer stored version is
   * refused with ReportMetaStale. Returns the value written so callers can echo it to the UI.
   */
  save(caseId: string, meta: unknown, baseUpdatedAt?: string): Promise<ReportMeta> {
    return this.update(caseId, (current) => {
      if (baseUpdatedAt !== undefined && baseUpdatedAt !== (current.updatedAt ?? "")) {
        throw new ReportMetaStale();
      }
      return replaceReportMeta(current, meta);
    });
  }
}
