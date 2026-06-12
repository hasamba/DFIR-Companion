import { z } from "zod";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { ReportMeta } from "./reportMeta.js";

// A "report template" lets a DFIR team turn the fixed-format incident report into a
// client-facing deliverable WITHOUT hand-formatting: it controls report **branding** (accent
// colour, cover title/subtitle, running header & footer/confidentiality banner, whether the
// firm logo + name show), and **section layout** (which of the canonical report sections appear
// and in what order). The branding strings support a small, safe Handlebars-style placeholder
// syntax (`{{organization}}`, `{{#if incidentId}}…{{/if}}`) filled from the case's report
// metadata, so one template renders correctly across every case.
//
// Templates are GLOBAL (shared across cases, like case templates / triage bundles) and consumed
// by the Markdown renderer — the single source of truth — so the same layout/branding flows to
// the HTML and Word (.docx) exports automatically. This module is pure (no I/O): the schema,
// built-ins, section model, placeholder engine, and branding context. Persistence lives in
// `reportTemplateStore.ts`; per-case selection in `reportTemplateControl.ts`.

// The canonical, toggleable/reorderable report sections — at MAJOR-section granularity so a
// disabled or reordered section never orphans a numbered heading (e.g. "## 1 Report metadata"
// and its 1.1/1.2 subsections move together). The order here is the default report order.
export const REPORT_SECTION_DEFS = [
  { key: "titlePage", label: "Title / cover page" },
  { key: "reportMetadata", label: "1 · Report metadata (revisions, distribution, disclaimer)" },
  { key: "executiveSummary", label: "2 · Executive summary" },
  { key: "businessImpact", label: "2.1 · Business Impact Analysis" },
  { key: "investigationLimitations", label: "2.2 · Investigation limitations" },
  { key: "investigationGoals", label: "2.3 · Investigation goals & targets" },
  { key: "glossary", label: "2.4 · Glossary of terms" },
  { key: "timeline", label: "3 · Timeline of events" },
  { key: "investigation", label: "4 · Investigation (findings, IOCs, MITRE, chain of evidence)" },
  { key: "conclusions", label: "5 · Conclusions & recommendations" },
  { key: "playbook", label: "Response Playbook" },
  { key: "notebook", label: "Analyst Notebook" },
] as const;

export type ReportSectionKey = (typeof REPORT_SECTION_DEFS)[number]["key"];

export const ALL_SECTION_KEYS: readonly ReportSectionKey[] = REPORT_SECTION_DEFS.map((s) => s.key);
const SECTION_KEY_SET = new Set<string>(ALL_SECTION_KEYS);
export const SECTION_LABELS: Record<ReportSectionKey, string> = Object.fromEntries(
  REPORT_SECTION_DEFS.map((s) => [s.key, s.label]),
) as Record<ReportSectionKey, string>;

export interface ReportTemplateSection {
  key: ReportSectionKey;
  enabled: boolean;
}

export const DEFAULT_ACCENT = "#2d6cdf"; // mirrors the HTML report's historical accent
export const DEFAULT_COVER_TITLE = "Incident Investigation Report";
export const DEFAULT_TEMPLATE_ID = "standard";

const HEX_COLOR = /^#?[0-9a-f]{6}$/i;

// Coerce any input to a valid `#rrggbb` accent colour, falling back to the default. Accepts an
// optional leading `#` and any case; anything else (3-digit hex, named colour, junk) → default,
// so an analyst typo can never inject arbitrary text into the report stylesheet.
export function normalizeHexColor(value: unknown): string {
  if (typeof value !== "string") return DEFAULT_ACCENT;
  const v = value.trim();
  if (!HEX_COLOR.test(v)) return DEFAULT_ACCENT;
  return (v.startsWith("#") ? v : `#${v}`).toLowerCase();
}

const sectionSchema = z.object({
  key: z.string().catch(""),
  enabled: z.boolean().catch(true),
});

// Every field is lenient (`.catch`) so a partial/slightly-malformed payload normalizes instead
// of rejecting — same philosophy as the report-meta and AI response schemas.
export const reportTemplateSchema = z.object({
  id: z.string().catch(""),
  name: z.string().catch(""),
  description: z.string().catch(""),
  // Branding
  accentColor: z.preprocess(normalizeHexColor, z.string().catch(DEFAULT_ACCENT)),
  coverTitle: z.string().catch(DEFAULT_COVER_TITLE),
  coverSubtitle: z.string().catch(""),
  headerText: z.string().catch(""),
  footerText: z.string().catch(""),
  showLogo: z.boolean().catch(true),
  showCompanyName: z.boolean().catch(true),
  // Section layout
  sections: z.array(sectionSchema).catch([]),
});

export type ReportTemplate = z.infer<typeof reportTemplateSchema>;

// Normalize an arbitrary section list to FULL canonical coverage: keep provided (valid, deduped)
// keys in their given order so analyst reordering survives, then append any canonical section not
// yet listed (enabled, so a section added in a newer version is never silently hidden from an
// older saved template).
export function normalizeSections(input: unknown): ReportTemplateSection[] {
  const out: ReportTemplateSection[] = [];
  const seen = new Set<string>();
  if (Array.isArray(input)) {
    for (const raw of input) {
      const key = typeof raw?.key === "string" ? raw.key : "";
      if (!SECTION_KEY_SET.has(key) || seen.has(key)) continue;
      seen.add(key);
      out.push({ key: key as ReportSectionKey, enabled: raw?.enabled !== false });
    }
  }
  for (const key of ALL_SECTION_KEYS) {
    if (!seen.has(key)) out.push({ key, enabled: true });
  }
  return out;
}

// The ordered list of section keys a template wants rendered (enabled only).
export function orderedEnabledSections(template: ReportTemplate): ReportSectionKey[] {
  return normalizeSections(template.sections)
    .filter((s) => s.enabled)
    .map((s) => s.key);
}

// Coerce untrusted input (a file's contents or a POST body) into a valid ReportTemplate. Unknown
// keys are dropped, wrong-typed fields fall back to their default, sections get full coverage,
// and the trimmable text fields are trimmed. Never throws.
export function normalizeReportTemplate(input: unknown): ReportTemplate {
  const parsed = reportTemplateSchema.safeParse(input ?? {});
  const t = parsed.success ? parsed.data : reportTemplateSchema.parse({});
  return {
    ...t,
    id: t.id.trim(),
    name: t.name.trim(),
    description: t.description.trim(),
    accentColor: normalizeHexColor(t.accentColor),
    sections: normalizeSections(t.sections),
  };
}

export function emptyReportTemplate(): ReportTemplate {
  return normalizeReportTemplate({});
}

// The built-in shipped templates. The first ("standard") reproduces the historical fixed-format
// report exactly (all sections, default accent, no header/footer) so an un-templated case is
// byte-identical to before. The others demonstrate branding + section layout.
export const BUILT_IN_REPORT_TEMPLATES: readonly ReportTemplate[] = [
  normalizeReportTemplate({
    id: "standard",
    name: "Standard (full report)",
    description: "The complete AnttiKurittu-structured incident report — every section, default branding.",
    accentColor: DEFAULT_ACCENT,
    coverTitle: DEFAULT_COVER_TITLE,
  }),
  normalizeReportTemplate({
    id: "executive-brief",
    name: "Executive Brief",
    description: "A short client-facing brief: cover, executive summary, and conclusions only.",
    accentColor: "#0b6e4f",
    coverTitle: "Incident Report — Executive Brief",
    coverSubtitle: "{{organization}}{{#if incidentId}} · {{incidentId}}{{/if}}",
    footerText: "{{restrictions}}",
    sections: [
      { key: "titlePage", enabled: true },
      { key: "reportMetadata", enabled: false },
      { key: "executiveSummary", enabled: true },
      { key: "businessImpact", enabled: true },
      { key: "investigationLimitations", enabled: false },
      { key: "investigationGoals", enabled: false },
      { key: "glossary", enabled: false },
      { key: "timeline", enabled: false },
      { key: "investigation", enabled: false },
      { key: "conclusions", enabled: true },
      { key: "playbook", enabled: false },
      { key: "notebook", enabled: false },
    ],
  }),
  normalizeReportTemplate({
    id: "technical-detailed",
    name: "Technical Detail",
    description: "Full technical report with a branded header/footer — for the responding team.",
    accentColor: "#1f6feb",
    coverTitle: "Technical Incident Investigation",
    coverSubtitle: "{{organization}}",
    headerText: "{{#if companyName}}{{companyName}} — {{/if}}Technical Investigation{{#if incidentId}} ({{incidentId}}){{/if}}",
    footerText: "{{restrictions}} · Generated by DFIR Companion",
    sections: [
      { key: "titlePage", enabled: true },
      { key: "reportMetadata", enabled: true },
      { key: "executiveSummary", enabled: true },
      { key: "businessImpact", enabled: false },
      { key: "investigationLimitations", enabled: true },
      { key: "investigationGoals", enabled: true },
      { key: "glossary", enabled: true },
      { key: "timeline", enabled: true },
      { key: "investigation", enabled: true },
      { key: "conclusions", enabled: true },
      { key: "playbook", enabled: true },
      { key: "notebook", enabled: true },
    ],
  }),
];

// The default template (a fresh copy each call, so callers can't mutate the shared constant).
export function defaultReportTemplate(): ReportTemplate {
  return normalizeReportTemplate(
    BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === DEFAULT_TEMPLATE_ID) ?? {},
  );
}

// The placeholder values available to a branding string. Derived from the human-authored report
// metadata + the case state. All values are plain strings (joined where multi-valued).
export function buildBrandingContext(
  state: InvestigationState,
  meta: ReportMeta,
): Record<string, string> {
  const investigators = meta.investigators.map((s) => s.trim()).filter(Boolean);
  // Treat the epoch default (a case with no recorded activity) as "no date".
  const date = state.updatedAt && !state.updatedAt.startsWith("1970-01-01") ? state.updatedAt.slice(0, 10) : "";
  return {
    organization: meta.organization.trim(),
    companyName: meta.companyName.trim(),
    incidentId: meta.incidentId.trim(),
    restrictions: meta.restrictions.trim(),
    tlp: meta.restrictions.trim(),
    reviewer: meta.reviewer.trim(),
    incidentManager: meta.incidentManager.trim(),
    investigators: investigators.join(", "),
    caseId: state.caseId,
    date,
  };
}

// A tiny, safe Handlebars-style template engine for the branding strings. Supports:
//   {{key}}                      → the context value (unknown key → empty)
//   {{#if key}}…{{/if}}          → body shown when the value is truthy (non-empty string / true)
//   {{#unless key}}…{{/unless}}  → body shown when the value is falsy
// Blocks may nest. There are NO helpers, partials, or arbitrary code — the only operation is a
// lookup against the supplied context, and substituted values are NOT re-scanned (single pass),
// so case data can never inject template syntax. Output is Markdown text.
export function renderTemplateString(
  template: string,
  context: Record<string, string | number | boolean | undefined>,
): string {
  if (!template) return "";
  const truthy = (key: string): boolean => {
    const v = context[key];
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    return typeof v === "string" && v.trim().length > 0;
  };
  // Innermost-first: the body cannot contain another opening block, so the regex matches the
  // deepest blocks first; the loop collapses outward until no block remains (guarded).
  const blockRe = /\{\{#(if|unless)\s+([\w.]+)\}\}((?:(?!\{\{#)[\s\S])*?)\{\{\/\1\}\}/;
  let out = template;
  for (let guard = 0; guard < 100 && blockRe.test(out); guard++) {
    out = out.replace(blockRe, (_m, kind: string, key: string, body: string) =>
      (kind === "if" ? truthy(key) : !truthy(key)) ? body : "",
    );
  }
  return out.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_m, key: string) => {
    const v = context[key];
    return v === undefined || v === null ? "" : String(v);
  });
}
