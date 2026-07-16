// Dashboard view presets (#142) — named, role- and phase-keyed layouts that toggle, order,
// and filter the EXISTING dashboard panels. This is pure config + the one genuinely new
// mechanic (a per-view severity/top-N filter). The dashboard fetches these via
// `GET /dashboard-views` and applies them client-side, reusing the section show/hide + reorder
// machinery already in `public/dashboard.html` (`SECTIONS_VIS_KEY` / `SECTIONS_ORDER_KEY`).
//
// INVARIANT: `sections` lists the section ids that are VISIBLE, in display order; any section id
// not listed is hidden. Every id must be in `DASHBOARD_SECTION_IDS`, and every `reportTemplateId`
// must be a built-in report template id — both are asserted by the unit test.

import { z } from "zod";
import { BUILT_IN_REPORT_TEMPLATES } from "../reports/reportTemplate.js";

/** Severity labels, most→least severe. Mirrors the dashboard's `SEV` constant. */
export type ViewSeverity = "Critical" | "High" | "Medium" | "Low" | "Info";

const SEVERITY_ORDER: readonly ViewSeverity[] = ["Critical", "High", "Medium", "Low", "Info"];

/** Per-view filtering applied at render time to findings (and the forensic timeline). */
export interface DashboardViewFilters {
  /** Hide findings/events below this severity (inclusive). Omit = show all severities. */
  minSeverity?: ViewSeverity;
  /** Cap the findings list to the N most-severe after sorting. Omit = no cap. */
  topN?: number;
}

export interface DashboardView {
  id: string;
  name: string;
  description: string;
  /** Visible section ids, in display order. Anything omitted is hidden. */
  sections: string[];
  filters?: DashboardViewFilters;
  /** Default sort for the findings list when this view is active. */
  defaultSort?: "time" | "severity";
  /** Built-in report template this view maps onto (exec brief / analyst appendix / lead summary). */
  reportTemplateId?: string;
}

// The user-managed dashboard section ids — mirrors `SECTION_DEFS` in `public/dashboard.html`.
// (Conditionally-shown sections like sec-mem-nextsteps / sec-geomap / sec-huntprofile /
// sec-velohunts are driven by their own logic and are intentionally NOT view-managed.)
export const DASHBOARD_SECTION_IDS: readonly string[] = [
  "sec-ask",
  "sec-nlquery",
  "sec-exec",
  "sec-playbook",
  "sec-attack-path",
  "sec-narrative",
  "sec-findings",
  "sec-next-steps",
  "sec-timeline",
  "sec-kill-chain",
  "sec-phases",
  "sec-hostranking",
  "sec-gaps",
  "sec-evidence-gaps",
  "sec-swimlane",
  "sec-assets",
  "sec-evidence",
  "sec-beacons",
  "sec-anomalies",
  "sec-iocs",
  "sec-exposure",
  "sec-questions",
  "sec-threads",
  "sec-mitre",
  "sec-adversary",
  "sec-d3fend",
  "sec-false-positive",
  "sec-source-trust",
  "sec-hypotheses",
  "sec-super-timeline",
  "sec-notebook",
  "sec-inv-log",
  "sec-activity",
  "sec-case-details",
];

export const BUILT_IN_DASHBOARD_VIEWS: readonly DashboardView[] = [
  {
    // Default view for new installs / any case without a saved per-case preference — see
    // `applySavedViewForCase()` in `public/dashboard.html`.
    id: "analyst",
    name: "Analyst",
    description: "Dense, deep-investigation layout. Default for new cases. No severity filter.",
    sections: [
      "sec-ask",
      "sec-exec",
      "sec-narrative",
      "sec-findings",
      "sec-timeline",
      "sec-super-timeline",
      "sec-iocs",
      "sec-playbook",
      "sec-attack-path",
      "sec-kill-chain",
      "sec-phases",
      "sec-hostranking",
      "sec-gaps",
      "sec-evidence-gaps",
      "sec-swimlane",
      "sec-assets",
      "sec-evidence",
      "sec-beacons",
      "sec-anomalies",
      "sec-exposure",
      "sec-questions",
      "sec-threads",
      "sec-mitre",
      "sec-adversary",
      "sec-d3fend",
      "sec-false-positive",
      "sec-source-trust",
      "sec-hypotheses",
      "sec-notebook",
      "sec-case-details",
    ],
    defaultSort: "time",
    reportTemplateId: "technical-detailed",
  },
  {
    id: "lead",
    name: "Lead",
    description: "Investigation lead — High/Critical findings, playbook progress, gaps and open questions.",
    sections: [
      "sec-exec",
      "sec-findings",
      "sec-playbook",
      "sec-next-steps",
      "sec-d3fend",
      "sec-gaps",
      "sec-evidence-gaps",
      "sec-questions",
      "sec-hostranking",
      "sec-phases",
      "sec-attack-path",
      "sec-timeline",
      "sec-case-details",
    ],
    filters: { minSeverity: "High" },
    defaultSort: "severity",
    reportTemplateId: "standard",
  },
  {
    id: "executive",
    name: "Executive",
    description: "C-suite / legal — narrative, top findings, remediation and scope. Technical detail hidden.",
    sections: [
      "sec-exec",
      "sec-narrative",
      "sec-attack-path",
      "sec-findings",
      "sec-playbook",
      "sec-d3fend",
      "sec-assets",
      "sec-exposure",
      "sec-case-details",
    ],
    filters: { minSeverity: "High", topN: 5 },
    defaultSort: "severity",
    reportTemplateId: "executive-brief",
  },
  {
    id: "triage",
    name: "Triage",
    description: "Initial response — timeline + findings, kill chain and phases. Sorted by severity.",
    sections: [
      "sec-findings",
      "sec-hostranking",
      "sec-timeline",
      "sec-kill-chain",
      "sec-phases",
      "sec-next-steps",
      "sec-iocs",
    ],
    defaultSort: "severity",
    reportTemplateId: "standard",
  },
  {
    id: "report",
    name: "Report",
    description: "Report drafting — exec summary, attacker path, findings, IOCs and metadata. Raw timeline hidden.",
    sections: [
      "sec-exec",
      "sec-narrative",
      "sec-attack-path",
      "sec-findings",
      "sec-mitre",
      "sec-iocs",
      "sec-assets",
      "sec-exposure",
      "sec-questions",
      "sec-case-details",
    ],
    defaultSort: "severity",
    reportTemplateId: "standard",
  },
  {
    id: "deep-dive",
    name: "Deep-Dive",
    description: "Hypothesis testing — timeline + evidence chain large, full detail, comments/tags/threads enabled.",
    sections: [
      "sec-timeline",
      "sec-evidence",
      "sec-assets",
      "sec-hostranking",
      "sec-swimlane",
      "sec-findings",
      "sec-kill-chain",
      "sec-phases",
      "sec-beacons",
      "sec-anomalies",
      "sec-iocs",
      "sec-gaps",
      "sec-evidence-gaps",
      "sec-questions",
      "sec-threads",
      "sec-mitre",
      "sec-adversary",
      "sec-d3fend",
      "sec-hypotheses",
      "sec-super-timeline",
      "sec-false-positive",
      "sec-source-trust",
      "sec-notebook",
      "sec-activity",
    ],
    defaultSort: "time",
    reportTemplateId: "technical-detailed",
  },
  {
    id: "hunt-prep",
    name: "Hunt Prep",
    description: "Planning collections — playbook, next steps, ATT&CK, adversary hints and D3FEND countermeasures to drive hunts.",
    sections: [
      "sec-playbook",
      "sec-next-steps",
      "sec-evidence-gaps",
      "sec-findings",
      "sec-hypotheses",
      "sec-mitre",
      "sec-adversary",
      "sec-d3fend",
      "sec-iocs",
      "sec-timeline",
    ],
    defaultSort: "severity",
    reportTemplateId: "standard",
  },
];

/** Look up a built-in view by id. */
export function getDashboardView(id: string): DashboardView | undefined {
  return BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id);
}

/** Rank of a severity label (0 = most severe); unknown labels rank last. */
export function severityRank(sev: string): number {
  const i = SEVERITY_ORDER.indexOf(sev as ViewSeverity);
  return i < 0 ? SEVERITY_ORDER.length : i;
}

/**
 * True when `sev` is at least as severe as `min`. Fails OPEN: an unknown threshold or an unknown
 * severity is never hidden (missing a real finding is worse than showing one extra).
 */
export function meetsMinSeverity(sev: string, min?: string): boolean {
  if (!min) return true;
  const minIdx = SEVERITY_ORDER.indexOf(min as ViewSeverity);
  if (minIdx < 0) return true;
  const sevIdx = SEVERITY_ORDER.indexOf(sev as ViewSeverity);
  if (sevIdx < 0) return true;
  return sevIdx <= minIdx;
}

/** Built-in report template ids — the set a view's `reportTemplateId` may reference. */
export function builtInReportTemplateIds(): string[] {
  return BUILT_IN_REPORT_TEMPLATES.map((t) => t.id);
}

const VALID_SECTION_IDS = new Set<string>(DASHBOARD_SECTION_IDS);

// Every field is lenient (`.catch`) so a partial / hand-edited file or POST body normalizes instead
// of rejecting — same philosophy as the report-template + AI response schemas.
export const dashboardViewSchema = z.object({
  id: z.string().catch(""),
  name: z.string().catch(""),
  description: z.string().catch(""),
  sections: z.array(z.string()).catch([]),
  filters: z
    .object({
      minSeverity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).optional().catch(undefined),
      topN: z.number().int().positive().max(1000).optional().catch(undefined),
    })
    .catch({}),
  defaultSort: z.enum(["time", "severity"]).catch("severity"),
  reportTemplateId: z.string().optional().catch(undefined),
});

/**
 * Coerce untrusted input (a saved file's contents or a POST body) into a valid DashboardView. Unknown
 * keys are dropped, wrong-typed fields fall back to defaults, and `sections` is filtered to the known
 * section ids (deduped, order preserved) so a bad id can never reach the dashboard. Never throws.
 * NOTE: unlike report templates, omitted sections are NOT back-filled — a view's `sections` list IS
 * exactly what it shows; everything else is hidden by design.
 */
export function normalizeDashboardView(input: unknown): DashboardView {
  const parsed = dashboardViewSchema.safeParse(input ?? {});
  const t = parsed.success ? parsed.data : dashboardViewSchema.parse({});
  const seen = new Set<string>();
  const sections: string[] = [];
  for (const raw of t.sections) {
    const id = typeof raw === "string" ? raw.trim() : "";
    if (!VALID_SECTION_IDS.has(id) || seen.has(id)) continue;
    seen.add(id);
    sections.push(id);
  }
  const filters: DashboardViewFilters = {};
  if (t.filters?.minSeverity) filters.minSeverity = t.filters.minSeverity;
  if (typeof t.filters?.topN === "number") filters.topN = t.filters.topN;
  const id = t.id.trim();
  const reportTemplateId = (t.reportTemplateId ?? "").trim();
  return {
    id,
    name: t.name.trim() || id || "Untitled view",
    description: t.description.trim(),
    sections,
    filters: filters.minSeverity || filters.topN ? filters : undefined,
    defaultSort: t.defaultSort,
    reportTemplateId: reportTemplateId || undefined,
  };
}
