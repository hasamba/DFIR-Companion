// Dashboard view presets (#142) — named, role- and phase-keyed layouts that toggle, order,
// and filter the EXISTING dashboard panels. This is pure config + the one genuinely new
// mechanic (a per-view severity/top-N filter). The dashboard fetches these via
// `GET /dashboard-views` and applies them client-side, reusing the section show/hide + reorder
// machinery already in `public/dashboard.html` (`SECTIONS_VIS_KEY` / `SECTIONS_ORDER_KEY`).
//
// INVARIANT: `sections` lists the section ids that are VISIBLE, in display order; any section id
// not listed is hidden. Every id must be in `DASHBOARD_SECTION_IDS`, and every `reportTemplateId`
// must be a built-in report template id — both are asserted by the unit test.

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
  "sec-gaps",
  "sec-swimlane",
  "sec-assets",
  "sec-evidence",
  "sec-beacons",
  "sec-iocs",
  "sec-exposure",
  "sec-questions",
  "sec-threads",
  "sec-mitre",
  "sec-adversary",
  "sec-legitimate",
  "sec-hypotheses",
  "sec-notebook",
  "sec-inv-log",
  "sec-case-details",
];

export const BUILT_IN_DASHBOARD_VIEWS: readonly DashboardView[] = [
  {
    id: "analyst",
    name: "Analyst",
    description: "Dense, everything visible — deep investigation. No severity filter.",
    sections: [...DASHBOARD_SECTION_IDS],
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
      "sec-gaps",
      "sec-questions",
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
      "sec-swimlane",
      "sec-findings",
      "sec-kill-chain",
      "sec-phases",
      "sec-beacons",
      "sec-iocs",
      "sec-gaps",
      "sec-questions",
      "sec-threads",
      "sec-mitre",
      "sec-adversary",
      "sec-hypotheses",
      "sec-notebook",
    ],
    defaultSort: "time",
    reportTemplateId: "technical-detailed",
  },
  {
    id: "hunt-prep",
    name: "Hunt Prep",
    description: "Planning collections — playbook, next steps, ATT&CK and adversary hints to drive hunts.",
    sections: [
      "sec-playbook",
      "sec-next-steps",
      "sec-findings",
      "sec-mitre",
      "sec-adversary",
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
