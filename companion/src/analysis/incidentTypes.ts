import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { InvestigationState, InvestigationQuestion, NextStep } from "./stateTypes.js";
import {
  buildInitialQuestions,
  buildInitialNextSteps,
  type CaseTemplate,
} from "./templateStore.js";

// Incident-type auto-playbooks (#236). A richer CaseTemplate: the template carries the GENERIC case
// skeleton (questions, next steps, recommended imports, hunt platforms); an IncidentType extends it
// with the per-type investigation GUIDANCE that auto-configures a case for a recurring incident
// pattern (ransomware, BEC, exfil, …). Because IncidentType extends CaseTemplate, an incident type
// IS a case template — the New Case dialog offers a single picker over both (the built-in template
// ids ransomware/bec/insider-threat are the same incidents, only thinner).
//
// This module is PURE — no I/O, no AI. The built-in library lives in companion/data/incident-types/
// as one JSON file per type (loaded by incidentTypesData.ts); per-case persistence of the chosen
// type lives in incidentTypeStore.ts. Custom analyst-defined types flow through the same schema and
// the same apply path, so there is exactly one validation and one mutation to reason about.
//
// Guidance fields and where they are consumed:
//   - findingsSeeds          — pre-seeded confirm/deny key questions (consumed here, at apply).
//   - synthesisHint          — one-line framing read by the synthesis prompt (pipeline.ts) from the
//                              per-case record. NOT stored in state.lastSummary: that field is the
//                              analyst-facing case summary and the report's executive-summary
//                              fallback, so a prompt hint written there would print as the executive
//                              summary of a forensic report.
//   - recommendedImportOrder — ordered import checklist for the Import panel.  ─┐ defined and served
//   - huntBundles            — pre-selected Velociraptor bundle ids.            ├─ over the API, not
//   - reportFraming          — report template + exec-summary audience.        ─┘ yet consumed (#347).

export type IncidentTypeId =
  | "ransomware"
  | "bec"
  | "data-exfiltration"
  | "intrusion"
  | "insider-threat"
  | "cloud-compromise"
  | "web-app-intrusion"
  | "malware-outbreak";

// Presentation order for the built-in library — the loader reads a directory, whose entries arrive
// alphabetically, but the pickers should lead with the incident types analysts meet most often.
export const BUILT_IN_INCIDENT_TYPE_IDS: readonly IncidentTypeId[] = [
  "ransomware",
  "bec",
  "data-exfiltration",
  "intrusion",
  "insider-threat",
  "cloud-compromise",
  "web-app-intrusion",
  "malware-outbreak",
];

export interface IncidentTypeReportFraming {
  template: string;          // report template id/name to pre-select
  audience: string;          // executive-summary audience, e.g. "board + insurer"
  summaryPrompt: string;     // a one-line framing prompt for the exec summary
}

// An incident type IS a case template plus the type-specific guidance fields.
export interface IncidentType extends CaseTemplate {
  recommendedImportOrder: string[];   // ordered importer labels, e.g. ["edr","dc-logs","network"]
  huntBundles: string[];              // pre-selected Velociraptor bundle ids
  findingsSeeds: string[];            // expected finding categories, pre-seeded as open questions
  reportFraming: IncidentTypeReportFraming;
  synthesisHint: string;              // one-line context for the synthesis prompt
}

const severitySchema = z.enum(["Critical", "High", "Medium", "Low", "Info"]);
const prioritySchema = z.enum(["critical", "high", "medium", "low"]);

// Validation for BOTH the bundled built-ins and analyst-authored custom types — a hand-edited file
// must not be able to inject a malformed type into the apply path. `id` and `name` are required
// (a type with neither is unusable and unpresentable); everything else degrades to an empty default
// so one bad field doesn't discard an otherwise-good definition.
export const incidentTypeSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().catch(""),
  builtIn: z.boolean().catch(false),
  recommendedImports: z.array(z.string()).catch([]),
  initialKeyQuestions: z.array(z.string()).catch([]),
  initialNextSteps: z.array(z.object({
    action: z.string(),
    priority: prioritySchema,
    rationale: z.string().catch(""),
    pointer: z.string().catch(""),
  })).catch([]),
  severityFloor: severitySchema.nullable().catch(null),
  huntPlatforms: z.array(z.string()).catch([]),
  recommendedImportOrder: z.array(z.string()).catch([]),
  huntBundles: z.array(z.string()).catch([]),
  findingsSeeds: z.array(z.string()).catch([]),
  reportFraming: z.object({
    template: z.string().catch(""),
    audience: z.string().catch(""),
    summaryPrompt: z.string().catch(""),
  }).catch({ template: "", audience: "", summaryPrompt: "" }),
  synthesisHint: z.string().catch(""),
});

// Parse one candidate definition, returning null rather than throwing — callers list a directory of
// analyst-editable files and must never crash the whole listing over a single bad one.
export function parseIncidentType(raw: unknown): IncidentType | null {
  const parsed = incidentTypeSchema.safeParse(raw);
  return parsed.success ? (parsed.data as IncidentType) : null;
}

// The prefix that marks a key question as seeded by an incident type rather than written by the
// analyst — the dashboard badges these, and the analyst can dismiss one as N/A.
export const TYPE_SEED_PREFIX = "[type-seed]";

export interface ApplyIncidentTypeOptions {
  now?: () => string;
  // When true, REPLACES existing key questions / next steps with the type's. When false (default),
  // MERGES — preserves analyst-added entries and only adds the type's seeds that aren't already
  // present (matched by exact question/action text). Merge is the default everywhere, including at
  // case creation: a template may already have seeded the fresh state, and discarding its questions
  // silently loses what the analyst picked.
  replace?: boolean;
}

export interface ApplyIncidentTypeResult {
  state: InvestigationState;
  questionsAdded: number;
  nextStepsAdded: number;
}

// Apply an incident type's auto-configuration to an InvestigationState:
//   - pre-populates key questions (the type's initialKeyQuestions)
//   - pre-populates next steps (the type's initialNextSteps)
//   - pre-seeds findingsSeeds as open confirm/deny key questions, so the analyst confirms or denies
//     each expected finding category rather than starting from a blank slate
//
// Deliberately does NOT touch state.lastSummary — see the module header. The synthesis hint reaches
// the AI from the per-case incident-type record, read by the synthesis prompt.
//
// Pure: returns a new state; never mutates the input. Does not persist (the caller does).
export function applyIncidentTypeToState(
  state: InvestigationState,
  type: IncidentType,
  opts: ApplyIncidentTypeOptions = {},
): ApplyIncidentTypeResult {
  const now = opts.now ?? (() => new Date().toISOString());
  const replace = opts.replace ?? false;

  const seedFindingsQuestions: InvestigationQuestion[] = type.findingsSeeds.map((label) => ({
    id: randomUUID(),
    question: `${TYPE_SEED_PREFIX} Confirm or deny: ${label}`,
    status: "unknown" as const,
    answer: "",
    pointer: "",
    pinned: true,
  }));
  const allSeedQuestions = [...buildInitialQuestions(type), ...seedFindingsQuestions];
  const seedNextSteps: NextStep[] = buildInitialNextSteps(type);

  let questions: InvestigationQuestion[];
  let nextSteps: NextStep[];
  let questionsAdded: number;
  let nextStepsAdded: number;

  if (replace) {
    questions = allSeedQuestions;
    nextSteps = seedNextSteps;
    questionsAdded = allSeedQuestions.length;
    nextStepsAdded = seedNextSteps.length;
  } else {
    const existingQ = new Set(state.keyQuestions.map((q) => q.question));
    const newQ = allSeedQuestions.filter((q) => !existingQ.has(q.question));
    questionsAdded = newQ.length;
    questions = [...state.keyQuestions, ...newQ];

    const existingSteps = new Set(state.nextSteps.map((s) => s.action));
    const newSteps = seedNextSteps.filter((s) => !existingSteps.has(s.action));
    nextStepsAdded = newSteps.length;
    nextSteps = [...state.nextSteps, ...newSteps];
  }

  const next: InvestigationState = {
    ...state,
    keyQuestions: questions,
    nextSteps,
    updatedAt: now(),
  };
  return { state: next, questionsAdded, nextStepsAdded };
}

// Render the type's synthesis hint as a prompt block for the synthesis pass, so the AI prioritizes
// the techniques that matter for this incident type. Returns "" for no type or an empty hint, so the
// caller can concatenate it unconditionally and it costs nothing when unset.
export function renderIncidentTypeBlock(type: IncidentType | null | undefined): string {
  const hint = type?.synthesisHint?.trim();
  if (!type || !hint) return "";
  return `INCIDENT TYPE: ${type.name}. ${hint}\n\n`;
}
