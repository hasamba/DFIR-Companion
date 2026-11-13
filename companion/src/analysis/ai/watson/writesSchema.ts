import { z } from "zod";
import type { Severity, StepPriority } from "../../stateTypes.js";
import type { WatsonReportField } from "./writers/writerTypes.js";

// The writes the model proposes in its reply: findings, next steps and report text. Untrusted like
// the rest of the reply: parsed leniently (a bad element is dropped, never the reply), then
// sanitizeWrites caps every list and text and keeps only citations that exist. Nothing here writes;
// each surviving draft becomes a PENDING proposal (roundProposals.ts).

const MAX_FINDINGS = 3;
const MAX_STEPS = 3;
const MAX_REPORT = 2;
const TITLE_MAX = 200;
const DESCRIPTION_MAX = 4000;
const ACTION_MAX = 300;
const RATIONALE_MAX = 500;
const POINTER_MAX = 500;
const REPORT_TEXT_MAX = 6000;
const MAX_CITED = 20;
const MAX_TECHNIQUES = 20;
const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;

export interface WatsonFindingDraft {
  /** A Watson-authored finding this draft updates; absent for a new finding. */
  updateId?: string;
  severity: Severity;
  title: string;
  description: string;
  mitreTechniques: string[];
  eventIds: string[];
  pasteLines: { pasteId: string; line: number }[];
}

export interface WatsonStepDraft {
  priority: StepPriority;
  action: string;
  rationale: string;
  pointer: string;
}

export interface WatsonWrites {
  findings: WatsonFindingDraft[];
  nextSteps: WatsonStepDraft[];
  report: { field: WatsonReportField; text: string }[];
}

/** What a finding draft may cite: each stored paste's line count, and the Watson-authored finding ids. */
export interface WatsonCitationSets {
  pasteLines: ReadonlyMap<string, number>;
  watsonFindingIds: ReadonlySet<string>;
}

export const emptyWrites = (): WatsonWrites => ({ findings: [], nextSteps: [], report: [] });

const str = z.string().catch("");

/** Parse an array element by element: a bad element is dropped, the valid ones stay. */
export function lenientArray<T extends z.ZodTypeAny>(element: T) {
  return z
    .array(z.unknown())
    .catch([])
    .transform((items) =>
      items.flatMap((item) => {
        const parsed = element.safeParse(item);
        return parsed.success ? [parsed.data as z.infer<T>] : [];
      }),
    );
}

const findingDraftSchema = z.object({
  updateId: z.string().optional().catch(undefined),
  severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).catch("Medium"),
  title: str,
  description: str,
  mitreTechniques: lenientArray(z.string()),
  eventIds: lenientArray(z.string()),
  pasteLines: lenientArray(z.object({ pasteId: z.string(), line: z.number() })),
});

const stepDraftSchema = z.object({
  priority: z.enum(["critical", "high", "medium", "low"]).catch("medium"),
  action: str,
  rationale: str,
  pointer: str,
});

export const writesSchema = z
  .object({
    findings: lenientArray(findingDraftSchema),
    nextSteps: lenientArray(stepDraftSchema),
    report: lenientArray(
      z.object({ field: z.enum(["conclusions", "investigationLimitations"]), text: z.string() }),
    ),
  })
  .catch(() => emptyWrites());

const NO_SETS: WatsonCitationSets = { pasteLines: new Map(), watsonFindingIds: new Set() };

function sanitizeFinding(
  d: WatsonFindingDraft,
  knownEventIds: ReadonlySet<string>,
  sets: WatsonCitationSets,
): WatsonFindingDraft | null {
  if (d.title.trim() === "") return null;
  // An update to a finding Watson did not write (or that does not exist) is dropped, never turned
  // into a new finding: that would be a near-duplicate of the synthesis finding it named.
  if (d.updateId && !sets.watsonFindingIds.has(d.updateId)) return null;
  const eventIds = [...new Set(d.eventIds.filter((id) => knownEventIds.has(id)))].slice(0, MAX_CITED);
  const seen = new Set<string>();
  const pasteLines = d.pasteLines
    .filter(({ pasteId, line }) => {
      const lines = sets.pasteLines.get(pasteId);
      const key = `${pasteId}:${line}`;
      if (lines === undefined || !Number.isInteger(line) || line < 1 || line > lines || seen.has(key))
        return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_CITED);
  // A finding with no valid citation is never proposed (spec §6).
  if (!eventIds.length && !pasteLines.length) return null;
  const { updateId, ...rest } = d;
  return {
    ...rest,
    ...(updateId ? { updateId } : {}),
    title: d.title.slice(0, TITLE_MAX),
    description: d.description.slice(0, DESCRIPTION_MAX),
    mitreTechniques: [
      ...new Set(d.mitreTechniques.map((t) => t.trim()).filter((t) => TECHNIQUE.test(t))),
    ].slice(0, MAX_TECHNIQUES),
    eventIds,
    pasteLines: pasteLines.map(({ pasteId, line }) => ({ pasteId, line })),
  };
}

/**
 * Caps and citation checks. `eventIds` are kept only when in the forensic timeline, `pasteLines` only
 * for a stored paste and a line it has; a draft whose `updateId` is not a Watson-authored finding is
 * dropped. Without the citation sets no paste line and no update survives. One report item per field.
 */
export function sanitizeWrites(
  w: WatsonWrites,
  knownEventIds: ReadonlySet<string>,
  sets: WatsonCitationSets = NO_SETS,
): WatsonWrites {
  const findings = w.findings
    .flatMap((d) => sanitizeFinding(d, knownEventIds, sets) ?? [])
    .slice(0, MAX_FINDINGS);
  const nextSteps = w.nextSteps
    .filter((s) => s.action.trim() !== "")
    .slice(0, MAX_STEPS)
    .map((s) => ({
      priority: s.priority,
      action: s.action.slice(0, ACTION_MAX),
      rationale: s.rationale.slice(0, RATIONALE_MAX),
      pointer: s.pointer.slice(0, POINTER_MAX),
    }));
  const fields = new Set<WatsonReportField>();
  const report = w.report
    .filter((r) => {
      if (r.text.trim() === "" || fields.has(r.field)) return false;
      fields.add(r.field);
      return true;
    })
    .slice(0, MAX_REPORT)
    .map((r) => ({ field: r.field, text: r.text.slice(0, REPORT_TEXT_MAX) }));
  return { findings, nextSteps, report };
}
