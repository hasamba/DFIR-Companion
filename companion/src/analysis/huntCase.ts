import { applyIncidentTypeToState, isHuntType, type IncidentType } from "./incidentTypes.js";
import type { InvestigationState } from "./stateTypes.js";

/** The built-in report template a hunt case defaults to (reports/reportTemplate.ts defines it). */
export const HUNT_REPORT_TEMPLATE_ID = "threat-hunt-summary";
/** The report template a case has when nobody picked one (reports/reportTemplate.ts). */
const STANDARD_TEMPLATE_ID = "standard";

/**
 * Hunt-case lifecycle helpers (#2670): the report a hunt case defaults to, and "Convert to incident".
 *
 * Conversion keeps every piece of evidence and analyst work. It switches the case's incident type
 * (MERGING the new type's questions and next steps, never replacing), records which hunt type it came
 * from, and the caller marks the existing AI conclusions out of date so the next synthesis re-frames
 * the case as an incident.
 */

/** Where the selected report template lives (ReportTemplateControlStore's shape). */
export interface TemplateControl {
  load(caseId: string): Promise<{ templateId: string }>;
  set(caseId: string, patch: { templateId: string }): Promise<unknown>;
}

/** A hunt case defaults to the Threat hunt summary — unless the analyst already picked a template. */
export async function applyHuntDefaults(
  control: TemplateControl | undefined,
  caseId: string,
  type: IncidentType | null,
): Promise<boolean> {
  if (!control || !isHuntType(type)) return false;
  const current = await control.load(caseId);
  if (current.templateId && current.templateId !== STANDARD_TEMPLATE_ID) return false;
  await control.set(caseId, { templateId: HUNT_REPORT_TEMPLATE_ID });
  return true;
}

/** The incident type a conversion lands on when the analyst names none. */
export const DEFAULT_CONVERT_TYPE_ID = "intrusion";

export type ConvertRefusal = "not-hunt" | "target-is-hunt" | "unknown-target";

/** Why a conversion cannot happen, or null when it can. Pure. */
export function convertRefusal(
  current: IncidentType | null,
  target: IncidentType | null,
): ConvertRefusal | null {
  if (!isHuntType(current)) return "not-hunt";
  if (!target) return "unknown-target";
  if (isHuntType(target)) return "target-is-hunt";
  return null;
}

/** The converted state: the incident type's seeds merged in, nothing removed. Pure. */
export function convertedState(
  state: InvestigationState,
  target: IncidentType,
  now: string,
): InvestigationState {
  return applyIncidentTypeToState(state, target, { now: () => now }).state;
}
