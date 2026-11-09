// CloudTrail's veto on Sigma raising severity (#2351). Pure.
//
// The importer grades a logging / AWS Config call that failed because its target was not found
// down to Low: it positively established that the request changed nothing (#1081). A Sigma rule
// that selects on the event name alone (aws_config_disable_recording, high) cannot see that, and
// would lift the row back to High. This veto keeps the importer's grade for exactly that row.
//
// - Keyed on the importer's own verdict (the logging-change block's `failure`), never on a list of
//   rules or error codes, so it covers every rule and every release the same way.
// - Only not-found: a denied or otherwise failed attempt can still be raised (a probe signal).
// - A rule whose condition REQUIRES an `errorCode` value already decided about failures, so it still
//   grades. A rule that only excludes an error code (`selection and not filter` with
//   `errorCode: AccessDenied`) or only asks whether there is an error (`errorCode|exists`) has not
//   decided about not-found, so the veto holds for it (#2499, the Suzaku rules).
// - A vetoed match still tags the row (title, ATT&CK, rule line) — the seam adds the note.

import type { MappedEvent } from "./siemImport.js";
import type { SigmaRuleRef } from "./sigmaRuleSet.js";

export interface SigmaGradeVeto {
  mayGrade: (ref: SigmaRuleRef) => boolean;
  note: string;
}

export const CLOUDTRAIL_NOT_FOUND_VETO_NOTE =
  "not graded — the request failed because its target was not found, so it changed nothing; the importer's grade stands";

const filtersOnErrorCode = (ref: SigmaRuleRef): boolean =>
  (ref.requiredFields ?? ref.fields ?? []).includes("errorcode");

/** The veto for one CloudTrail row, or undefined when Sigma may grade it as usual. */
export function cloudTrailSigmaVeto(event: Pick<MappedEvent, "canonical">): SigmaGradeVeto | undefined {
  if (event.canonical?.loggingChange?.failure !== "not-found") return undefined;
  return { mayGrade: filtersOnErrorCode, note: CLOUDTRAIL_NOT_FOUND_VETO_NOTE };
}
