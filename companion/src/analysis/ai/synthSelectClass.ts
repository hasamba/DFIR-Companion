/**
 * Why an event earned a synthesis seat. "anchor" = Critical/High verdict; "earliest" = initial-access
 * context; "command" = a reserved seat for a quiet session command (#1622); "account" = a reserved seat
 * for an account logon (#2014), which the prompt builder relabels from "command" after selection; the
 * rest are the behavioral fills. Exposed (via the annotated selection) so the dashboard can show the
 * analyst what CLASSES of evidence the model actually saw.
 */
export type SelectionClass =
  | "anchor"
  | "earliest"
  | "command"
  | "account"
  | "anchor_context"
  | "corroborated"
  | "technique"
  | "rare"
  | "spread";

export function emptyCounts(): Record<SelectionClass, number> {
  return {
    anchor: 0,
    earliest: 0,
    command: 0,
    account: 0,
    anchor_context: 0,
    corroborated: 0,
    technique: 0,
    rare: 0,
    spread: 0,
  };
}
