import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";
import {
  evidenceSafetyActivity,
  evidenceSafetyLines,
  type EvidenceSafetyFinding,
  type EvidenceSafetyFormat,
} from "../reports/evidenceSafety.js";

// The one line every human-readable export route writes when it ships with evidence-safety
// findings (#1006). Nothing when the export was clean; best-effort, like every activity append.
export function logEvidenceSafety(
  options: Pick<RouteContext["options"], "activityLogStore" | "onActivity">,
  caseId: string,
  format: EvidenceSafetyFormat,
  found: readonly EvidenceSafetyFinding[] | readonly string[],
): void {
  if (found.length === 0) return;
  const lines =
    typeof found[0] === "string"
      ? (found as readonly string[])
      : evidenceSafetyLines(found as EvidenceSafetyFinding[]);
  void logActivity(
    options.activityLogStore,
    options.onActivity,
    caseId,
    evidenceSafetyActivity(format, lines),
  );
}
