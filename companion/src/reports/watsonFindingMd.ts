import type { Finding } from "../analysis/stateTypes.js";
import { oneLineMd } from "./mdText.js";

/**
 * The line a Watson-written finding carries in the report: who approved it. `approvedBy` is the
 * analyst's name as typed in the dashboard, so it goes through oneLineMd like any other free text.
 * An older finding applied before the name was recorded still says an analyst approved it.
 */
export function watsonApprovalLine(f: Finding): string {
  const who = f.approvedBy ? oneLineMd(f.approvedBy) : "an analyst";
  return `- Added by Watson, approved by ${who}`;
}
