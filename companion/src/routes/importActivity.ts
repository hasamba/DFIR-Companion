import { logActivity, type ActivityLogStore } from "../analysis/activityLog.js";
import type { TimelineDiff } from "../analysis/timelineDiff.js";
import type { IocsDiff } from "../analysis/iocsDiff.js";

/**
 * The 'import' activity-log entry an import writes once it has settled. Shared by POST /import and
 * POST /import-file: the path route was a copy of the text route without this call, so an import by
 * path left no audit-trail entry (#1906). Fire-and-forget like every activity line — a failed append
 * never fails an import that already landed.
 */
export function logImportActivity(
  sink: { activityLogStore?: ActivityLogStore; onActivity?: (caseId: string) => void },
  caseId: string,
  label: string,
  diffs: { timeline: TimelineDiff; iocs: IocsDiff },
): void {
  void logActivity(sink.activityLogStore, sink.onActivity, caseId, {
    category: "import",
    action: "import",
    detail: `${label} — +${diffs.timeline.added.length} event(s), +${diffs.iocs.added.length} IOC(s)`,
  });
}
