import request from "supertest";
import { pollFor } from "./poll.js";

/**
 * Wait for an activity-log entry to appear after the mutation that writes it has already responded.
 *
 * logActivity is DELIBERATELY FIRE-AND-FORGET — `void logActivity(...)` in the routes — so that a
 * failed log write can never fail the analyst's request. 68 of the 77 call sites are written that
 * way. The consequence is that the response can be sent before the entry lands, and reading the log
 * straight after the POST races the write: it wins on a fast dev box and loses on contended CI.
 *
 * SO THE WAIT IS THE CORRECT ASSERTION, not a workaround for one. The nine routes that DO await
 * their append are the ones the dashboard re-reads the moment they respond, and those are pinned
 * separately by activityLogReadAfterWrite.test.ts against a deliberately slowed store, so dropping
 * one of those awaits fails every run. A caller reaching for this helper is saying the opposite: no
 * client reads this log synchronously, so the entry is allowed to arrive a moment later.
 *
 * The budget is WALL-CLOCK, via pollFor. A fixed attempt count reports a timeout as a missing entry
 * — the same symptom the lost write produces — which is how #408 and #489 both got filed as
 * mysteries rather than as the one-line races they were.
 */
export async function awaitActivityEntry(
  app: Parameters<typeof request>[0],
  caseId: string,
  action: string,
): Promise<{ action: string; detail?: string }> {
  let seen: string[] = [];
  return pollFor(
    () => `an activity-log entry for "${action}" on case ${caseId}, saw only [${seen.join(", ")}]`,
    async () => {
      const log = await request(app).get(`/cases/${caseId}/activity-log`);
      const entries = log.body as { action: string; detail?: string }[];
      seen = entries.map((e) => e.action);
      return entries.find((e) => e.action === action);
    },
  );
}

/**
 * Every activity-log entry for one action, once at least one has arrived.
 *
 * The count matters where a test is proving a mutation logs ONCE — a duplicate entry is a real
 * defect, and asserting on the first match alone would miss it.
 */
export async function awaitActivityEntries(
  app: Parameters<typeof request>[0],
  caseId: string,
  action: string,
): Promise<{ action: string; detail?: string }[]> {
  await awaitActivityEntry(app, caseId, action);
  const log = await request(app).get(`/cases/${caseId}/activity-log`);
  return (log.body as { action: string; detail?: string }[]).filter((e) => e.action === action);
}
