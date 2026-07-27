import type { ComplianceControl } from "./complianceControl.js";
import type { ComplianceMapping, ComplianceResult, NotificationClock } from "./complianceMap.js";

// The presentation layer over the raw ATT&CK -> obligation mapping (#336): applies the analyst's
// framework filter and turns each real notification clock into a concrete due date + status.
// Pure — no I/O, no clock reads except the `now` the caller passes, so the dashboard, the report,
// and the tests all compute the same thing.
//
// The honesty constraints this module exists to enforce:
//   - Only rows carrying a `notification` get a deadline. Control cadences (back up, train,
//     review) are NOT deadlines and must never render a countdown.
//   - `unit` is respected: Form 8-K Item 1.05's four days are BUSINESS days; GDPR's 72 hours and
//     HIPAA's 60 days are calendar. Treating them alike silently misstates a legal deadline.
//   - Without an analyst-set `discoveredAt` there are no deadlines at all. The clocks start on a
//     legal determination, not on a forensic timestamp, so there is nothing to count from until a
//     human supplies it.

export interface ComplianceDeadline {
  dueAt: string;
  // Whole days remaining, negative once overdue. Computed in the clock's own unit, so a business
  // -day deadline reports business days.
  remainingDays: number;
  status: "overdue" | "due-soon" | "open";
}

export interface ComplianceMappingView extends ComplianceMapping {
  deadline?: ComplianceDeadline;
}

export interface ComplianceResultView extends Omit<ComplianceResult, "frameworks"> {
  frameworks: ComplianceMappingView[];
}

export interface ComplianceViewOptions {
  control?: ComplianceControl;
  now?: Date;
  // Below this many days remaining, a deadline is "due-soon". Deliberately generous: these are
  // legal clocks, and the useful signal is "this needs counsel now", not "this expires tonight".
  dueSoonDays?: number;
}

const DEFAULT_DUE_SOON_DAYS = 7;
const MS_PER_DAY = 86_400_000;

// ISO-8601 duration -> milliseconds, for the subset the dataset uses: whole days (P4D, P30D,
// P60D) and whole hours (PT72H). Anything else returns null rather than a guess, so an
// unparseable duration degrades to "no countdown" instead of a wrong one.
export function parseDuration(value: string): { days: number } | { hours: number } | null {
  const days = /^P(\d+)D$/.exec(value);
  if (days) return { days: Number(days[1]) };
  const hours = /^PT(\d+)H$/.exec(value);
  if (hours) return { hours: Number(hours[1]) };
  return null;
}

// Add whole business days, skipping Saturday and Sunday. Public holidays are jurisdiction-specific
// (and for Form 8-K, SEC-calendar-specific), so they are NOT modelled — a holiday makes the real
// deadline later than this, never earlier, so the computed date stays conservative.
function addBusinessDays(from: Date, count: number): Date {
  const out = new Date(from.getTime());
  let left = count;
  while (left > 0) {
    out.setUTCDate(out.getUTCDate() + 1);
    const day = out.getUTCDay();
    if (day !== 0 && day !== 6) left--;
  }
  return out;
}

// Whole business days between two instants, negative when `to` is in the past.
function businessDaysBetween(from: Date, to: Date): number {
  const backwards = to.getTime() < from.getTime();
  const [start, end] = backwards ? [to, from] : [from, to];
  const cursor = new Date(start.getTime());
  let count = 0;
  while (cursor.getTime() + MS_PER_DAY <= end.getTime()) {
    cursor.setUTCDate(cursor.getUTCDate() + 1);
    const day = cursor.getUTCDay();
    if (day !== 0 && day !== 6) count++;
  }
  return backwards ? -count : count;
}

export function computeDeadline(
  clock: NotificationClock,
  discoveredAt: string,
  now: Date,
  dueSoonDays: number = DEFAULT_DUE_SOON_DAYS,
): ComplianceDeadline | undefined {
  const startMs = Date.parse(discoveredAt);
  if (Number.isNaN(startMs)) return undefined;
  const parsed = parseDuration(clock.within);
  if (!parsed) return undefined;
  const start = new Date(startMs);

  let due: Date;
  if (clock.unit === "business") {
    // Business-day clocks are only ever expressed in days in this dataset; an hours-based
    // business clock has no agreed meaning, so it gets no countdown.
    if (!("days" in parsed)) return undefined;
    due = addBusinessDays(start, parsed.days);
  } else if ("days" in parsed) {
    due = new Date(startMs + parsed.days * MS_PER_DAY);
  } else {
    due = new Date(startMs + parsed.hours * 3_600_000);
  }

  const remainingDays =
    clock.unit === "business"
      ? businessDaysBetween(now, due)
      : Math.floor((due.getTime() - now.getTime()) / MS_PER_DAY);

  const status: ComplianceDeadline["status"] =
    due.getTime() < now.getTime() ? "overdue" : remainingDays <= dueSoonDays ? "due-soon" : "open";

  return { dueAt: due.toISOString(), remainingDays, status };
}

// The frameworks present in a mapping, in first-seen order — what the UI offers as filter options
// so the list always matches the data rather than a hardcoded roster.
export function availableFrameworks(results: ComplianceResult[]): string[] {
  const seen = new Set<string>();
  for (const r of results) {
    for (const m of r.frameworks) seen.add(String(m.framework));
  }
  return [...seen];
}

// Apply the analyst's framework filter and attach deadlines. A result whose every row is filtered
// out drops entirely, so the caller never renders an empty technique card.
export function buildComplianceView(
  results: ComplianceResult[],
  opts: ComplianceViewOptions = {},
): ComplianceResultView[] {
  const { control = {}, now = new Date(), dueSoonDays = DEFAULT_DUE_SOON_DAYS } = opts;
  // Absent = every framework. An explicit (even empty) array is a deliberate narrowing.
  const allowed = Array.isArray(control.frameworks) ? new Set(control.frameworks) : null;

  const out: ComplianceResultView[] = [];
  for (const result of results) {
    const frameworks: ComplianceMappingView[] = [];
    for (const row of result.frameworks) {
      if (allowed && !allowed.has(String(row.framework))) continue;
      const deadline =
        row.notification && control.discoveredAt
          ? computeDeadline(row.notification, control.discoveredAt, now, dueSoonDays)
          : undefined;
      frameworks.push(deadline ? { ...row, deadline } : { ...row });
    }
    if (frameworks.length) out.push({ ...result, frameworks });
  }
  return out;
}
