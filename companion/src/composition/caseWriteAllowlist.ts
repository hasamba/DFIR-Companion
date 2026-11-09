/**
 * What a closed or archived case still accepts (#2437), and how a refusal ends its sentence.
 *
 * DENY BY DEFAULT. composition/caseWriteGuard.ts refuses every non-GET request under /cases/:id/ on
 * a frozen case unless it matches FROZEN_CASE_ALLOWLIST below, so a write route added tomorrow is
 * refused on a closed case without anyone remembering to list it. tests/server/
 * frozenCaseDenyByDefault.test.ts walks the live route stack and pins the exact allowed set: adding an
 * entry here is a product decision, and the reason goes next to it.
 *
 * Patterns are matched against the path below /cases/:id, lowercased, trailing slash removed.
 */

type Entry = readonly [method: string, pattern: RegExp];

const SEG = "[^/]+";
const re = (body: string) => new RegExp(`^${body.replace(/:seg/g, SEG)}$`);

/** Reopen, close, archive, restore, delete and the encrypted export: how a case leaves the freeze. */
const LIFECYCLE: Entry[] = [
  ["PATCH", re("/status")],
  ["POST", re("/(archive|restore|delete)")],
  ["POST", re("/export/encrypted")],
];

/**
 * Case password, unlock and "forget this browser's unlock" (/lock), revoking the push key, and the
 * case's cloud credentials (the held-credentials list checks and removes them on closed cases). Only
 * ADDING a new cloud account or a new push key is refused: neither is any use to a frozen case.
 */
const CREDENTIALS: Entry[] = [
  ["POST", re("/(unlock|password|lock)")],
  ["DELETE", re("/password")],
  ["DELETE", re("/push-token")],
  ["POST", re("/cloud-accounts/:seg/(attach|detach|check)")],
  ["PUT", re("/cloud-accounts/:seg")],
  ["DELETE", re("/cloud-accounts/:seg")],
];

/** Exports: they write report files or send the case out, and never change its record. */
const EXPORTS: Entry[] = [
  ["POST", re("/report")],
  ["POST", re("/push/(iris|timesketch|timesketch-super|misp|notion|clickup|jira|servicenow)")],
  ["POST", re("/push/(jira|servicenow)/bulk")],
];

/**
 * Reads sent as POST. Each handler was checked to write nothing to the case beyond the activity log,
 * an AI-cost line or a saved hunt's run counter: ephemeral AI answers, previews, syntax checks,
 * searches and cloud probes. /tools/:t/update-rules updates the tool's own rule files, not the case.
 * NOT here, because they persist or promote: /narrative, /questions, /deobfuscate, /events/:e/explain
 * and /starred-report (both promote, CLAUDE.md §7), /customer-exposure/check, /containment-check.
 */
const READS_AS_POST: Entry[] = [
  ["POST", re("/tags/tagger-for")],
  ["POST", re("/false-positive/suggest")],
  ["POST", re("/tagger/(suggest-rule|preview)")],
  ["POST", re("/sigma/(compile|dry-run)")],
  ["POST", re("/translate-query")],
  ["POST", re("/hunt-query/(validate|execute|finding-evidence)")],
  ["POST", re("/timeline-gaps/hypothesize")],
  ["POST", re("/sessions/:seg/summary")],
  ["POST", re("/custody/verify")],
  ["POST", re("/(ask|executive-summary|view-summary|remediation-plan|hypothesis-review)")],
  ["POST", re("/adversary-hints/hunt-technique")],
  ["POST", re("/memory/next-steps")],
  ["POST", re("/velociraptor/(suggest-hunts|hunt-rows)")],
  ["POST", re("/cloud-collect/(precheck|regions)")],
  ["POST", re("/tools/:seg/update-rules")],
];

/**
 * Stopping, or finishing, work that was already running when the case froze (#2404: a running
 * import finishes and is recorded). Imports, dedicated imports and cloud collections finish inside
 * their jobs, not through a route, so they need no entry. poll-status is the manual tick of a hunt
 * that was launched before the close — the same tick the scheduler runs on its own.
 */
const RUNNING_WORK: Entry[] = [
  ["POST", re("/hunt-query/executions/:seg/cancel")],
  ["DELETE", re("/mcp/preview/:seg")],
  ["POST", re("/velociraptor/monitors/:seg/stop")],
  ["DELETE", re("/velociraptor/monitors/:seg")],
  ["POST", re("/velociraptor/hunt-jobs/:seg/poll-status")],
];

/**
 * Passes the gate, refuses itself. POST /push authenticates its push token BEFORE it says anything
 * about the case — answering 423 first would tell a caller with no token that the case exists and is
 * closed (the same reason caseWriteExistsGate.ts lets it through). Its own inline 423 still runs.
 */
const SELF_GUARDED: Entry[] = [["POST", re("/push")]];

/**
 * Owner decision (#2437, 2026-11-09): notes, comments, tags and pins do NOT stay editable after a
 * case is closed or archived — "Reopen the case to annotate it." Kept here as one block so the
 * decision can be reversed by adding ANNOTATIONS to FROZEN_CASE_ALLOWLIST (and the test's list).
 */
export const ANNOTATIONS: readonly Entry[] = [
  ["POST", re("/(notebook|comments|pinned-findings)")],
  ["PATCH", re("/notebook/:seg")],
  ["DELETE", re("/(notebook|comments|pinned-findings)/:seg")],
  ["PUT", re("/pinned-findings/order")],
];

export const FROZEN_CASE_ALLOWLIST: readonly Entry[] = [
  ...LIFECYCLE,
  ...CREDENTIALS,
  ...EXPORTS,
  ...READS_AS_POST,
  ...RUNNING_WORK,
  ...SELF_GUARDED,
];

/**
 * How each refusal ends its sentence, so the routes whose inline checks the gate replaced keep their
 * exact wording ("Case "x" is closed — reopen it before running synthesis"). First match wins; any
 * other refused route says "changing it".
 */
const PURPOSES: ReadonlyArray<readonly [method: string, pattern: RegExp, purpose: string]> = [
  ["POST", re("/(events|iocs)"), "adding evidence"],
  ["POST", re("/import(-[a-z0-9-]+)?"), "importing evidence"],
  ["POST", re("/import/:seg"), "changing it"], // undo / redo
  ["POST", re("/drop/run-pending"), "importing evidence"],
  ["POST", re("/velociraptor/(run-bundle|import-external|collect)"), "importing evidence"],
  ["POST", re("/iris-import"), "importing evidence"],
  ["POST", re("/tools/:seg/(run|run-upload)"), "importing evidence"],
  ["POST", re("/mcp/preview/:seg/import"), "importing"],
  ["POST", re("/mcp/agent(-upload)?"), "running the investigation"],
  ["POST", re("/mcp/:seg/(run|run-upload)"), "running a tool"],
  ["POST", re("/synthesize"), "running synthesis"],
  ["POST", re("/deep-pass"), "running a deep pass"],
  ["POST", re("/second-look"), "running a second look"],
  ["POST", re("/jev/promote"), "promoting evidence"],
  ["POST", re("/custody"), "recording custody"],
  ["POST", re("/sigma/regrade"), "re-grading its evidence"],
];

const matches = (method: string, rel: string) => (entry: readonly [string, RegExp, ...unknown[]]) =>
  entry[0] === method && entry[1].test(rel);

/** null when a frozen case accepts this request; otherwise the end of the 423 sentence. */
export function frozenWritePurpose(method: string, rel: string): string | null {
  const m = method.toUpperCase();
  if (FROZEN_CASE_ALLOWLIST.some(matches(m, rel))) return null;
  return PURPOSES.find(matches(m, rel))?.[2] ?? "changing it";
}
