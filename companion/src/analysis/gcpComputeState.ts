// The bounded state of the GCP instance compute-lifecycle pass (#931 item 8 second half, #1066) —
// the constants, the typed per-instance accumulator, the small readers of a GCP Cloud Audit Log
// record, and the words shared by the pass (gcpCompute.ts) and the row (gcpComputeRow.ts). Mirrors
// awsComputeState.ts's shape; kept as its own file rather than shared with AWS's or Azure's, since
// each provider's Row/identity conventions differ.

import type { Severity } from "./stateTypes.js";
import type { GcpComputeFact, GcpComputeLaunch, GcpComputeOperation } from "./canonicalGcpCompute.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, isObject, str } from "./siemImport.js";

export type Row = Record<string, unknown>;

export const GCP_COMPUTE_MAX = 256;
/** Instances tracked per upload; further instance ids are counted, never tracked. */
export const INSTANCES_TRACKED_MAX = 4096;
export const OPERATIONS_EARLY_MAX = 24;
export const OPERATIONS_LATE_MAX = 8;
export const METADATA_KEYS_MAX = 16;
export const ATTACHMENTS_MAX = 16;
export const SESSION_CITED_MAX = 8;
export const OPERATIONS_NAMED_MAX = 8;
export const RAW_RECORDS_MAX = 256;
export const NAME_MAX = 80;
export const DESCRIPTION_MAX = 1400;
export const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
export const LIMIT_NOTE =
  "what ran on the instance and its network egress are not in this case's GCP Cloud Audit Log exports; no firewall/tag join is made and an attached email is never claimed unique to this instance — see #1073";
export const COVERAGE_NOTE = "record retention and export filtering are not in this evidence";
export const BASIS =
  "records of this upload only; joined through the instance's resource name; what ran on the instance and its network egress are not in this case's GCP Cloud Audit Log exports; no firewall/tag join is made and an attached email is never claimed unique to this instance — see #1073";
/** The full documented GCE resourceName shape — `projectRefOf` (gcpIdentity.ts) parses only the leading scope, not this tail. */
const INSTANCE_RESOURCE_NAME = /^projects\/([^/]+)\/zones\/([^/]+)\/instances\/([^/]+)$/i;
export const FACT_WORDS: Record<GcpComputeFact, string> = {
  "metadata-replaced": "metadata replaced after the launch",
  "service-account-attached": "service account recorded as attached to the instance",
  "session-privileged-change":
    "a call from the attached service account matched a High entry in the shared GCP_RULES table (not necessarily the record's own final imported severity)",
};
export const FACT_MITRE: Record<GcpComputeFact, string> = {
  "metadata-replaced": "T1578.005",
  "service-account-attached": "T1098.001",
  "session-privileged-change": "T1098",
};

const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;
export const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
export const lower = (s: string): string => s.trim().toLowerCase();
export const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
export const field = (o: unknown, ...keys: string[]): string => {
  let cur: unknown = o;
  for (const k of keys) cur = isObject(cur) ? getCI(cur, k) : undefined;
  return str(cur).trim();
};

/**
 * An instance's `(project, zone, instanceName)`, parsed from the record's own `resourceName` —
 * ONLY the documented full `projects/<p>/zones/<z>/instances/<n>` shape. A record whose
 * `resourceName` does not parse to this exact shape is not tracked — never guessed from
 * `request.name` alone, which carries no project/zone (Codex design round 1, finding #9). This is
 * a deliberately conservative choice pending a real captured export to verify against.
 */
export function parseGcpInstanceResourceName(
  resourceName: string,
): { project: string; zone: string; instanceName: string } | null {
  const m = INSTANCE_RESOURCE_NAME.exec(resourceName.trim());
  if (!m) return null;
  return { project: m[1], zone: m[2], instanceName: m[3] };
}

export const instanceKey = (project: string, zone: string, instanceName: string): string =>
  `${lower(project)}|${lower(zone)}|${lower(instanceName)}`;

/**
 * The SAME `status.code`-present-and-non-zero convention `decodeGcpWorkloadAttachment`
 * (gcpWorkloadAttachment.ts, #1065) already uses — reused verbatim rather than `mapGcp`'s own
 * numeric conversion, so the two GCP-reading code paths can never quietly disagree about what
 * "success" means (Codex design round 1, finding #13).
 */
export const gcpAttemptOutcome = (pp: Row): "success" | "not-succeeded" => {
  const code = field(pp, "status", "code");
  return !code || code === "0" ? "success" : "not-succeeded";
};

export interface Timed {
  time: number;
}
export class EdgeBuffer<T extends Timed> {
  early: T[] = [];
  late: T[] = [];
  count = 0;
  constructor(
    private readonly earlyMax: number,
    private readonly lateMax: number,
  ) {}
  push(v: T): void {
    this.count += 1;
    insertSorted(this.early, v);
    if (this.early.length > this.earlyMax) {
      const spilled = this.early.pop()!;
      insertSorted(this.late, spilled);
      if (this.late.length > this.lateMax) this.late.shift();
    }
  }
  all(): T[] {
    return [...this.early, ...this.late];
  }
  get beyond(): number {
    return this.count - this.early.length - this.late.length;
  }
}
export const byTime = (a: Timed, b: Timed): number =>
  a.time - b.time ||
  (a as { locator?: string }).locator?.localeCompare((b as { locator?: string }).locator ?? "") ||
  0;
export function insertSorted<T extends Timed>(buf: T[], v: T): void {
  let i = buf.length;
  while (i > 0 && byTime(buf[i - 1], v) > 0) i -= 1;
  buf.splice(i, 0, v);
}

export interface Cited {
  time: number;
  locator: string;
}
export type Operation = Omit<GcpComputeOperation, "time"> & Timed;
/** One open-or-closed attachment interval — `to` absent while still open. */
export interface Attachment extends Timed {
  email: string;
  to: number | null;
  locator: string;
}
export interface SessionTally {
  email: string;
  /** The interval's own start time (ms) — disambiguates two sessions for the same re-attached email. */
  attachmentFrom: number;
  records: number;
  first: Cited | null;
  last: Cited | null;
  cited: { call: string; time: number; locator: string }[];
}

export interface Instance {
  project: string;
  zone: string;
  instanceName: string;
  launch: (Omit<GcpComputeLaunch, "time"> & Timed) | null;
  operations: EdgeBuffer<Operation>;
  attachments: Attachment[];
  attachmentsBeyond: number;
  sessions: Map<string, SessionTally>;
  sessionsBeyond: number;
  notSucceeded: number;
  facts: Map<GcpComputeFact, Cited>;
  /** Locators already counted toward `contributing` — cite() is idempotent per locator, since one
   * record (e.g. an insert that also attaches a service account) can be cited from two code paths. */
  citedSet: Set<string>;
  locators: string[];
  contributing: number;
}

export interface Tracked {
  instances: Map<string, Instance>;
  untrackedRecords: number;
}

export function instanceFor(
  t: Tracked,
  project: string,
  zone: string,
  instanceName: string,
): Instance | null {
  const key = instanceKey(project, zone, instanceName);
  const cur = t.instances.get(key);
  if (cur) return cur;
  if (t.instances.size >= INSTANCES_TRACKED_MAX) {
    t.untrackedRecords += 1;
    return null;
  }
  const inst: Instance = {
    project: lower(project),
    zone: lower(zone),
    instanceName,
    launch: null,
    operations: new EdgeBuffer(OPERATIONS_EARLY_MAX, OPERATIONS_LATE_MAX),
    attachments: [],
    attachmentsBeyond: 0,
    sessions: new Map(),
    sessionsBeyond: 0,
    notSucceeded: 0,
    facts: new Map(),
    citedSet: new Set(),
    locators: [],
    contributing: 0,
  };
  t.instances.set(key, inst);
  return inst;
}

/** Idempotent per locator — a single record (e.g. an insert that also attaches a service
 * account) can be cited from more than one code path in the same pass; it must count once. */
export const cite = (inst: Instance, locator: string): void => {
  if (inst.citedSet.has(locator)) return;
  inst.citedSet.add(locator);
  inst.contributing += 1;
  if (inst.locators.length < RAW_RECORDS_MAX) inst.locators.push(locator);
};

export const noteFact = (inst: Instance, fact: GcpComputeFact, time: number, locator: string): void => {
  const cur = inst.facts.get(fact);
  if (!cur || time < cur.time) inst.facts.set(fact, { time, locator });
};

/** Opens a new interval at `time` for `email`, closing whatever interval was open beforehand. */
export function openAttachment(inst: Instance, email: string, time: number, locator: string): void {
  const open = inst.attachments.find((a) => a.to === null);
  if (open) open.to = time;
  if (inst.attachments.length >= ATTACHMENTS_MAX) {
    inst.attachmentsBeyond += 1;
    return;
  }
  inst.attachments.push({ email, time, to: null, locator });
}

/** Closes whatever interval is open, without opening a new one — a recorded detachment. */
export function closeAttachment(inst: Instance, time: number): void {
  const open = inst.attachments.find((a) => a.to === null);
  if (open) open.to = time;
}

/**
 * The instance's own attachment interval covering `email` at `time` — or `null`. Returns the
 * INTERVAL, not a boolean, so a session tally can be keyed per interval: an account attached,
 * detached, then reattached later is two intervals, and their calls must never merge into one
 * session whose first→last range spans the detached gap (Codex code review, finding #5).
 */
export function attachedInterval(inst: Instance, email: string, time: number): Attachment | null {
  return (
    inst.attachments.find(
      (a) => lower(a.email) === lower(email) && a.time <= time && (a.to === null || time < a.to),
    ) ?? null
  );
}

/** Sessions tracked per instance; further distinct intervals are counted, never tracked. */
export const SESSIONS_MAX = 8;

export function tallySession(
  inst: Instance,
  interval: Attachment,
  time: number,
  locator: string,
  call: string,
): void {
  const key = `${lower(interval.email)}@${interval.time}`;
  let s = inst.sessions.get(key);
  if (!s) {
    if (inst.sessions.size >= SESSIONS_MAX) {
      inst.sessionsBeyond += 1;
      return;
    }
    s = {
      email: interval.email,
      attachmentFrom: interval.time,
      records: 0,
      first: null,
      last: null,
      cited: [],
    };
    inst.sessions.set(key, s);
  }
  s.records += 1;
  if (!s.first || time < s.first.time) s.first = { time, locator };
  if (!s.last || time > s.last.time) s.last = { time, locator };
  if (s.cited.length < SESSION_CITED_MAX) s.cited.push({ call, time, locator });
}

export const firstTime = (inst: Instance): number =>
  Math.min(
    ...[
      inst.launch?.time,
      inst.operations.all()[0]?.time,
      inst.attachments[0]?.time,
      ...[...inst.facts.values()].map((f) => f.time),
    ].filter((t): t is number => t !== undefined),
    Number.MAX_SAFE_INTEGER,
  );
