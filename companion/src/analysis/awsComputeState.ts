// The bounded state of the AWS compute lifecycle pass (#931 item 8) — the constants, the typed
// per-instance accumulators (earliest + latest by time, never file order), the small readers of
// a CloudTrail record, and the words shared by the pass (awsCompute.ts) and the row
// (awsComputeRow.ts). Split from the pass so each file stays inside its size bound.

import type { Severity } from "./stateTypes.js";
import type {
  AwsComputeAddress,
  AwsComputeFact,
  AwsComputeLaunch,
  AwsComputeLifecycle,
  AwsComputeRemote,
  AwsComputeRule,
} from "./canonicalAwsCompute.js";
import type { AwsIdentity } from "./awsIdentity.js";
import type { ShapeHit } from "./awsLineage.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, isObject, normalizeTime, str } from "./siemImport.js";

export type Row = Record<string, unknown>;

export const AWS_COMPUTE_MAX = 256;
/** Instances tracked per upload; further instance ids are counted, never tracked. */
export const INSTANCES_TRACKED_MAX = 4096;
/** Lifecycle records retained per instance: the earliest and the latest, the rest counted. */
export const LIFECYCLE_EARLY_MAX = 24;
export const LIFECYCLE_LATE_MAX = 8;
export const GROUPS_MAX = 16;
export const RULES_EARLY_MAX = 16;
export const RULES_LATE_MAX = 16;
export const RULE_SOURCES_PER_RECORD_MAX = 8;
export const ADDRESSES_MAX = 8;
export const REMOTE_MAX = 8;
/** Configuration changes named in the words; the envelope carries every retained one. */
export const CHANGES_NAMED_MAX = 8;
export const RAW_RECORDS_MAX = 256;
export const SOURCES_NAMED_MAX = 8;
export const SHAPES_NAMED_MAX = 6;
export const OVERFLOW_SOURCES_MAX = 1024;
export const NAME_MAX = 80;
export const DESCRIPTION_MAX = 1400;
export const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
export const LIMIT_NOTE = "what ran on the instance and its network egress are not in CloudTrail";
export const COVERAGE_NOTE = "record retention and the trails' selectors are not in this evidence";
export const BASIS =
  "records of this upload only; joined through the instance id; what ran on the instance and its network egress are not in CloudTrail";
export const INSTANCE_ID = /^i-[0-9a-f]{8,17}$/i;
export const ANY_SOURCE = new Set(["0.0.0.0/0", "::/0"]);
export const DENIED = /accessdenied|unauthorized/i;
/** ModifyInstanceAttribute attribute names the row may name; anything else is "other". */
export const ATTRIBUTES = new Set(
  [
    "userData",
    "groupSet",
    "disableApiTermination",
    "disableApiStop",
    "instanceType",
    "kernel",
    "ramdisk",
    "sourceDestCheck",
    "blockDeviceMapping",
    "productCodes",
    "sriovNetSupport",
    "enaSupport",
    "enclaveOptions",
    "instanceInitiatedShutdownBehavior",
    "ebsOptimized",
    "rootDeviceName",
  ].map((a) => a.toLowerCase()),
);
export const FACT_WORDS: Record<AwsComputeFact, string> = {
  "startup-config-replaced": "startup configuration replaced after the launch",
  "profile-changed": "instance profile changed after the launch",
  "any-address-rule": "any-address ingress rule recorded on a group the instance holds",
  "session-privileged-change": "privileged change by the instance-role credentials",
  "session-remote-execution": "remote execution by the instance-role credentials",
  "session-enumeration": "enumeration by the instance-role credentials",
  "remote-access-request": "remote-access request to the instance",
};
export const FACT_MITRE: Record<AwsComputeFact, string> = {
  "startup-config-replaced": "T1578.005",
  "profile-changed": "T1098.003",
  "any-address-rule": "T1562.007",
  "session-privileged-change": "T1098",
  "session-remote-execution": "T1651",
  "session-enumeration": "T1580",
  "remote-access-request": "T1651",
};

const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;
export const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
export const lower = (s: string): string => s.trim().toLowerCase();
export const ms = (s: string): number | null => {
  const t = Date.parse(normalizeTime(s));
  return Number.isFinite(t) ? t : null;
};
export const iso = (t: number): string => new Date(t).toISOString();
export const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
export const field = (o: unknown, ...keys: string[]): string => {
  let cur: unknown = o;
  for (const k of keys) cur = isObject(cur) ? getCI(cur, k) : undefined;
  return str(cur).trim();
};
/** A CloudTrail set: `{ items: [...] }` or a bare array — its object items. */
export const items = (v: unknown): Row[] => {
  const list = Array.isArray(v) ? v : isObject(v) ? getCI(v, "items") : undefined;
  return Array.isArray(list) ? list.filter(isObject) : [];
};
export const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.map((x) => str(x).trim()).filter(Boolean) : str(v).trim() ? [str(v).trim()] : [];
export type Outcome = "success" | "denied" | "failed";
export const outcomeOf = (rec: Row): Outcome => {
  const code = str(getCI(rec, "errorCode")).trim();
  return !code ? "success" : DENIED.test(code) ? "denied" : "failed";
};
export const identityWords = (who: AwsIdentity): string => `${who.kind}${who.arn ? ` ${who.arn}` : ""}`;

// ───────────────────────────── accumulators (bounded) ─────────────────────────────

export interface Timed {
  time: number;
}
/** Earliest N + latest M by time, the rest counted — never file order. */
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
  /** Retained entries in time order, deduplicated. */
  all(): T[] {
    return [...this.early, ...this.late];
  }
  get beyond(): number {
    return this.count - this.early.length - this.late.length;
  }
}
/** Time order with the record position as the tie-breaker — equal timestamps never depend on file order. */
export const byTime = (a: Timed, b: Timed): number =>
  a.time - b.time ||
  (a as { locator?: string }).locator?.localeCompare((b as { locator?: string }).locator ?? "") ||
  0;
export function insertSorted<T extends Timed>(buf: T[], v: T): void {
  let i = buf.length;
  while (i > 0 && byTime(buf[i - 1], v) > 0) i -= 1;
  buf.splice(i, 0, v);
}
/** Keep the earliest `max` entries by time, count the rest. */
export function keepEarliest<T extends Timed>(buf: T[], v: T, max: number): boolean {
  insertSorted(buf, v);
  if (buf.length > max) {
    buf.pop();
    return false;
  }
  return true;
}

export interface Cited {
  time: number;
  locator: string;
}
export interface Source {
  address: string;
  agent: string;
  first: Cited;
  records: number;
}
export type Lifecycle = Omit<AwsComputeLifecycle, "time" | "order"> & Timed;
export type Rule = Omit<AwsComputeRule, "time" | "order"> & Timed;
export type Address = Omit<AwsComputeAddress, "time"> & Timed;
export type Remote = Omit<AwsComputeRemote, "time"> & Timed;
/** One membership statement — the launch's group set, or a successful ModifyInstanceAttribute group set, which REPLACES it. */
export interface GroupSet extends Timed {
  locator: string;
  groups: string[];
}
export interface Inst {
  account: string;
  region: string;
  id: string;
  launch: (Omit<AwsComputeLaunch, "time"> & Timed) | null;
  /** Membership statements in time order (the earliest kept); a rule joins against the statement in force at its time. */
  groupSets: GroupSet[];
  groupSetsBeyond: number;
  lifecycle: EdgeBuffer<Lifecycle>;
  rules: Map<string, EdgeBuffer<Rule>>;
  /** The earliest address records by time. */
  addresses: Address[];
  addressesBeyond: number;
  remote: Remote[];
  remoteBeyond: number;
  attempts: { denied: number; failed: number };
  /** Every fact kind seen while scanning — set on the whole upload, never from a retained buffer — with its earliest record. */
  facts: Map<AwsComputeFact, Cited>;
  session: {
    records: number;
    first: Cited | null;
    last: Cited | null;
    sources: Map<string, Source>;
    overflowSources: Set<string>;
    untrackedRecords: number;
    enumeration: ShapeHit[];
    shapes: Record<
      "privileged-change" | "remote-execution",
      { earliest: ShapeHit | null; named: ShapeHit[]; count: number }
    >;
    attempts: number;
  };
  /** The first cited locators, and the count of every citation — the row reserves the decisive ones first. */
  locators: string[];
  contributing: number;
  terminatedAt: number | null;
}

export interface Tracked {
  instances: Map<string, Inst>;
  /** Records naming an instance past the tracked bound — counted, never read. */
  untrackedRecords: number;
}

export function instFor(t: Tracked, account: string, region: string, id: string): Inst | null {
  const key = `${lower(account)}|${lower(region)}|${lower(id)}`;
  const cur = t.instances.get(key);
  if (cur) return cur;
  if (t.instances.size >= INSTANCES_TRACKED_MAX) {
    t.untrackedRecords += 1;
    return null;
  }
  const inst: Inst = {
    account: lower(account),
    region: lower(region),
    id,
    launch: null,
    groupSets: [],
    groupSetsBeyond: 0,
    lifecycle: new EdgeBuffer(LIFECYCLE_EARLY_MAX, LIFECYCLE_LATE_MAX),
    rules: new Map(),
    addresses: [],
    addressesBeyond: 0,
    remote: [],
    remoteBeyond: 0,
    attempts: { denied: 0, failed: 0 },
    facts: new Map(),
    session: {
      records: 0,
      first: null,
      last: null,
      sources: new Map(),
      overflowSources: new Set(),
      untrackedRecords: 0,
      enumeration: [],
      shapes: {
        "privileged-change": { earliest: null, named: [], count: 0 },
        "remote-execution": { earliest: null, named: [], count: 0 },
      },
      attempts: 0,
    },
    locators: [],
    contributing: 0,
    terminatedAt: null,
  };
  t.instances.set(key, inst);
  return inst;
}

/** Cite every replica locator of a record; the count runs on past the retained list. */
export const cite = (inst: Inst, locators: readonly string[]): void => {
  for (const locator of locators) {
    inst.contributing += 1;
    if (inst.locators.length < RAW_RECORDS_MAX) inst.locators.push(locator);
  }
};

/** Note a fact kind with its earliest record — the grade counts kinds, the row cites this record. */
export const noteFact = (inst: Inst, fact: AwsComputeFact, time: number, locator: string): void => {
  const cur = inst.facts.get(fact);
  if (!cur || time < cur.time) inst.facts.set(fact, { time, locator });
};

/** The groups the instance's own records say it held at `time`: the statement in force, else the launch's for a record before it. */
export function groupsAt(inst: Inst, time: number): readonly string[] | null {
  let inForce: GroupSet | null = null;
  for (const g of inst.groupSets) if (g.time <= time) inForce = g;
  if (inForce) return inForce.groups;
  return inst.launch ? inst.launch.groups.map((g) => lower(g.id)) : null;
}

/** The earliest record of the instance — the launch, else its first lifecycle, address, remote or session record. */
export const firstTime = (inst: Inst): number =>
  Math.min(
    ...[
      inst.launch?.time,
      inst.lifecycle.all()[0]?.time,
      inst.addresses[0]?.time,
      inst.remote[0]?.time,
      inst.session.first?.time,
      ...[...inst.facts.values()].map((f) => f.time),
    ].filter((t): t is number => t !== undefined),
    Number.MAX_SAFE_INTEGER,
  );

export const orderOf = (inst: Inst, time: number): AwsComputeLifecycle["order"] | undefined =>
  !inst.launch ? undefined : time > inst.launch.time ? "after" : time < inst.launch.time ? "before" : "same";
