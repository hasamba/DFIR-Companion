// The bounded state of the Azure VM compute-lifecycle pass (#931 item 8 second half, #1066) — the
// constants, the typed per-VM accumulator, the small readers of an Azure Activity Log record, and
// the words shared by the pass (azureCompute.ts) and the row (azureComputeRow.ts). Mirrors
// awsComputeState.ts's shape; kept as its own file rather than shared with AWS's, since AWS's
// types are specific to CloudTrail's own Row/Outcome conventions.

import type { Severity } from "./stateTypes.js";
import type { AzureComputeFact, AzureComputeLaunch, AzureComputeOperation } from "./canonicalAzureCompute.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, isObject, str } from "./siemImport.js";

export type Row = Record<string, unknown>;

export const AZURE_COMPUTE_MAX = 256;
/** VMs tracked per upload; further VM ids are counted, never tracked. */
export const VMS_TRACKED_MAX = 4096;
/** Operation records retained per VM: the earliest and the latest, the rest counted. */
export const OPERATIONS_EARLY_MAX = 24;
export const OPERATIONS_LATE_MAX = 8;
export const NICS_MAX = 8;
export const REMOTE_MAX = 8;
export const OPERATIONS_NAMED_MAX = 8;
export const RAW_RECORDS_MAX = 256;
export const NAME_MAX = 80;
export const DESCRIPTION_MAX = 1400;
export const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
export const LIMIT_NOTE =
  "what ran on the VM and its network egress are not in this case's Azure Activity Log exports; no network-security-group join is made — see #1073";
export const COVERAGE_NOTE = "record retention and export filtering are not in this evidence";
export const BASIS =
  "records of this upload only; joined through the VM's resource id; what ran on the VM and its network egress are not in this case's Azure Activity Log exports; no network-security-group join is made — see #1073";
/** A standalone VM's resource id — VM scale sets are out of scope (#1073). */
const VM_RESOURCE_ID =
  /\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/providers\/microsoft\.compute\/virtualmachines\/([^/]+)/i;
export const FACT_WORDS: Record<AzureComputeFact, string> = {
  "identity-assigned": "managed identity recorded on the VM's write",
  "remote-access-request": "remote-access request to the VM",
};
export const FACT_MITRE: Record<AzureComputeFact, string> = {
  "identity-assigned": "T1098.003",
  "remote-access-request": "T1651",
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
 * A standalone VM's `(subscriptionId, resourceGroup, vmName)`, parsed from a `resourceId` field —
 * `null` for a VM-scale-set instance (out of scope, #1073) or an unparseable id. Exported so the
 * remote-access fact can compare `azureRemoteExecutionTarget`'s returned id against this same
 * canonical form, never trusting that helper's synthetic non-matching-parse fallback.
 */
export function parseAzureVmResourceId(
  resourceId: string,
): { subscriptionId: string; resourceGroup: string; vmName: string } | null {
  const m = VM_RESOURCE_ID.exec(resourceId);
  if (!m) return null;
  return { subscriptionId: m[1], resourceGroup: m[2], vmName: m[3] };
}

export const vmKey = (subscriptionId: string, resourceGroup: string, vmName: string): string =>
  `${lower(subscriptionId)}|${lower(resourceGroup)}|${lower(vmName)}`;

/**
 * Success only on the record's own status field reading exactly "succeeded" (case-insensitive) —
 * "started"/"accepted"/anything else is a non-terminal or unrecognised record and is an ATTEMPT,
 * never a joined fact (Codex design round 1, finding #13: Azure Activity Log can record an
 * operation's acceptance separately from its completion).
 */
export const azureAttemptOutcome = (status: string): "success" | "not-succeeded" =>
  lower(status) === "succeeded" ? "success" : "not-succeeded";

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
export type Operation = Omit<AzureComputeOperation, "time"> & Timed;
export type Remote = { call: string; by: string } & Timed & { locator: string };

export interface Vm {
  subscriptionId: string;
  resourceGroup: string;
  vmName: string;
  launch: (Omit<AzureComputeLaunch, "time"> & Timed) | null;
  operations: EdgeBuffer<Operation>;
  remote: Remote[];
  remoteBeyond: number;
  notSucceeded: number;
  /** Every fact kind seen while scanning, with its earliest record. */
  facts: Map<AzureComputeFact, Cited>;
  locators: string[];
  contributing: number;
}

export interface Tracked {
  vms: Map<string, Vm>;
  untrackedRecords: number;
}

export function vmFor(t: Tracked, subscriptionId: string, resourceGroup: string, vmName: string): Vm | null {
  const key = vmKey(subscriptionId, resourceGroup, vmName);
  const cur = t.vms.get(key);
  if (cur) return cur;
  if (t.vms.size >= VMS_TRACKED_MAX) {
    t.untrackedRecords += 1;
    return null;
  }
  const vm: Vm = {
    subscriptionId: lower(subscriptionId),
    resourceGroup: lower(resourceGroup),
    vmName,
    launch: null,
    operations: new EdgeBuffer(OPERATIONS_EARLY_MAX, OPERATIONS_LATE_MAX),
    remote: [],
    remoteBeyond: 0,
    notSucceeded: 0,
    facts: new Map(),
    locators: [],
    contributing: 0,
  };
  t.vms.set(key, vm);
  return vm;
}

export const cite = (vm: Vm, locator: string): void => {
  vm.contributing += 1;
  if (vm.locators.length < RAW_RECORDS_MAX) vm.locators.push(locator);
};

export const noteFact = (vm: Vm, fact: AzureComputeFact, time: number, locator: string): void => {
  const cur = vm.facts.get(fact);
  if (!cur || time < cur.time) vm.facts.set(fact, { time, locator });
};

export const firstTime = (vm: Vm): number =>
  Math.min(
    ...[
      vm.launch?.time,
      vm.operations.all()[0]?.time,
      vm.remote[0]?.time,
      ...[...vm.facts.values()].map((f) => f.time),
    ].filter((t): t is number => t !== undefined),
    Number.MAX_SAFE_INTEGER,
  );
