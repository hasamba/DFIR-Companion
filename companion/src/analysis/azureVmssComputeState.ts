// The bounded state of the Azure VMSS-member compute-lifecycle pass (#931 item 8, #1078) — a
// SIBLING to azureComputeState.ts (standalone VMs), never a modification of it: a VMSS member's
// identity is a 4-tuple (subscription, resource group, set name, instance id), never the
// standalone 3-tuple, and Uniform-mode instance ids are reused after deletion, so each member's
// own timeline is split into OBSERVED LIFECYCLE EPOCHS at successful-delete boundaries — never a
// claim of a proven distinct physical machine. See RECOMMENDATION-1078.md's design-round-1
// section for the full reasoning (why the epoch rule is stricter than a naive "anything after a
// close opens a new one," why Flexible-mode members are out of scope entirely, and why the NIC
// reader only ever reads one candidate body shape).

import type { Severity } from "./stateTypes.js";
import type { AzureVmssComputeFact } from "./canonicalAzureCompute.js";
import type { AzureComputeLaunch, AzureComputeOperation } from "./canonicalAzureCompute.js";
import {
  EdgeBuffer,
  byTime,
  field,
  isAzureNicResourceId,
  lower,
  plural,
  show,
  type Cited,
  type Timed,
} from "./azureComputeState.js";

export type Row = Record<string, unknown>;

export const VMSS_COMPUTE_MAX = 256;
/** Members tracked per upload; further member ids are counted, never tracked. */
export const VMSS_MEMBERS_TRACKED_MAX = 4096;
/** Epochs retained per member; further post-closure activity for the SAME member is counted,
 * never mutating the last retained epoch (#1078, Codex code review finding H2). */
export const VMSS_EPOCHS_PER_MEMBER_MAX = 8;
/** A GLOBAL cap on the total epochs retained across ALL members — `members × per-member max`
 * alone is unbounded in aggregate (#1078, Codex code review finding H2). */
export const VMSS_EPOCHS_TRACKED_MAX = 8192;
export const VMSS_OPERATIONS_EARLY_MAX = 24;
export const VMSS_OPERATIONS_LATE_MAX = 8;
export const VMSS_REMOTE_MAX = 8;
export const OPERATIONS_NAMED_MAX = 8;
export const RAW_RECORDS_MAX = 256;
export const NAME_MAX = 80;
export const DESCRIPTION_MAX = 1400;
export const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
export const LIMIT_NOTE =
  "what ran on the member and its network egress are not in this case's Azure Activity Log exports; Flexible-orchestration members are out of scope — only Uniform-mode members are tracked; per-member operations coverage is opportunistic, and an absent member row is never evidence that no scale-set activity occurred; each row is one OBSERVED lifecycle epoch, bounded at a successful delete, never a claim of one proven distinct physical machine — see #1078";
export const COVERAGE_NOTE = "record retention and export filtering are not in this evidence";
export const BASIS =
  "records of this upload only; joined through the VMSS member's resource id (subscription, resource group, scale-set name, instance id); what ran on the member and its network egress are not in this case's Azure Activity Log exports; Flexible-orchestration members (identified by their own record's virtualMachineResourceId field) are out of scope — only Uniform-mode members are tracked; per-member operations coverage is opportunistic, and an absent member row is never evidence that no scale-set activity occurred; each row is one OBSERVED lifecycle epoch, bounded at a successful delete, never a claim of one proven distinct physical machine — see #1078";

/**
 * A VMSS member's own resourceId shape — a 4-tuple, captured so both this file's own scan and
 * `cloudActivityImport.ts`'s `azureRemoteExecutionTarget` (Run Command targeting) can share ONE
 * pattern instead of drifting independently (#1078, Codex design round 1, finding M1 — the
 * original draft proposed a second, independent copy of `cloudActivityImport.ts`'s own private
 * `VMSS_RE`). Not end-anchored, so it matches both the member's own resourceId and a Run Command
 * child form (`.../virtualMachines/<id>/runCommands/<name>`), mirroring the standalone parser's
 * own not-end-anchored convention.
 */
export const VMSS_MEMBER_RESOURCE_ID =
  /\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/providers\/microsoft\.compute\/virtualmachinescalesets\/([^/]+)\/virtualmachines\/([^/]+)/i;

export function parseAzureVmssMemberResourceId(
  resourceId: string,
): { subscriptionId: string; resourceGroup: string; setName: string; instanceId: string } | null {
  const m = VMSS_MEMBER_RESOURCE_ID.exec(resourceId);
  if (!m) return null;
  return { subscriptionId: m[1], resourceGroup: m[2], setName: m[3], instanceId: m[4] };
}

export const vmssMemberKey = (
  subscriptionId: string,
  resourceGroup: string,
  setName: string,
  instanceId: string,
): string => `${lower(subscriptionId)}|${lower(resourceGroup)}|${lower(setName)}|${lower(instanceId)}`;

export const FACT_WORDS: Record<AzureVmssComputeFact, string> = {
  "identity-assigned": "managed identity recorded on the member's write",
  "remote-access-request": "remote-access request to the member",
};
export const FACT_MITRE: Record<AzureVmssComputeFact, string> = {
  "identity-assigned": "T1098.003",
  "remote-access-request": "T1651",
};

export type Operation = Omit<AzureComputeOperation, "time"> & Timed;
export type Remote = { call: string; by: string } & Timed & { locator: string };

/** One OBSERVED lifecycle epoch for a member — bounded at a successful delete. Never a proven
 * distinct physical machine (#1078, design-round-1 finding H1). */
export interface VmssEpoch {
  index: number;
  launch: (Omit<AzureComputeLaunch, "time"> & Timed) | null;
  operations: EdgeBuffer<Operation>;
  remote: Remote[];
  remoteBeyond: number;
  notSucceeded: number;
  facts: Map<AzureVmssComputeFact, Cited>;
  locators: string[];
  contributing: number;
  /** Set once a successful delete has closed this epoch — no further record may open or mutate it. */
  closed: boolean;
}

export interface VmssMember {
  subscriptionId: string;
  resourceGroup: string;
  setName: string;
  instanceId: string;
  epochs: VmssEpoch[];
  /** Post-closure/post-global-cap activity for this member — counted, never mutating the last
   * retained epoch (#1078, Codex code review, finding H2). */
  epochsBeyond: number;
  /** Set once a record's own body reveals `virtualMachineResourceId` — a Flexible-orchestration
   * alias of a standalone VM (#1066) this join does not attempt to reconcile. Once set, every
   * later record for this member is skipped too (design-round-1 finding M3). */
  flexible: boolean;
}

export interface Tracked {
  members: Map<string, VmssMember>;
  untrackedRecords: number;
  /** The running total of epochs retained across ALL members, checked against
   * `VMSS_EPOCHS_TRACKED_MAX` before a new one is opened. */
  epochsTracked: number;
}

function newEpoch(index: number): VmssEpoch {
  return {
    index,
    launch: null,
    operations: new EdgeBuffer(VMSS_OPERATIONS_EARLY_MAX, VMSS_OPERATIONS_LATE_MAX),
    remote: [],
    remoteBeyond: 0,
    notSucceeded: 0,
    facts: new Map(),
    locators: [],
    contributing: 0,
    closed: false,
  };
}

export function memberFor(
  t: Tracked,
  subscriptionId: string,
  resourceGroup: string,
  setName: string,
  instanceId: string,
): VmssMember | null {
  const key = vmssMemberKey(subscriptionId, resourceGroup, setName, instanceId);
  const cur = t.members.get(key);
  if (cur) return cur;
  if (t.members.size >= VMSS_MEMBERS_TRACKED_MAX) {
    t.untrackedRecords += 1;
    return null;
  }
  const member: VmssMember = {
    subscriptionId: lower(subscriptionId),
    resourceGroup: lower(resourceGroup),
    setName,
    instanceId,
    epochs: [],
    epochsBeyond: 0,
    flexible: false,
  };
  t.members.set(key, member);
  return member;
}

/**
 * The epoch a record for `member` at `time` belongs to, per the rule (#1078, design-round-1,
 * finding H1, reworked after Codex's code review):
 * - a successful delete with NO open epoch creates one that is IMMEDIATELY closed (the boundary
 *   is retained even with no predecessor);
 * - a successful delete while ALREADY closed stays on the closed epoch (repeated deletes are
 *   never distinct machines);
 * - only a SUCCESSFUL, non-delete record may open a NEW epoch once the current one is closed (or
 *   none exists yet) — a failed/non-terminal record while closed returns `null`: it is a
 *   post-closure attempt, never an epoch opener;
 * - once open, ANY record (success or not) continues that SAME open epoch, so `notSucceeded` is
 *   still tracked per-epoch for attempts against an in-progress member.
 * Returns `null` when the record does not open or continue any epoch (a post-closure attempt, or
 * every bound already exhausted) — the caller must then only count it, never track it.
 */
export function epochFor(
  t: Tracked,
  member: VmssMember,
  isDelete: boolean,
  succeeded: boolean,
): VmssEpoch | null {
  const last = member.epochs[member.epochs.length - 1];
  if (last && !last.closed) {
    if (isDelete && succeeded) last.closed = true;
    return last;
  }
  // No epoch yet, or the last one is closed.
  if (isDelete) {
    if (!succeeded) return null; // a failed delete after closure is a post-closure attempt only
    if (!last) {
      // Delete-first: retain the boundary as an immediately-closed placeholder epoch.
      if (member.epochs.length >= VMSS_EPOCHS_PER_MEMBER_MAX || t.epochsTracked >= VMSS_EPOCHS_TRACKED_MAX) {
        member.epochsBeyond += 1;
        return null;
      }
      const epoch = newEpoch(member.epochs.length + 1);
      epoch.closed = true;
      member.epochs.push(epoch);
      t.epochsTracked += 1;
      return epoch;
    }
    // Already closed — a repeated delete stays on the closed epoch, never opens a new one.
    return last;
  }
  if (!succeeded) return null; // a failed/non-terminal record after closure opens nothing
  if (member.epochs.length >= VMSS_EPOCHS_PER_MEMBER_MAX || t.epochsTracked >= VMSS_EPOCHS_TRACKED_MAX) {
    member.epochsBeyond += 1;
    return null;
  }
  const epoch = newEpoch(member.epochs.length + 1);
  member.epochs.push(epoch);
  t.epochsTracked += 1;
  return epoch;
}

export const cite = (epoch: VmssEpoch, locator: string): void => {
  epoch.contributing += 1;
  if (epoch.locators.length < RAW_RECORDS_MAX) epoch.locators.push(locator);
};

export const noteFact = (
  epoch: VmssEpoch,
  fact: AzureVmssComputeFact,
  time: number,
  locator: string,
): void => {
  const cur = epoch.facts.get(fact);
  if (!cur || time < cur.time) epoch.facts.set(fact, { time, locator });
};

export const firstTime = (epoch: VmssEpoch): number =>
  Math.min(
    ...[
      epoch.launch?.time,
      epoch.operations.all()[0]?.time,
      epoch.remote[0]?.time,
      ...[...epoch.facts.values()].map((f) => f.time),
    ].filter((t): t is number => t !== undefined),
    Number.MAX_SAFE_INTEGER,
  );

export { byTime, field, isAzureNicResourceId, plural, show };
