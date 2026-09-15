// The bounded state of the Azure VM compute-lifecycle pass (#931 item 8 second half, #1066) — the
// constants, the typed per-VM accumulator, the small readers of an Azure Activity Log record, and
// the words shared by the pass (azureCompute.ts) and the row (azureComputeRow.ts). Mirrors
// awsComputeState.ts's shape; kept as its own file rather than shared with AWS's, since AWS's
// types are specific to CloudTrail's own Row/Outcome conventions.
//
// #1077 adds the NIC/Subnet attachment chain and `resolveAt()` — see that function's own comment
// and RECOMMENDATION-1077.md for the full design (why the RULE side needs no ongoing state, only
// the ATTACHMENT chain does; how a bound overflow becomes "not established" rather than a stale
// guess).

import type { Severity } from "./stateTypes.js";
import type {
  AzureComputeFact,
  AzureComputeLaunch,
  AzureComputeOperation,
  AzureNsgObservation,
} from "./canonicalAzureCompute.js";
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
/** NICs/Subnets tracked per upload; further ids are counted, never tracked (#1077). */
export const NICS_TRACKED_MAX = 4096;
export const SUBNETS_TRACKED_MAX = 4096;
/** Per-entity attachment-history bounds — the earliest and the latest, the rest counted (#1077). */
export const NIC_STATE_EARLY_MAX = 24;
export const NIC_STATE_LATE_MAX = 8;
export const SUBNET_STATE_EARLY_MAX = 24;
export const SUBNET_STATE_LATE_MAX = 8;
export const VM_NIC_SETS_EARLY_MAX = 24;
export const VM_NIC_SETS_LATE_MAX = 8;
/** The NSG join's own attacker-controlled-work bounds (#1077, Codex design round 1, finding H5). */
export const NSG_RULE_RECORDS_MAX = 256;
export const NSG_PARENT_RULES_MAX = 64;
export const LIMIT_NOTE =
  "what ran on the VM and its network egress are not in this case's Azure Activity Log exports; the network-security-group join covers only a direct NIC attachment or its subnet's own attachment, resolved as of the rule-write's own time, matched by exact resourceId — a match on one of the two NSGs Azure evaluates never by itself establishes that traffic reaches the VM — see #1077, #1078";
export const COVERAGE_NOTE = "record retention and export filtering are not in this evidence";
export const BASIS =
  "records of this upload only; joined through the VM's resource id; what ran on the VM and its network egress are not in this case's Azure Activity Log exports; the network-security-group join covers only a direct NIC attachment or its subnet's own attachment, resolved as of the rule-write's own time, matched by exact resourceId — a match on one of the two NSGs Azure evaluates never by itself establishes that traffic reaches the VM — see #1077, #1078";
/** A standalone VM's resource id — VM scale sets are out of scope (#1078). */
const VM_RESOURCE_ID =
  /\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/providers\/microsoft\.compute\/virtualmachines\/([^/]+)/i;
/** A NIC's own resource id (#1077). */
const NIC_RESOURCE_ID =
  /^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networkinterfaces\/[^/]+$/i;
/** A subnet's own resource id, capturing its parent VNet's resource id (#1077). */
const SUBNET_RESOURCE_ID =
  /^(\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/virtualnetworks\/[^/]+)\/subnets\/[^/]+$/i;
/** A VNet's own (parent) resource id — no `/subnets/...` suffix (#1077). */
const VNET_RESOURCE_ID =
  /^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/virtualnetworks\/[^/]+$/i;
/** An NSG's own resource id, whether named directly (parent rule form) or as a named child rule's parent (#1077). */
const NSG_RESOURCE_ID =
  /^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networksecuritygroups\/[^/]+$/i;
const NSG_RULE_RESOURCE_ID = /^(.+\/networksecuritygroups\/[^/]+)\/securityrules\/[^/]+$/i;
/**
 * The Run Command operation family (the action form and the managed form) — the ONE shared
 * source of this pattern. `cloudActivityImport.ts`'s `AZURE_RULES` severity table and its
 * `azureRemoteExecutionTarget` both import this constant rather than keeping their own copies, so
 * a security-sensitive match can never drift between the two files (Codex code review, finding #8).
 */
export const AZURE_RUN_COMMAND_RE = /virtualmachines(?:\/[^/]+)?\/runcommands?\/(?:action|write)/i;
export const FACT_WORDS: Record<AzureComputeFact, string> = {
  "identity-assigned": "managed identity recorded on the VM's write",
  "remote-access-request": "remote-access request to the VM",
  "any-address-nsg-rule":
    "a network-security-group rule matching this VM's attached NSG was recorded allowing inbound access from a broad source (see the observation below for which NSG and which source category)",
};
export const FACT_MITRE: Record<AzureComputeFact, string> = {
  "identity-assigned": "T1098.003",
  "remote-access-request": "T1651",
  "any-address-nsg-rule": "T1562.007",
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

/** True only for the documented full standalone-NIC resourceId shape (#1077). Never guessed. */
export const isAzureNicResourceId = (id: string): boolean => NIC_RESOURCE_ID.test(id.trim());

/** The subnet's parent VNet resourceId, or `null` for a non-subnet / unparseable id (#1077). */
export function azureSubnetParentVnet(id: string): string | null {
  const m = SUBNET_RESOURCE_ID.exec(id.trim());
  return m ? lower(m[1]) : null;
}

/** True only for the documented full VNet (parent) resourceId shape — no `/subnets/...` suffix (#1077). */
export const isAzureVnetResourceId = (id: string): boolean => VNET_RESOURCE_ID.test(id.trim());

/**
 * The NSG's own resourceId a rule-write record names, whichever of the two forms it is: the
 * parent form's own resourceId IS the NSG; the child form's resourceId is the NSG's own id with a
 * trailing `/securityRules/<name>` segment, stripped here. `null` for anything else — never
 * guessed (#1077).
 */
export function azureNsgIdForRuleRecord(resourceId: string): string | null {
  const trimmed = resourceId.trim();
  const child = NSG_RULE_RESOURCE_ID.exec(trimmed);
  if (child) return lower(child[1]);
  return NSG_RESOURCE_ID.test(trimmed) ? lower(trimmed) : null;
}

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
/** The trailing integer of a `record:<index>` locator, or null when it does not end in one. */
const locatorIndex = (locator: string | undefined): number | null => {
  const m = /(\d+)$/.exec(locator ?? "");
  return m ? Number(m[1]) : null;
};
/**
 * Ties equal timestamps by the record's own scan position, not by comparing the locator STRING —
 * `"record:10".localeCompare("record:2")` sorts `record:10` first, ordering a numerically later
 * record before an earlier one (#1084, surfaced by #1077's design review). Falls back to the
 * string compare only when either side's locator does not end in a digit run.
 */
export const byTime = (a: Timed, b: Timed): number => {
  if (a.time !== b.time) return a.time - b.time;
  const aLocator = (a as { locator?: string }).locator;
  const bLocator = (b as { locator?: string }).locator;
  const ai = locatorIndex(aLocator);
  const bi = locatorIndex(bLocator);
  if (ai !== null && bi !== null) return ai - bi;
  return aLocator?.localeCompare(bLocator ?? "") ?? 0;
};
export function insertSorted<T extends Timed>(buf: T[], v: T): void {
  let i = buf.length;
  while (i > 0 && byTime(buf[i - 1], v) > 0) i -= 1;
  buf.splice(i, 0, v);
}

/** A recorded delete (VM/NIC/subnet) or a parent-write invalidation (subnet) — never a positive
 * statement (#1077). Shares its entity's own `EdgeBuffer`, ordered by `byTime` like any statement. */
export interface Tombstone extends Timed {
  locator: string;
  deleted: true;
}
export type WithTombstone<T> = T | Tombstone;
const isTombstone = (v: unknown): v is Tombstone =>
  isObject(v) && (v as { deleted?: unknown }).deleted === true;

/**
 * Resolves the statement in force for entity `buf` as of the QUERYING record's own `(time,
 * locator)` position — the helper that actually fixes `groupsAt()`'s (`awsComputeState.ts`)
 * unsoundness (#1077, RECOMMENDATION-1077.md's design-round-1 section, finding M1).
 *
 * `EdgeBuffer` guarantees `early` holds the TRUE earliest-N statements ever pushed (a bounded
 * "keep the N smallest" set) and, once any overflow has happened, `late` holds the TRUE latest-M
 * among what spilled out of `early` (a bounded "keep the M largest of the rest" set) — so `late`,
 * from its own first entry forward, is provably complete: nothing between `late[0]` and any later
 * query was ever discarded. Only the OPEN interval strictly between `early`'s last entry and
 * `late`'s first entry can contain a discarded (uncounted-by-position, but counted in `beyond`)
 * statement — a query landing there cannot honestly resolve to anything, since the true in-force
 * statement might be one of the discarded ones. Returns:
 * - `null` — no statement at or before the query exists at all (the query predates every
 *   statement ever seen — `early` holds the true global earliest, so this is never a guess).
 * - the statement itself — found within `early`'s own gap-free interior, or at/after `late`'s own
 *   first entry (both provably exact), or anywhere at all when nothing was ever discarded
 *   (`beyond === 0`).
 * - `"gap"` — the query falls strictly after `early`'s own last entry with a discard beyond it
 *   (`beyond > 0`) and before `late` starts. A query landing EXACTLY on `early`'s own last entry's
 *   own position still resolves to it, never a gap (Codex code review: the gap starts strictly
 *   AFTER the last retained early entry, not at-or-after).
 * A resolved tombstone (a recorded delete, or a parent-write invalidation) is reported as `"gap"`
 * too — from the caller's perspective nothing trustworthy is established, never a positive result.
 */
export function resolveAt<T extends Timed>(
  buf: EdgeBuffer<WithTombstone<T>>,
  at: Timed & { locator: string },
): T | "gap" | null {
  const query: Timed = at;
  const latest = (list: readonly WithTombstone<T>[]): { entry: WithTombstone<T>; index: number } | null => {
    let hit: { entry: WithTombstone<T>; index: number } | null = null;
    for (let i = 0; i < list.length; i += 1) {
      if (byTime(list[i], query) > 0) break;
      hit = { entry: list[i], index: i };
    }
    return hit;
  };
  const lateHit = latest(buf.late);
  if (lateHit) return isTombstone(lateHit.entry) ? "gap" : lateHit.entry;
  const earlyHit = latest(buf.early);
  if (!earlyHit) return null;
  const isLastInEarly = earlyHit.index === buf.early.length - 1;
  if (!isLastInEarly) return isTombstone(earlyHit.entry) ? "gap" : earlyHit.entry;
  if (buf.beyond === 0) return isTombstone(earlyHit.entry) ? "gap" : earlyHit.entry;
  if (byTime(earlyHit.entry, query) === 0) return isTombstone(earlyHit.entry) ? "gap" : earlyHit.entry;
  return "gap";
}

export interface Cited {
  time: number;
  locator: string;
}
export type Operation = Omit<AzureComputeOperation, "time"> & Timed;
export type Remote = { call: string; by: string } & Timed & { locator: string };

/** One "this VM's write named these NICs" statement (#1077) — a sibling of `vm.launch`, pushed on
 * EVERY successful write that demonstrably carries `networkProfile.networkInterfaces`, never only
 * the first (Codex design round 1, finding H1). */
export interface NicSetStatement extends Timed {
  locator: string;
  nicIds: string[];
}
/** One "this NIC's direct NSG and subnet reference" statement (#1077). */
export interface NicState extends Timed {
  locator: string;
  nsgId: string | null;
  subnetId: string | null;
}
/** One "this subnet's own NSG" statement (#1077). */
export interface SubnetState extends Timed {
  locator: string;
  nsgId: string | null;
}
export interface Nic {
  states: EdgeBuffer<WithTombstone<NicState>>;
}
export interface Subnet {
  states: EdgeBuffer<WithTombstone<SubnetState>>;
}

export interface Vm {
  subscriptionId: string;
  resourceGroup: string;
  vmName: string;
  launch: (Omit<AzureComputeLaunch, "time"> & Timed) | null;
  operations: EdgeBuffer<Operation>;
  remote: Remote[];
  remoteBeyond: number;
  /** The temporal source of truth for the NSG join (#1077) — `vm.launch.networkInterfaces` stays
   * an untouched, first-write-only snapshot; this is updated on every qualifying write. */
  nicSets: EdgeBuffer<WithTombstone<NicSetStatement>>;
  /** The earliest qualifying NSG match only (#1077) — mirrors `noteFact`'s own "earliest wins". */
  nsgObservation: (Omit<AzureNsgObservation, "time"> & Timed) | null;
  notSucceeded: number;
  /** Every fact kind seen while scanning, with its earliest record. */
  facts: Map<AzureComputeFact, Cited>;
  /** Locators already counted toward `contributing` — idempotent per locator, since the NSG join's
   * resolution chain can cite the same NIC/Subnet write from more than one VM/rule match. */
  citedSet: Set<string>;
  locators: string[];
  contributing: number;
}

export interface Tracked {
  vms: Map<string, Vm>;
  /** NIC/Subnet resourceId → tracked entity (#1077). Keys are already lowercased. */
  nics: Map<string, Nic>;
  subnets: Map<string, Subnet>;
  untrackedRecords: number;
  /** NIC/Subnet ids named past their own tracked bound — counted, never read (#1077). */
  untrackedNics: number;
  untrackedSubnets: number;
  /** NSG-rule-write records past `NSG_RULE_RECORDS_MAX` — counted, never examined (#1077). */
  nsgRuleRecordsBeyond: number;
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
    nicSets: new EdgeBuffer(VM_NIC_SETS_EARLY_MAX, VM_NIC_SETS_LATE_MAX),
    nsgObservation: null,
    notSucceeded: 0,
    facts: new Map(),
    citedSet: new Set(),
    locators: [],
    contributing: 0,
  };
  t.vms.set(key, vm);
  return vm;
}

/** `id` must already be lowercased — every caller derives it from a parser that already lowers. */
export function nicFor(t: Tracked, id: string): Nic | null {
  const cur = t.nics.get(id);
  if (cur) return cur;
  if (t.nics.size >= NICS_TRACKED_MAX) {
    t.untrackedNics += 1;
    return null;
  }
  const nic: Nic = { states: new EdgeBuffer(NIC_STATE_EARLY_MAX, NIC_STATE_LATE_MAX) };
  t.nics.set(id, nic);
  return nic;
}

/** `id` must already be lowercased — every caller derives it from a parser that already lowers. */
export function subnetFor(t: Tracked, id: string): Subnet | null {
  const cur = t.subnets.get(id);
  if (cur) return cur;
  if (t.subnets.size >= SUBNETS_TRACKED_MAX) {
    t.untrackedSubnets += 1;
    return null;
  }
  const subnet: Subnet = { states: new EdgeBuffer(SUBNET_STATE_EARLY_MAX, SUBNET_STATE_LATE_MAX) };
  t.subnets.set(id, subnet);
  return subnet;
}

/** Idempotent per locator — the NSG join's resolution chain can cite the same NIC/Subnet write
 * record from more than one VM/rule match; it must count once (mirrors #1066 code-round's own
 * GCP fix). */
export const cite = (vm: Vm, locator: string): void => {
  if (vm.citedSet.has(locator)) return;
  vm.citedSet.add(locator);
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
