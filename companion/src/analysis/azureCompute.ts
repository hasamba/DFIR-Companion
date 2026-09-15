// Azure VM compute lifecycle (#931 item 8 second half, #1066): what one Activity Log upload
// records about one standalone VM — the launch/update facts as the `virtualMachines/write`
// request body states them, every later recorded operation that names it, whether a managed
// identity was recorded, the remote-access requests to it, and (#1077) a network-security-group
// rule recorded against its attached NSG — built over the records of ONE upload, mirroring the
// shape `awsCompute.ts` established for EC2.
//
// What one row rests on, and what it never says: see canonicalAzureCompute.ts's basis sentence,
// RECOMMENDATION-1066.md's design-round-1 section, and RECOMMENDATION-1077.md (the NSG join). In
// short — identity is the VM's own resourceId, never a display name; a recorded operation is
// never a fabricated before/after transition; an unsuccessful call is an attempt, never a joined
// fact; the grade counts distinct recorded-fact kinds (2+ → High, 1 → Medium, 0 → Low), and no
// single record makes a High. The NSG join never claims what the rule content itself does not
// establish, and never claims a match on one of the two NSGs Azure evaluates means traffic
// actually reaches the VM — see `azureComputeState.ts`'s `LIMIT_NOTE`/`BASIS`.

import type { Severity } from "./stateTypes.js";
import type { AzureComputeFact, AzureComputeLaunch, AzureNsgObservation } from "./canonicalAzureCompute.js";
import { parseAzureRequestBody } from "./loggingChangeCloud.js";
import { getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import {
  AZURE_COMPUTE_MAX,
  AZURE_RUN_COMMAND_RE,
  NICS_MAX,
  NSG_PARENT_RULES_MAX,
  NSG_PREFIXES_PER_RULE_MAX,
  NSG_RULE_RECORDS_MAX,
  RANK,
  REMOTE_MAX,
  azureAttemptOutcome,
  azureNsgIdForRuleRecord,
  azureSubnetParentVnet,
  cite,
  field,
  firstTime,
  isAzureNicResourceId,
  isAzureVnetResourceId,
  lower,
  nicFor,
  noteFact,
  parseAzureVmResourceId,
  resolveAt,
  subnetFor,
  VNET_INVALIDATION_RECORDS_MAX,
  vmFor,
  type Nic,
  type NicState,
  type Operation,
  type Row,
  type Subnet,
  type SubnetState,
  type Timed,
  type Tracked,
  type Vm,
} from "./azureComputeState.js";
import { omittedRow, summaryRow } from "./azureComputeRow.js";

export { AZURE_COMPUTE_MAX, VMS_TRACKED_MAX } from "./azureComputeState.js";

interface Scanned {
  rec: Row;
  index: number;
  time: number;
  op: string;
  resourceId: string;
  /** `null` for a record whose resourceId does not parse as a standalone VM — #1077's new record
   * kinds (NIC/subnet/NSG/VNet writes) are named by their OWN resourceId shape instead. */
  vmId: { subscriptionId: string; resourceGroup: string; vmName: string } | null;
  status: string;
  by: string;
  locator: string;
  requestBody: unknown;
}

function pickStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}

/**
 * Every Azure record this pass can classify by its own `operationName`/`resourceId` shape, in
 * time order (record position as tie-breaker) — VM records (as before #1077) AND, new in #1077,
 * NIC/subnet/NSG/VNet records, so `recordNic`/`recordSubnet`/`recordNsgJoin`/etc. can each check
 * their own resourceId shape independently. The upload's own `coverage.records/first/last`
 * window stays VM-ONLY (#1066's own meaning, unchanged — Codex design round 1, finding M2): a
 * record only advances it when it also parses as a standalone VM.
 */
function scan(
  records: readonly Row[],
  coverage: { records: number; first: string; last: string },
): Scanned[] {
  const out: Scanned[] = [];
  records.forEach((rec, index) => {
    if (!isObject(rec)) return;
    const op = pickStr(rec, ["operationName.value", "operationName", "OperationNameValue", "OperationName"]);
    const resourceId = pickStr(rec, ["resourceId", "ResourceId"]);
    if (!op || !resourceId) return;
    const vmId = parseAzureVmResourceId(resourceId);
    const observed = pickStr(rec, ["eventTimestamp", "time", "TimeGenerated", "timeStamp"]);
    const t = normalizeTime(observed);
    const time = Date.parse(t);
    if (!Number.isFinite(time)) return;
    if (vmId) {
      coverage.records += 1;
      if (!coverage.first || t < coverage.first) coverage.first = t;
      if (!coverage.last || t > coverage.last) coverage.last = t;
    }
    out.push({
      rec,
      index,
      time,
      op,
      resourceId,
      vmId,
      status: pickStr(rec, ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"]),
      by: pickStr(rec, ["caller", "Caller", "identity.claims.name"]) || "(caller not recorded)",
      locator: `record:${index}`,
      requestBody:
        getPath(rec, "properties.requestbody") ??
        getPath(rec, "properties.requestBody") ??
        getPath(rec, "Properties.requestbody") ??
        getPath(rec, "Properties.requestBody"),
    });
  });
  return out.sort((a, b) => a.time - b.time || a.index - b.index);
}

function launchFacts(
  s: Scanned,
  body: Row | null,
): { launch: Omit<AzureComputeLaunch, "time">; identityAssigned: boolean } {
  const props = body && isObject(getCI(body, "properties")) ? (getCI(body, "properties") as Row) : {};
  const networkProfile = isObject(getCI(props, "networkProfile"))
    ? (getCI(props, "networkProfile") as Row)
    : {};
  const nicList = getCI(networkProfile, "networkInterfaces");
  const nics = (Array.isArray(nicList) ? nicList : [])
    .filter(isObject)
    .map((n) => field(n, "id"))
    .filter(Boolean)
    .slice(0, NICS_MAX);
  const identity = body && isObject(getCI(body, "identity")) ? (getCI(body, "identity") as Row) : null;
  const identityAssigned = !!(
    identity &&
    (field(identity, "type") || isObject(getCI(identity, "userAssignedIdentities")))
  );
  return {
    launch: {
      locators: [s.locator],
      by: s.by,
      vmSize: field(props, "hardwareProfile", "vmSize") || undefined,
      image:
        field(props, "storageProfile", "imageReference", "id") ||
        [
          field(props, "storageProfile", "imageReference", "publisher"),
          field(props, "storageProfile", "imageReference", "offer"),
          field(props, "storageProfile", "imageReference", "sku"),
        ]
          .filter(Boolean)
          .join(":") ||
        undefined,
      adminUsername: field(props, "osProfile", "adminUsername") || undefined,
      networkInterfaces: nics,
      identityAssigned,
    },
    identityAssigned,
  };
}

/** The NIC ids a write's own body names, or `null` when the field is genuinely absent — never
 * guessed into an empty set (#1077, Codex design round 1, finding H1: an unrelated VM PATCH can
 * omit `networkProfile` entirely without detaching anything). Also never guessed from a
 * MALFORMED value once present — a non-array value, or an array whose entries all fail to decode
 * to a valid NIC resourceId, is NOT the same as a genuinely empty `[]` Azure sent, and must not
 * silently supersede a real prior attachment (#1077, Codex code review, finding M2). */
function nicSetFromBody(body: Row | null): string[] | null {
  const props = body && isObject(getCI(body, "properties")) ? (getCI(body, "properties") as Row) : null;
  const networkProfile =
    props && isObject(getCI(props, "networkProfile")) ? (getCI(props, "networkProfile") as Row) : null;
  if (!networkProfile) return null;
  const nicList = getCI(networkProfile, "networkInterfaces");
  if (nicList === undefined) return null;
  if (!Array.isArray(nicList)) return null;
  const ids = nicList
    .filter(isObject)
    .map((n) => field(n, "id"))
    .filter((id) => id && isAzureNicResourceId(id))
    .map(lower)
    .slice(0, NICS_MAX);
  if (ids.length === 0 && nicList.length > 0) return null;
  return ids;
}

function recordWrite(t: Tracked, s: Scanned): void {
  if (!s.vmId) return;
  if (!/microsoft\.compute\/virtualmachines\/write$/i.test(s.op)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const vm = vmFor(t, s.vmId.subscriptionId, s.vmId.resourceGroup, s.vmId.vmName);
  if (!vm) return;
  const body = parseAzureRequestBody(s.requestBody);
  const { launch, identityAssigned } = launchFacts(s, body);
  if (!vm.launch) vm.launch = { ...launch, time: s.time };
  if (identityAssigned) noteFact(vm, "identity-assigned", s.time, s.locator);
  cite(vm, s.locator);
  // #1077: the temporal source of truth for the NSG join — updated on EVERY qualifying write,
  // never only the first (unlike the unchanged, informational `vm.launch.networkInterfaces`).
  const nicIds = nicSetFromBody(body);
  if (nicIds) vm.nicSets.push({ time: s.time, locator: s.locator, nicIds });
}

/** A successful `virtualMachines/delete` also closes the NIC-set chain (#1077, finding H2) — a
 * rule recorded after this time must never resolve through a NIC set the VM no longer had. */
function recordVmDelete(t: Tracked, s: Scanned): void {
  if (!s.vmId) return;
  if (!/microsoft\.compute\/virtualmachines\/delete$/i.test(s.op)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const vm = vmFor(t, s.vmId.subscriptionId, s.vmId.resourceGroup, s.vmId.vmName);
  if (!vm) return;
  vm.nicSets.push({ time: s.time, locator: s.locator, deleted: true });
}

const OPERATION_RE: Record<"start" | "deallocate" | "delete", RegExp> = {
  start: /microsoft\.compute\/virtualmachines\/start\/action$/i,
  deallocate: /microsoft\.compute\/virtualmachines\/deallocate\/action$/i,
  delete: /microsoft\.compute\/virtualmachines\/delete$/i,
};

function recordOperation(t: Tracked, s: Scanned): void {
  if (!s.vmId) return;
  const entry = Object.entries(OPERATION_RE).find(([, re]) => re.test(s.op));
  if (!entry) return;
  const kind = entry[0] as "start" | "deallocate" | "delete";
  const vm = vmFor(t, s.vmId.subscriptionId, s.vmId.resourceGroup, s.vmId.vmName);
  if (!vm) return;
  if (azureAttemptOutcome(s.status) !== "success") {
    vm.notSucceeded += 1;
    return;
  }
  const op: Operation = { kind, call: s.op, time: s.time, locator: s.locator, by: s.by };
  vm.operations.push(op);
  cite(vm, s.locator);
}

// The Run Command operation match is the shared AZURE_RUN_COMMAND_RE (azureComputeState.ts) —
// the same constant cloudActivityImport.ts's AZURE_RULES table and azureRemoteExecutionTarget
// use, so the two files can never disagree about what counts as a Run Command call. Never by
// importing azureRemoteExecutionTarget ITSELF here: its return `id` is a different string SHAPE
// (the full lowercased resource path, not this join's `sub|rg|vm` key) and importing the function
// (as opposed to the regex) would create a cycle, since cloudActivityImport.ts wires this join in.
// A record whose resourceId does not parse as a standalone VM is never a remote-access target —
// true for both the "action" form (`resourceId` IS the VM) and the "managed" form (`resourceId`
// is `<vm>/runCommands/<name>`, and the VM-id regex is not end-anchored) — no separate
// target-resolution step is needed: `s.vmId` already IS the target.
function recordRemote(t: Tracked, s: Scanned): void {
  if (!s.vmId) return;
  if (!AZURE_RUN_COMMAND_RE.test(s.op)) return;
  const vm = vmFor(t, s.vmId.subscriptionId, s.vmId.resourceGroup, s.vmId.vmName);
  if (!vm) return;
  if (azureAttemptOutcome(s.status) !== "success") {
    vm.notSucceeded += 1;
    return;
  }
  // Records arrive here in time order (scan() sorts before any pass runs), so keeping the first
  // REMOTE_MAX encountered is equivalent to keeping the earliest — no separate sort needed.
  if (vm.remote.length < REMOTE_MAX)
    vm.remote.push({ call: s.op, time: s.time, locator: s.locator, by: s.by });
  else vm.remoteBeyond += 1;
  noteFact(vm, "remote-access-request", s.time, s.locator);
  cite(vm, s.locator);
}

// ───────────────────────────── #1077: the NIC / Subnet attachment chain ─────────────────────────────

const NIC_WRITE_RE = /microsoft\.network\/networkinterfaces\/write$/i;
const NIC_DELETE_RE = /microsoft\.network\/networkinterfaces\/delete$/i;
const SUBNET_WRITE_RE = /microsoft\.network\/virtualnetworks\/subnets\/write$/i;
const SUBNET_DELETE_RE = /microsoft\.network\/virtualnetworks\/subnets\/delete$/i;
const VNET_WRITE_RE = /microsoft\.network\/virtualnetworks\/write$/i;
const VNET_DELETE_RE = /microsoft\.network\/virtualnetworks\/delete$/i;
/** The PARENT NSG form — its own inline `properties.securityRules[]`, never `defaultSecurityRules[]`. */
const NSG_WRITE_RE = /microsoft\.network\/networksecuritygroups\/write$/i;
/** The CHILD named-rule form — one rule, read as a FULL rule object (Azure's control-plane PUT for
 * a named security rule has no partial form, unlike GCP's `firewalls.patch` — #1073). */
const NSG_RULE_WRITE_RE = /microsoft\.network\/networksecuritygroups\/securityrules\/write$/i;

function requestProps(requestBody: unknown): Row | null {
  const body = parseAzureRequestBody(requestBody);
  return body && isObject(getCI(body, "properties")) ? (getCI(body, "properties") as Row) : null;
}

/** A successful NIC write records its own direct NSG and (first IP configuration only — every IP
 * configuration on one NIC shares the same subnet, per Azure's own documented constraint, so this
 * is not a coverage gap) subnet reference (#1077). A record with no `properties` at all is never
 * guessed into a state. */
function recordNic(t: Tracked, s: Scanned): void {
  if (!NIC_WRITE_RE.test(s.op)) return;
  if (!isAzureNicResourceId(s.resourceId)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const props = requestProps(s.requestBody);
  if (!props) return;
  const nic = nicFor(t, lower(s.resourceId));
  if (!nic) return;
  const nsgIdRaw = field(props, "networkSecurityGroup", "id");
  const ipConfigs = getCI(props, "ipConfigurations");
  const firstIpConfig = (Array.isArray(ipConfigs) ? ipConfigs : []).find(isObject);
  const subnetIdRaw = firstIpConfig ? field(firstIpConfig, "properties", "subnet", "id") : "";
  const state: NicState = {
    time: s.time,
    locator: s.locator,
    nsgId: nsgIdRaw ? lower(nsgIdRaw) : null,
    subnetId: subnetIdRaw ? lower(subnetIdRaw) : null,
  };
  nic.states.push(state);
}

/** A successful NIC delete closes its own chain (#1077, finding H2) — a rule recorded after this
 * time must never resolve through an attachment the NIC no longer had. */
function recordNicDelete(t: Tracked, s: Scanned): void {
  if (!NIC_DELETE_RE.test(s.op)) return;
  if (!isAzureNicResourceId(s.resourceId)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const nic = nicFor(t, lower(s.resourceId));
  if (!nic) return;
  nic.states.push({ time: s.time, locator: s.locator, deleted: true });
}

/** A successful CHILD subnet write records its own NSG (#1077). */
function recordSubnet(t: Tracked, s: Scanned): void {
  if (!SUBNET_WRITE_RE.test(s.op)) return;
  const parentVnet = azureSubnetParentVnet(s.resourceId);
  if (!parentVnet) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const props = requestProps(s.requestBody);
  if (!props) return;
  const subnet = subnetFor(t, lower(s.resourceId), parentVnet);
  if (!subnet) return;
  const nsgIdRaw = field(props, "networkSecurityGroup", "id");
  const state: SubnetState = { time: s.time, locator: s.locator, nsgId: nsgIdRaw ? lower(nsgIdRaw) : null };
  subnet.states.push(state);
}

/** A successful CHILD subnet delete closes its own chain (#1077, finding H2). */
function recordSubnetDelete(t: Tracked, s: Scanned): void {
  if (!SUBNET_DELETE_RE.test(s.op)) return;
  const parentVnet = azureSubnetParentVnet(s.resourceId);
  if (!parentVnet) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const subnet = subnetFor(t, lower(s.resourceId), parentVnet);
  if (!subnet) return;
  subnet.states.push({ time: s.time, locator: s.locator, deleted: true });
}

/**
 * Invalidates (write) or tombstones (delete) ONLY the given VNet's own tracked children, via
 * `subnetsByVnet`'s index — never a full scan of every tracked subnet (#1077, Codex code review,
 * finding H3: an attacker-controlled number of VNet writes against a large tracked subnet map is
 * otherwise an O(writes × subnets) cost). Bounded by `VNET_INVALIDATION_RECORDS_MAX` at the call
 * site in `azureComputeLifecycles()`, same discipline as the NSG-rule-record bound.
 */
function invalidateVnetChildren(t: Tracked, vnetId: string, time: number, locator: string): void {
  const children = t.subnetsByVnet.get(vnetId);
  if (!children) return;
  for (const id of children) {
    const subnet = t.subnets.get(id);
    if (subnet) subnet.states.push({ time, locator, deleted: true });
  }
}

/**
 * A successful PARENT VNet write invalidates its own currently-tracked child subnets (#1077,
 * finding H2) rather than being silently ignored. Decoding the parent's own inline
 * `properties.subnets[]` is out of scope (#1077's Files section) — but ignoring the write
 * entirely would let a later child-subnet state look current when the parent write may have
 * changed the same subnet's NSG in between.
 */
function recordVnetWrite(t: Tracked, s: Scanned): void {
  if (!VNET_WRITE_RE.test(s.op)) return;
  if (!isAzureVnetResourceId(s.resourceId)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  invalidateVnetChildren(t, lower(s.resourceId), s.time, s.locator);
}

/** A successful PARENT VNet delete tombstones every one of its own tracked children (#1077,
 * Codex code review, finding H2) — a subnet cannot outlive the VNet that deleted it. */
function recordVnetDelete(t: Tracked, s: Scanned): void {
  if (!VNET_DELETE_RE.test(s.op)) return;
  if (!isAzureVnetResourceId(s.resourceId)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  invalidateVnetChildren(t, lower(s.resourceId), s.time, s.locator);
}

type AnySourceToken = "*" | "0.0.0.0/0" | "::/0" | "internet";

/** The rule objects a rule-write record's own body carries: the parent form's bounded
 * `properties.securityRules[]` (never `defaultSecurityRules[]`), or the child form's own body
 * (the ONE rule it wrote, in full — #1077). */
/** Bounds by INDEX POSITION EXAMINED, never by filtering the full array first — an untrusted
 * `securityRules[]` of any length costs at most `NSG_PARENT_RULES_MAX` object checks (#1077,
 * Codex code review, finding M1: `.filter(isObject)` over the complete array before slicing did
 * not actually bound traversal). Rules beyond the bound are counted, never read. */
function ruleObjects(t: Tracked, op: string, props: Row | null): Row[] {
  if (!props) return [];
  if (NSG_WRITE_RE.test(op)) {
    const rules = getCI(props, "securityRules");
    if (!Array.isArray(rules)) return [];
    const examined = Math.min(rules.length, NSG_PARENT_RULES_MAX);
    const out: Row[] = [];
    for (let i = 0; i < examined; i += 1) if (isObject(rules[i])) out.push(rules[i] as Row);
    if (rules.length > NSG_PARENT_RULES_MAX) t.nsgRulesBeyond += rules.length - NSG_PARENT_RULES_MAX;
    return out;
  }
  if (NSG_RULE_WRITE_RE.test(op)) return [props];
  return [];
}

/** The EXACT source category a rule names, kept distinct — never collapsed into one "any source"
 * phrase (#1077, Codex design round 1, finding H3). `null` for anything not inbound-allow, or
 * whose source is a specific range rather than one of Azure's own documented wildcards. A rule's
 * own `sourceAddressPrefixes` is bounded too — further entries counted, never read (#1077, Codex
 * code review, finding M1). */
function anySourceToken(t: Tracked, rule: Row): AnySourceToken | null {
  if (lower(field(rule, "direction")) !== "inbound") return null;
  if (lower(field(rule, "access")) !== "allow") return null;
  const prefixes: string[] = [];
  const single = field(rule, "sourceAddressPrefix");
  if (single) prefixes.push(single);
  const many = getCI(rule, "sourceAddressPrefixes");
  if (Array.isArray(many)) {
    const examined = Math.min(many.length, NSG_PREFIXES_PER_RULE_MAX);
    for (let i = 0; i < examined; i += 1) prefixes.push(str(many[i]).trim());
    if (many.length > NSG_PREFIXES_PER_RULE_MAX) t.nsgRulesBeyond += many.length - NSG_PREFIXES_PER_RULE_MAX;
  }
  for (const raw of prefixes) {
    const p = raw.trim();
    if (p === "*") return "*";
    if (p === "0.0.0.0/0") return "0.0.0.0/0";
    if (p === "::/0") return "::/0";
    if (lower(p) === "internet") return "internet";
  }
  return null;
}

/** The earliest qualifying match for ONE VM against ONE qualifying rule query, or `null` — never
 * a guess when a hop's own attachment state cannot be resolved (#1077). */
function resolveNsgMatch(
  t: Tracked,
  vm: Vm,
  nsgId: string,
  token: AnySourceToken,
  query: { time: number; locator: string },
): (Omit<AzureNsgObservation, "time"> & Timed) | null {
  const nicSet = resolveAt(vm.nicSets, query);
  if (!nicSet || nicSet === "gap") return null;
  for (const nicId of nicSet.nicIds) {
    const nic: Nic | undefined = t.nics.get(nicId);
    if (!nic) continue;
    const nicState = resolveAt(nic.states, query);
    if (!nicState || nicState === "gap") continue;
    if (nicState.nsgId === nsgId)
      return {
        time: query.time,
        path: "direct",
        token,
        nsgId,
        ruleLocator: query.locator,
        nicId,
        nicLocator: nicState.locator,
      };
    if (nicState.subnetId) {
      const subnet: Subnet | undefined = t.subnets.get(nicState.subnetId);
      const subnetState = subnet ? resolveAt(subnet.states, query) : null;
      if (subnetState && subnetState !== "gap" && subnetState.nsgId === nsgId)
        return {
          time: query.time,
          path: "via-subnet",
          token,
          nsgId,
          ruleLocator: query.locator,
          nicId,
          nicLocator: nicState.locator,
          subnetId: nicState.subnetId,
          subnetLocator: subnetState.locator,
        };
    }
  }
  return null;
}

/** The NSG join itself (#1077) — a direct or via-subnet match against EVERY tracked VM, keeping
 * only the earliest qualifying observation per VM (mirrors `noteFact`'s own "earliest wins"). */
function recordNsgJoin(t: Tracked, s: Scanned): void {
  if (!NSG_WRITE_RE.test(s.op) && !NSG_RULE_WRITE_RE.test(s.op)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const nsgId = azureNsgIdForRuleRecord(s.resourceId);
  if (!nsgId) return;
  const props = requestProps(s.requestBody);
  let token: AnySourceToken | null = null;
  for (const rule of ruleObjects(t, s.op, props)) {
    token = anySourceToken(t, rule);
    if (token) break;
  }
  if (!token) return;
  const query = { time: s.time, locator: s.locator };
  for (const vm of t.vms.values()) {
    if (vm.nsgObservation && vm.nsgObservation.time <= s.time) continue;
    const match = resolveNsgMatch(t, vm, nsgId, token, query);
    if (!match) continue;
    vm.nsgObservation = match;
    noteFact(vm, "any-address-nsg-rule", match.time, match.ruleLocator);
    cite(vm, match.ruleLocator);
    cite(vm, match.nicLocator);
    if (match.subnetLocator) cite(vm, match.subnetLocator);
  }
}

/** Two or more distinct recorded-fact kinds → High; one → Medium; none → Low. */
const gradeOf = (facts: readonly AzureComputeFact[]): Severity =>
  facts.length >= 2 ? "High" : facts.length === 1 ? "Medium" : "Low";

/** One summary row per standalone VM the upload's records form a lifecycle for. */
export function azureComputeLifecycles(records: readonly Row[], uploadId: string): MappedEvent[] {
  const t: Tracked = {
    vms: new Map(),
    nics: new Map(),
    subnets: new Map(),
    subnetsByVnet: new Map(),
    untrackedRecords: 0,
    untrackedNics: 0,
    untrackedSubnets: 0,
    nsgRuleRecordsBeyond: 0,
    vnetInvalidationsBeyond: 0,
    nsgRulesBeyond: 0,
  };
  const coverage = { records: 0, first: "", last: "" };
  const scanned = scan(records, coverage);
  let nsgRuleRecordsExamined = 0;
  let vnetInvalidationsExamined = 0;
  for (const s of scanned) {
    recordWrite(t, s);
    recordVmDelete(t, s);
    recordOperation(t, s);
    recordRemote(t, s);
    recordNic(t, s);
    recordNicDelete(t, s);
    recordSubnet(t, s);
    recordSubnetDelete(t, s);
    if (VNET_WRITE_RE.test(s.op) || VNET_DELETE_RE.test(s.op)) {
      if (vnetInvalidationsExamined < VNET_INVALIDATION_RECORDS_MAX) {
        vnetInvalidationsExamined += 1;
        recordVnetWrite(t, s);
        recordVnetDelete(t, s);
      } else t.vnetInvalidationsBeyond += 1;
    }
    if (NSG_WRITE_RE.test(s.op) || NSG_RULE_WRITE_RE.test(s.op)) {
      if (nsgRuleRecordsExamined < NSG_RULE_RECORDS_MAX) {
        nsgRuleRecordsExamined += 1;
        recordNsgJoin(t, s);
      } else t.nsgRuleRecordsBeyond += 1;
    }
  }
  const findings = [...t.vms.values()]
    .map((vm) => ({ vm, facts: [...vm.facts.keys()] as AzureComputeFact[] }))
    .filter(({ vm, facts }) => vm.launch || vm.operations.count >= 2 || facts.length > 0)
    .map((f) => ({ ...f, grade: gradeOf(f.facts) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        firstTime(a.vm) - firstTime(b.vm) ||
        a.vm.vmName.localeCompare(b.vm.vmName) ||
        a.vm.subscriptionId.localeCompare(b.vm.subscriptionId) ||
        a.vm.resourceGroup.localeCompare(b.vm.resourceGroup),
    );
  const rows = findings
    .slice(0, AZURE_COMPUTE_MAX)
    .map((f) => summaryRow(f.vm, f.facts, f.grade, coverage, uploadId));
  const omitted = Math.max(0, findings.length - AZURE_COMPUTE_MAX);
  const untrackedRecords = t.untrackedRecords + t.untrackedNics + t.untrackedSubnets;
  const nsgWorkBeyond = t.nsgRuleRecordsBeyond + t.vnetInvalidationsBeyond + t.nsgRulesBeyond;
  if (omitted > 0 || untrackedRecords > 0 || nsgWorkBeyond > 0)
    rows.push(
      omittedRow(
        omitted,
        findings[AZURE_COMPUTE_MAX]?.grade ?? "Low",
        untrackedRecords,
        uploadId,
        nsgWorkBeyond,
      ),
    );
  return rows;
}
