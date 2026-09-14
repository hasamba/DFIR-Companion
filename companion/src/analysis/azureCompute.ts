// Azure VM compute lifecycle (#931 item 8 second half, #1066): what one Activity Log upload
// records about one standalone VM — the launch/update facts as the `virtualMachines/write`
// request body states them, every later recorded operation that names it, whether a managed
// identity was recorded, and the remote-access requests to it — built over the records of ONE
// upload, mirroring the shape `awsCompute.ts` established for EC2.
//
// What one row rests on, and what it never says: see canonicalAzureCompute.ts's basis sentence
// and RECOMMENDATION-1066.md's design-round-1 section. In short — identity is the VM's own
// resourceId, never a display name; a recorded operation is never a fabricated before/after
// transition; no network-security-group join is made (#1073); an unsuccessful call is an attempt,
// never a joined fact; the grade counts distinct recorded-fact kinds (2+ → High, 1 → Medium,
// 0 → Low), and no single record makes a High.

import type { Severity } from "./stateTypes.js";
import type { AzureComputeFact, AzureComputeLaunch } from "./canonicalAzureCompute.js";
import { parseAzureRequestBody } from "./loggingChangeCloud.js";
import { getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import {
  AZURE_COMPUTE_MAX,
  NICS_MAX,
  RANK,
  azureAttemptOutcome,
  cite,
  field,
  firstTime,
  noteFact,
  parseAzureVmResourceId,
  vmFor,
  type Operation,
  type Row,
  type Tracked,
} from "./azureComputeState.js";
import { omittedRow, summaryRow } from "./azureComputeRow.js";

export { AZURE_COMPUTE_MAX, VMS_TRACKED_MAX } from "./azureComputeState.js";

interface Scanned {
  rec: Row;
  index: number;
  time: number;
  op: string;
  resourceId: string;
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

/** Every Azure record naming a standalone VM, in time order (record position as tie-breaker). */
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
    if (!vmId) return;
    const observed = pickStr(rec, ["eventTimestamp", "time", "TimeGenerated", "timeStamp"]);
    const t = normalizeTime(observed);
    const time = Date.parse(t);
    if (!Number.isFinite(time)) return;
    coverage.records += 1;
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
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

function recordWrite(t: Tracked, s: Scanned): void {
  if (!/microsoft\.compute\/virtualmachines\/write$/i.test(s.op)) return;
  if (azureAttemptOutcome(s.status) !== "success") return;
  const vm = vmFor(t, s.vmId!.subscriptionId, s.vmId!.resourceGroup, s.vmId!.vmName);
  if (!vm) return;
  const body = parseAzureRequestBody(s.requestBody);
  const { launch, identityAssigned } = launchFacts(s, body);
  if (!vm.launch) vm.launch = { ...launch, time: s.time };
  if (identityAssigned) noteFact(vm, "identity-assigned", s.time, s.locator);
  cite(vm, s.locator);
}

const OPERATION_RE: Record<"start" | "deallocate" | "delete", RegExp> = {
  start: /microsoft\.compute\/virtualmachines\/start\/action$/i,
  deallocate: /microsoft\.compute\/virtualmachines\/deallocate\/action$/i,
  delete: /microsoft\.compute\/virtualmachines\/delete$/i,
};

function recordOperation(t: Tracked, s: Scanned): void {
  const entry = Object.entries(OPERATION_RE).find(([, re]) => re.test(s.op));
  if (!entry) return;
  const kind = entry[0] as "start" | "deallocate" | "delete";
  const vm = vmFor(t, s.vmId!.subscriptionId, s.vmId!.resourceGroup, s.vmId!.vmName);
  if (!vm) return;
  if (azureAttemptOutcome(s.status) !== "success") {
    vm.notSucceeded += 1;
    return;
  }
  const op: Operation = { kind, call: s.op, time: s.time, locator: s.locator, by: s.by };
  vm.operations.push(op);
  cite(vm, s.locator);
}

// The same Run Command operation match `cloudActivityImport.ts`'s `azureRemoteExecutionTarget`
// uses — matched directly here, never by importing that helper, since its return `id` is a
// different string SHAPE (the full lowercased resource path, not this join's `sub|rg|vm` key) and
// importing it would create a cycle (`cloudActivityImport.ts` wires this join in). Because `scan()`
// above already requires a record's OWN `resourceId` to parse as a standalone VM before it is kept
// at all — true for both the "action" form (`resourceId` IS the VM) and the "managed" form
// (`resourceId` is `<vm>/runCommands/<name>`, and the VM-id regex is not end-anchored) — no
// separate target-resolution step is needed: `s.vmId` already IS the Run Command's target.
const RUN_COMMAND_RE = /virtualmachines(?:\/[^/]+)?\/runcommands?\/(?:action|write)/i;

function recordRemote(t: Tracked, s: Scanned): void {
  if (!RUN_COMMAND_RE.test(s.op)) return;
  const vm = vmFor(t, s.vmId!.subscriptionId, s.vmId!.resourceGroup, s.vmId!.vmName);
  if (!vm) return;
  if (azureAttemptOutcome(s.status) !== "success") {
    vm.notSucceeded += 1;
    return;
  }
  vm.remote.push({ call: s.op, time: s.time, locator: s.locator, by: s.by });
  noteFact(vm, "remote-access-request", s.time, s.locator);
  cite(vm, s.locator);
}

/** Two or more distinct recorded-fact kinds → High; one → Medium; none → Low. */
const gradeOf = (facts: readonly AzureComputeFact[]): Severity =>
  facts.length >= 2 ? "High" : facts.length === 1 ? "Medium" : "Low";

/** One summary row per standalone VM the upload's records form a lifecycle for. */
export function azureComputeLifecycles(records: readonly Row[], uploadId: string): MappedEvent[] {
  const t: Tracked = { vms: new Map(), untrackedRecords: 0 };
  const coverage = { records: 0, first: "", last: "" };
  const scanned = scan(records, coverage);
  for (const s of scanned) {
    recordWrite(t, s);
    recordOperation(t, s);
    recordRemote(t, s);
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
  if (omitted > 0 || t.untrackedRecords > 0)
    rows.push(omittedRow(omitted, findings[AZURE_COMPUTE_MAX]?.grade ?? "Low", t.untrackedRecords, uploadId));
  return rows;
}
