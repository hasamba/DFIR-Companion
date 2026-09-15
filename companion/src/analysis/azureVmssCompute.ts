// Azure VMSS-member compute lifecycle (#931 item 8, #1078): what one Activity Log upload records
// about one Uniform-mode VM-scale-set member — the launch/update facts as the member's own write
// request body states them, every later recorded operation that names it, whether a managed
// identity was recorded, and the remote-access requests to it — built over the records of ONE
// upload, mirroring the shape `azureCompute.ts` established for standalone VMs.
//
// What one row rests on, and what it never says: see azureVmssComputeState.ts's own BASIS/LIMIT_NOTE
// and RECOMMENDATION-1078.md's design-round-1 section. In short — identity is a 4-tuple
// (subscription, resource group, scale-set name, instance id), never the standalone 3-tuple; a
// Flexible-orchestration member (its own record carries `virtualMachineResourceId`) is skipped
// entirely, not merely under-covered; each row is one OBSERVED lifecycle epoch bounded at a
// successful delete, never a claim of a proven distinct physical machine; an unsuccessful call is
// an attempt, never a joined fact; the grade counts distinct recorded-fact kinds (2+ → High,
// 1 → Medium, 0 → Low), and no single record makes a High.

import type { Severity } from "./stateTypes.js";
import type { AzureComputeLaunch, AzureVmssComputeFact } from "./canonicalAzureCompute.js";
import { parseAzureRequestBody } from "./loggingChangeCloud.js";
import { AZURE_RUN_COMMAND_RE, NICS_MAX, azureAttemptOutcome } from "./azureComputeState.js";
import { getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import {
  RANK,
  VMSS_COMPUTE_MAX,
  VMSS_REMOTE_MAX,
  cite,
  epochFor,
  field,
  firstTime,
  isAzureNicResourceId,
  memberFor,
  noteFact,
  parseAzureVmssMemberResourceId,
  type Operation,
  type Row,
  type Tracked,
} from "./azureVmssComputeState.js";
import { omittedRow, summaryRow } from "./azureVmssComputeRow.js";

export { VMSS_COMPUTE_MAX, VMSS_MEMBERS_TRACKED_MAX } from "./azureVmssComputeState.js";

interface Scanned {
  rec: Row;
  index: number;
  time: number;
  op: string;
  resourceId: string;
  memberId: { subscriptionId: string; resourceGroup: string; setName: string; instanceId: string } | null;
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

/** Every Azure record naming a VMSS member, in time order (record position as tie-breaker). The
 * upload's own coverage window is VMSS-member-only, its own separate meaning from the standalone
 * pass's own coverage — never blended with it. */
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
    const memberId = parseAzureVmssMemberResourceId(resourceId);
    if (!memberId) return;
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
      memberId,
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

/** A Flexible-orchestration member's own body carries `properties.virtualMachineResourceId`,
 * aliasing the same physical machine under the standalone `Microsoft.Compute/virtualMachines`
 * resource type #1066 already tracks (#1078, design-round-1, finding M3). This join is Uniform-only
 * — a record carrying that field is never tracked, and once seen, the whole member is marked
 * `flexible` so later records for the SAME member (which may lack a body to re-check) are skipped
 * too, on the reasonable assumption that a member's own orchestration mode does not change mid-upload. */
function isFlexibleModeBody(body: Row | null): boolean {
  return !!(body && field(body, "properties", "virtualMachineResourceId"));
}

function launchFacts(
  s: Scanned,
  body: Row | null,
): { launch: Omit<AzureComputeLaunch, "time">; identityAssigned: boolean } {
  const props = body && isObject(getCI(body, "properties")) ? (getCI(body, "properties") as Row) : {};
  const networkProfile = isObject(getCI(props, "networkProfile"))
    ? (getCI(props, "networkProfile") as Row)
    : {};
  // ONLY networkProfile.networkInterfaces[] is read — networkProfileConfiguration holds NIC
  // CONFIGURATION TEMPLATES, never NIC resource references (#1078, Codex design round 1, finding
  // M2: reading an `id` from a template would misreport a template name as a NIC id).
  const nicList = getCI(networkProfile, "networkInterfaces");
  const nics: string[] = [];
  if (Array.isArray(nicList)) {
    // Bounded by INDEX POSITION EXAMINED, never filter-then-slice over an untrusted full array
    // (mirrors #1077's own code-round fix for the exact same class of bug).
    const examined = Math.min(nicList.length, NICS_MAX);
    for (let i = 0; i < examined; i += 1) {
      const entry = nicList[i];
      if (!isObject(entry)) continue;
      const id = field(entry, "id");
      if (id && isAzureNicResourceId(id)) nics.push(id);
    }
  }
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

const WRITE_RE = /microsoft\.compute\/virtualmachinescalesets\/virtualmachines\/write$/i;

function recordWrite(t: Tracked, s: Scanned): void {
  if (!s.memberId || !WRITE_RE.test(s.op)) return;
  const member = memberFor(
    t,
    s.memberId.subscriptionId,
    s.memberId.resourceGroup,
    s.memberId.setName,
    s.memberId.instanceId,
  );
  if (!member || member.flexible) return;
  const success = azureAttemptOutcome(s.status) === "success";
  const body = parseAzureRequestBody(s.requestBody);
  if (isFlexibleModeBody(body)) {
    member.flexible = true;
    return;
  }
  if (!success) return;
  const epoch = epochFor(t, member, false, true);
  if (!epoch) return;
  const { launch, identityAssigned } = launchFacts(s, body);
  if (!epoch.launch) epoch.launch = { ...launch, time: s.time };
  if (identityAssigned) noteFact(epoch, "identity-assigned", s.time, s.locator);
  cite(epoch, s.locator);
}

const OPERATION_RE: Record<"start" | "deallocate" | "delete", RegExp> = {
  start: /microsoft\.compute\/virtualmachinescalesets\/virtualmachines\/start\/action$/i,
  deallocate: /microsoft\.compute\/virtualmachinescalesets\/virtualmachines\/deallocate\/action$/i,
  delete: /microsoft\.compute\/virtualmachinescalesets\/virtualmachines\/delete$/i,
};

function recordOperation(t: Tracked, s: Scanned): void {
  if (!s.memberId) return;
  const entry = Object.entries(OPERATION_RE).find(([, re]) => re.test(s.op));
  if (!entry) return;
  const kind = entry[0] as "start" | "deallocate" | "delete";
  const member = memberFor(
    t,
    s.memberId.subscriptionId,
    s.memberId.resourceGroup,
    s.memberId.setName,
    s.memberId.instanceId,
  );
  if (!member || member.flexible) return;
  const success = azureAttemptOutcome(s.status) === "success";
  const epoch = epochFor(t, member, kind === "delete", success);
  if (!epoch) return;
  if (!success) {
    epoch.notSucceeded += 1;
    return;
  }
  const op: Operation = { kind, call: s.op, time: s.time, locator: s.locator, by: s.by };
  epoch.operations.push(op);
  cite(epoch, s.locator);
}

// Reuses the SAME AZURE_RUN_COMMAND_RE the standalone pass and cloudActivityImport.ts already
// share (#1066's own finding #8 discipline, extended here rather than duplicated).
function recordRemote(t: Tracked, s: Scanned): void {
  if (!s.memberId || !AZURE_RUN_COMMAND_RE.test(s.op)) return;
  const member = memberFor(
    t,
    s.memberId.subscriptionId,
    s.memberId.resourceGroup,
    s.memberId.setName,
    s.memberId.instanceId,
  );
  if (!member || member.flexible) return;
  const success = azureAttemptOutcome(s.status) === "success";
  const epoch = epochFor(t, member, false, success);
  if (!epoch) return;
  if (!success) {
    epoch.notSucceeded += 1;
    return;
  }
  if (epoch.remote.length < VMSS_REMOTE_MAX)
    epoch.remote.push({ call: s.op, time: s.time, locator: s.locator, by: s.by });
  else epoch.remoteBeyond += 1;
  noteFact(epoch, "remote-access-request", s.time, s.locator);
  cite(epoch, s.locator);
}

/** Two or more distinct recorded-fact kinds → High; one → Medium; none → Low. */
const gradeOf = (facts: readonly AzureVmssComputeFact[]): Severity =>
  facts.length >= 2 ? "High" : facts.length === 1 ? "Medium" : "Low";

/** One summary row per Uniform-mode VMSS member EPOCH the upload's records form a lifecycle for. */
export function azureVmssComputeLifecycles(records: readonly Row[], uploadId: string): MappedEvent[] {
  const t: Tracked = { members: new Map(), untrackedRecords: 0, epochsTracked: 0 };
  const coverage = { records: 0, first: "", last: "" };
  const scanned = scan(records, coverage);
  for (const s of scanned) {
    recordWrite(t, s);
    recordOperation(t, s);
    recordRemote(t, s);
  }
  const findings = [...t.members.values()]
    .flatMap((member) =>
      member.epochs.map((epoch) => ({
        member,
        epoch,
        facts: [...epoch.facts.keys()] as AzureVmssComputeFact[],
      })),
    )
    .filter(({ epoch, facts }) => epoch.launch || epoch.operations.count >= 2 || facts.length > 0)
    .map((f) => ({ ...f, grade: gradeOf(f.facts) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        firstTime(a.epoch) - firstTime(b.epoch) ||
        a.member.setName.localeCompare(b.member.setName) ||
        a.member.instanceId.localeCompare(b.member.instanceId) ||
        a.epoch.index - b.epoch.index,
    );
  const rows = findings
    .slice(0, VMSS_COMPUTE_MAX)
    .map((f) => summaryRow(f.member, f.epoch, f.facts, f.grade, coverage, uploadId));
  const omitted = Math.max(0, findings.length - VMSS_COMPUTE_MAX);
  const epochsBeyond = [...t.members.values()].reduce((n, m) => n + m.epochsBeyond, 0);
  if (omitted > 0 || t.untrackedRecords > 0 || epochsBeyond > 0)
    rows.push(
      omittedRow(
        omitted,
        findings[VMSS_COMPUTE_MAX]?.grade ?? "Low",
        t.untrackedRecords,
        uploadId,
        epochsBeyond,
      ),
    );
  return rows;
}
