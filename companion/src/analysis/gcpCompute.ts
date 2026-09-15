// GCP instance compute lifecycle (#931 item 8 second half, #1066): what one Cloud Audit Log
// upload records about one instance — the launch facts as the `instances.insert` request states
// them, every later recorded operation that names it, a metadata-replaced fact (presence only),
// a service-account-attachment fact reusing #1065's own decode, and the calls recorded from that
// attached email while it was recorded as attached — built over the records of ONE upload,
// mirroring the shape `awsCompute.ts` established for EC2.
//
// What one row rests on, and what it never says: see canonicalGcpCompute.ts's basis sentence and
// RECOMMENDATION-1066.md's design-round-1 section. In short — identity requires the FULL
// documented `projects/<p>/zones/<z>/instances/<n>` resourceName shape, never guessed from
// `request.name` alone; a recorded operation is never a fabricated before/after transition; an
// unsuccessful call is an attempt, never a joined fact; an attached email's calls are never
// claimed unique to this instance — the same account may be attached elsewhere this upload cannot
// see; the "privileged call" fact names ONE specific check (a High entry in the shared GCP_RULES
// table), never the record's own final imported severity; the grade counts distinct recorded-fact
// kinds (2+ → High, 1 → Medium, 0 → Low), and no single record makes a High.
//
// The firewall join (#1073, RECOMMENDATION-1073.md's design-round-1 section) is deliberately
// narrow: only `firewalls.insert`/`.update` (never `.patch` — a partial update whose absent
// fields this stateless decoder cannot read as "confirmed absent") naming NEITHER target tags NOR
// target service accounts (GCP's own documented "applies to every instance on the network"
// default) joins, by EXACT literal network-string match against the instance's own FIRST network
// interface (#1066's own launch capture) — no cross-project Shared-VPC resolution is attempted; a
// mismatched project token in the two records' own network strings simply does not join. The
// wording never claims traffic is reaching the instance: a higher-priority deny rule or a
// hierarchical firewall policy are not evaluated. Azure's NSG join and VM-scale-set support were
// both dropped from this item as unsound on the available evidence — see #1077, #1078.

import type { Severity } from "./stateTypes.js";
import type { GcpComputeFact, GcpComputeLaunch } from "./canonicalGcpCompute.js";
import { decodeGcpWorkloadAttachment } from "./gcpWorkloadAttachment.js";
import { matchGcpRule } from "./gcpSeverityRules.js";
import { getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";
import {
  GCP_COMPUTE_MAX,
  METADATA_KEYS_MAX,
  RANK,
  attachedInterval,
  cite,
  closeAttachment,
  field,
  firstTime,
  gcpAttemptOutcome,
  instanceFor,
  lower,
  noteFact,
  openAttachment,
  parseGcpFirewallResourceName,
  parseGcpInstanceResourceName,
  tallySession,
  type Instance,
  type Operation,
  type Row,
  type Tracked,
} from "./gcpComputeState.js";
import { omittedRow, summaryRow } from "./gcpComputeRow.js";

export { GCP_COMPUTE_MAX, INSTANCES_TRACKED_MAX } from "./gcpComputeState.js";

interface Scanned {
  rec: Row;
  pp: Row;
  index: number;
  time: number;
  method: string;
  service: string;
  principal: string;
  locator: string;
}

/** Every GCP record with a decodable protoPayload, in time order (record position as tie-breaker). */
function scan(
  records: readonly Row[],
  coverage: { records: number; first: string; last: string },
): Scanned[] {
  const out: Scanned[] = [];
  records.forEach((rec, index) => {
    if (!isObject(rec)) return;
    const pp = isObject(getCI(rec, "protoPayload"))
      ? (getCI(rec, "protoPayload") as Row)
      : isObject(getCI(rec, "jsonPayload"))
        ? (getCI(rec, "jsonPayload") as Row)
        : null;
    if (!pp) return;
    const method = str(getCI(pp, "methodName")).trim();
    const service = str(getCI(pp, "serviceName")).trim();
    if (!method) return;
    const t = normalizeTime(str(getCI(pp, "timestamp")) || str(getCI(rec, "timestamp")));
    const time = Date.parse(t);
    if (!Number.isFinite(time)) return;
    coverage.records += 1;
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    out.push({
      rec,
      pp,
      index,
      time,
      method,
      service,
      principal: str(getPath(pp, "authenticationInfo.principalEmail")).trim(),
      locator: `record:${index}`,
    });
  });
  return out.sort((a, b) => a.time - b.time || a.index - b.index);
}

/** Method-name TAIL match, gated on the compute service first — never a bare substring (mirrors gcpWorkloadAttachment.ts). */
const isCompute = (s: Scanned): boolean => lower(s.service) === "compute.googleapis.com";
const tail = (re: RegExp, method: string): boolean => re.test(lower(method));
const INSERT_RE = /(^|\.)instances\.insert$/;
const START_RE = /(^|\.)instances\.start$/;
const STOP_RE = /(^|\.)instances\.stop$/;
const DELETE_RE = /(^|\.)instances\.delete$/;
const SET_METADATA_RE = /(^|\.)instances\.setmetadata$/;
const SET_SA_RE = /(^|\.)instances\.setserviceaccount$/;
// Deliberately no regex for `firewalls.patch` — a partial update whose absent fields this
// stateless decoder cannot read as "confirmed absent" (RECOMMENDATION-1073.md, finding H2).
const FIREWALL_INSERT_RE = /(^|\.)firewalls\.insert$/;
const FIREWALL_UPDATE_RE = /(^|\.)firewalls\.update$/;
const GOOGLE_API_PREFIX = "https://www.googleapis.com/compute/v1/";

/**
 * Resolves a network reference to a project-qualified identity. GCP treats a bare
 * `global/networks/<n>` reference as relative to the RECORD'S OWN project — two different
 * projects' identically-named networks (e.g. both named "default") must never collide just
 * because both requests happened to use the short form (Codex code review, finding H2). A
 * reference already qualified with a `projects/<p>/...` prefix (or the full API-URL form) is
 * left as its own project, never overridden by `project`.
 */
function resolveNetworkIdentity(raw: string, project: string): string {
  const trimmed = raw.trim();
  const stripped = trimmed.startsWith(GOOGLE_API_PREFIX) ? trimmed.slice(GOOGLE_API_PREFIX.length) : trimmed;
  return stripped.startsWith("projects/") ? stripped : `projects/${lower(project)}/${stripped}`;
}

/** True only when NEITHER target mechanism is present — GCP's documented network-wide default (finding H1). */
function firewallAppliesNetworkWide(request: Row): boolean {
  const tags = getCI(request, "targetTags");
  const accounts = getCI(request, "targetServiceAccounts");
  const hasTags = Array.isArray(tags) && tags.length > 0;
  const hasAccounts = Array.isArray(accounts) && accounts.length > 0;
  return !hasTags && !hasAccounts;
}

/**
 * Reads an array field under either of two possible spellings — no fixture of a real captured
 * GCP Cloud Audit Log firewall record exists to confirm which one is used (Codex code review,
 * finding H1: the REST resource itself is documented as singular `allowed`/`denied`, but a
 * sourced third-party audit-log field mapping documents the audit record itself as pluralized
 * `alloweds`/`denieds`). Checking both costs nothing and can only avoid a false negative — it
 * never manufactures a fact that isn't there, since the semantics checked are identical either way.
 */
function arrayField(o: Row, primary: string, alt: string): unknown[] {
  const p = getCI(o, primary);
  if (Array.isArray(p)) return p;
  const a = getCI(o, alt);
  return Array.isArray(a) ? a : [];
}

/** Enabled, ingress, allow (never deny) for a matching source admitting 0.0.0.0/0 or ::/0. */
function firewallAllowsAnySource(request: Row): boolean {
  if (str(getCI(request, "disabled")).trim().toLowerCase() === "true") return false;
  const direction = field(request, "direction") || "INGRESS";
  if (direction.toUpperCase() !== "INGRESS") return false;
  if (arrayField(request, "denied", "denieds").length > 0) return false;
  const allowed = arrayField(request, "allowed", "alloweds");
  if (allowed.length === 0) return false;
  const ranges = getCI(request, "sourceRanges");
  if (!Array.isArray(ranges)) return false;
  return ranges.some((r) => {
    const v = str(r).trim();
    return v === "0.0.0.0/0" || v === "::/0";
  });
}

function launchFacts(request: Row, locator: string, by: string): Omit<GcpComputeLaunch, "time"> {
  const disks = getCI(request, "disks");
  const firstDisk = (Array.isArray(disks) ? disks : []).find(isObject);
  const nics = getCI(request, "networkInterfaces");
  const firstNic = (Array.isArray(nics) ? nics : []).find(isObject);
  const metadata = getCI(request, "metadata");
  const items = isObject(metadata) ? getCI(metadata, "items") : undefined;
  const metadataKeys = (Array.isArray(items) ? items : [])
    .filter(isObject)
    .map((i) => field(i, "key"))
    .filter(Boolean)
    .slice(0, METADATA_KEYS_MAX);
  return {
    locators: [locator],
    by,
    machineType: field(request, "machineType") || undefined,
    sourceImage: firstDisk ? field(firstDisk, "initializeParams", "sourceImage") || undefined : undefined,
    network: firstNic ? field(firstNic, "network") || undefined : undefined,
    subnetwork: firstNic ? field(firstNic, "subnetwork") || undefined : undefined,
    metadataKeys,
  };
}

function recordCompute(t: Tracked, s: Scanned): void {
  const resourceName = field(s.pp, "resourceName");
  const id = parseGcpInstanceResourceName(resourceName);
  if (!id) return;
  const inst = instanceFor(t, id.project, id.zone, id.instanceName);
  if (!inst) return;
  const request = isObject(getCI(s.pp, "request")) ? (getCI(s.pp, "request") as Row) : {};
  const by = s.principal || "(principal not recorded)";
  const success = gcpAttemptOutcome(s.pp) === "success";

  if (tail(INSERT_RE, s.method)) {
    if (success) {
      if (!inst.launch) inst.launch = { ...launchFacts(request, s.locator, by), time: s.time };
      cite(inst, s.locator);
    } else inst.notSucceeded += 1;
  } else if (tail(SET_METADATA_RE, s.method)) {
    if (success) {
      const op: Operation = {
        kind: "metadata-replaced",
        call: s.method,
        time: s.time,
        locator: s.locator,
        by,
      };
      inst.operations.push(op);
      noteFact(inst, "metadata-replaced", s.time, s.locator);
      cite(inst, s.locator);
    } else inst.notSucceeded += 1;
  } else if (tail(START_RE, s.method) || tail(STOP_RE, s.method) || tail(DELETE_RE, s.method)) {
    if (success) {
      const kind = tail(START_RE, s.method) ? "start" : tail(STOP_RE, s.method) ? "stop" : "delete";
      const op: Operation = { kind, call: s.method, time: s.time, locator: s.locator, by };
      inst.operations.push(op);
      cite(inst, s.locator);
    } else inst.notSucceeded += 1;
  }

  // The attachment ITSELF is #1065's own decode, called unmodified — never re-parsed here.
  for (const reading of decodeGcpWorkloadAttachment(s.pp, s.service, s.method)) {
    if (reading.attachment.workloadKind !== "gce-instance") continue;
    const target = parseGcpInstanceResourceName(reading.attachment.workloadName ?? "");
    if (
      !target ||
      target.instanceName.toLowerCase() !== id.instanceName.toLowerCase() ||
      target.project !== id.project ||
      target.zone !== id.zone
    )
      continue;
    openAttachment(inst, reading.serviceAccount.email, s.time, s.locator);
    noteFact(inst, "service-account-attached", s.time, s.locator);
    cite(inst, s.locator);
  }
  // Detachment: `setServiceAccount` succeeded but named no email. Reading `request.email`'s
  // EMPTINESS here is narrower than decoding the attachment itself (#1065's own job) — it never
  // re-parses which account WAS attached, only whether this call cleared it.
  if (tail(SET_SA_RE, s.method) && success && !field(request, "email")) {
    closeAttachment(inst, s.time);
    cite(inst, s.locator);
  }
}

/** Two or more distinct recorded-fact kinds → High; one → Medium; none → Low. */
const gradeOf = (facts: readonly GcpComputeFact[]): Severity =>
  facts.length >= 2 ? "High" : facts.length === 1 ? "Medium" : "Low";

/** One summary row per instance the upload's records form a lifecycle for. */
export function gcpComputeLifecycles(records: readonly Row[], uploadId: string): MappedEvent[] {
  const t: Tracked = { instances: new Map(), untrackedRecords: 0 };
  const coverage = { records: 0, first: "", last: "" };
  const scanned = scan(records, coverage);

  // Pass 1: launches, operations, metadata and attachment intervals — compute-service records only.
  for (const s of scanned) if (isCompute(s)) recordCompute(t, s);

  // Index instances by every email they have ever had attached, so pass 2 checks only the few
  // instances a record's principal could possibly belong to — never every tracked instance.
  const byEmail = new Map<string, Instance[]>();
  for (const inst of t.instances.values())
    for (const a of new Set(inst.attachments.map((a) => lower(a.email))))
      (byEmail.get(a) ?? byEmail.set(a, []).get(a)!).push(inst);

  // Pass 2: calls recorded from an attached email, over EVERY GCP record of this upload (not only
  // compute-service ones) — an attached identity can act against any other GCP service. Gated on
  // the SAME outcome function as pass 1 (Codex code review, finding #1): a denied call joins
  // nothing and is tallied only as an attempt, never a session record or a privileged-call fact.
  for (const s of scanned) {
    if (!s.principal) continue;
    const candidates = byEmail.get(lower(s.principal));
    if (!candidates) continue;
    const success = gcpAttemptOutcome(s.pp) === "success";
    for (const inst of candidates) {
      const interval = attachedInterval(inst, s.principal, s.time);
      if (!interval) continue;
      if (!success) {
        inst.notSucceeded += 1;
        continue;
      }
      tallySession(inst, interval, s.time, s.locator, `${s.service} ${s.method}`);
      if (matchGcpRule(s.method)?.severity === "High")
        noteFact(inst, "session-privileged-change", s.time, s.locator);
      cite(inst, s.locator);
    }
  }

  // Pass 3: the firewall join (#1073) — a network-wide, allow-any-source insert/update rule joins
  // by EXACT literal network-string match against the instance's own first network interface.
  const byNetwork = new Map<string, Instance[]>();
  for (const inst of t.instances.values()) {
    const network = inst.launch?.network;
    if (!network) continue;
    const key = resolveNetworkIdentity(network, inst.project);
    (byNetwork.get(key) ?? byNetwork.set(key, []).get(key)!).push(inst);
  }
  if (byNetwork.size > 0) {
    for (const s of scanned) {
      if (!isCompute(s)) continue;
      if (!tail(FIREWALL_INSERT_RE, s.method) && !tail(FIREWALL_UPDATE_RE, s.method)) continue;
      if (gcpAttemptOutcome(s.pp) !== "success") continue;
      const firewallId = parseGcpFirewallResourceName(field(s.pp, "resourceName"));
      if (!firewallId) continue;
      const request = isObject(getCI(s.pp, "request")) ? (getCI(s.pp, "request") as Row) : {};
      if (!firewallAppliesNetworkWide(request)) continue;
      if (!firewallAllowsAnySource(request)) continue;
      const network = field(request, "network");
      if (!network) continue;
      const matches = byNetwork.get(resolveNetworkIdentity(network, firewallId.project));
      if (!matches) continue;
      for (const inst of matches) {
        noteFact(inst, "any-address-firewall-rule", s.time, s.locator);
        cite(inst, s.locator);
      }
    }
  }

  const findings = [...t.instances.values()]
    .map((inst) => ({ inst, facts: [...inst.facts.keys()] as GcpComputeFact[] }))
    .filter(({ inst, facts }) => inst.launch || inst.operations.count >= 2 || facts.length > 0)
    .map((f) => ({ ...f, grade: gradeOf(f.facts) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] ||
        firstTime(a.inst) - firstTime(b.inst) ||
        a.inst.instanceName.localeCompare(b.inst.instanceName) ||
        a.inst.project.localeCompare(b.inst.project) ||
        a.inst.zone.localeCompare(b.inst.zone),
    );
  const rows = findings
    .slice(0, GCP_COMPUTE_MAX)
    .map((f) => summaryRow(f.inst, f.facts, f.grade, coverage, uploadId));
  const omitted = Math.max(0, findings.length - GCP_COMPUTE_MAX);
  if (omitted > 0 || t.untrackedRecords > 0)
    rows.push(omittedRow(omitted, findings[GCP_COMPUTE_MAX]?.grade ?? "Low", t.untrackedRecords, uploadId));
  return rows;
}
