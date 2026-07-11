// Deterministic importer for Kubernetes API-server AUDIT LOGS (`audit.k8s.io`) — the first
// container-orchestration ingest path; no AI call.
//
// The API server writes one JSON `Event` object per request (JSON-lines, a `{ kind: "EventList",
// items: [...] }` batch, or a plain array — all unwrapped by `extractRecords`). Each event carries
// no maliciousness verdict, so — like the AWS/GCP/Azure importers — severity is DERIVED from the
// request: a curated map of high-signal `(verb, resource, subresource)` tuples → severity + MITRE
// (pod exec/attach, secret access, RBAC changes, privileged-pod creation, anonymous API access).
// Everything else is Info evidence, keeping the timeline signal-rich on a mostly-benign control
// plane. Sourced from the Anthropic-Cybersecurity-Skills `analyzing-kubernetes-audit-logs`
// (Apache-2.0) detection taxonomy; consumed as a VERDICT OVERLAY, NOT re-implemented as a detection
// engine. The event reads its OWN time (`requestReceivedTimestamp`), never the import time.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  worst,
  str,
  isObject,
  getCI,
  getPath,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface K8sAuditImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface K8sAuditParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "k8s-audit" | "empty"
}

const RBAC_RESOURCES = new Set(["clusterroles", "clusterrolebindings", "roles", "rolebindings"]);
const ANON_USERS = new Set(["system:anonymous", "system:unauthenticated"]);
const WRITE_VERBS = new Set(["create", "update", "patch", "delete", "deletecollection"]);

function truthy(v: unknown): boolean { return v === true || /^(true|1|yes)$/i.test(str(v).trim()); }

// k8s audit timestamps are RFC3339 with MICROSECOND precision (`…000000Z`); normalize to the
// millisecond ISO the rest of the timeline uses so ordering/rendering stays consistent.
function isoTime(raw: string): string {
  const n = normalizeTime(raw);
  const d = new Date(n);
  return Number.isNaN(d.getTime()) ? n : d.toISOString();
}

// A pod spec is "privileged" (container-escape risk) if any container runs privileged, or the pod
// shares the host's PID/network/IPC namespace or mounts a hostPath — the classic escape primitives.
function isPrivilegedPodSpec(reqObj: unknown): boolean {
  const spec = isObject(reqObj) ? getCI(reqObj, "spec") : undefined;
  if (!isObject(spec)) return false;
  if (truthy(getCI(spec, "hostPID")) || truthy(getCI(spec, "hostNetwork")) || truthy(getCI(spec, "hostIPC"))) return true;
  const groups = [getCI(spec, "containers"), getCI(spec, "initContainers"), getCI(spec, "ephemeralContainers")];
  for (const g of groups) {
    if (!Array.isArray(g)) continue;
    for (const c of g) {
      const sc = isObject(c) ? getCI(c, "securityContext") : undefined;
      if (isObject(sc) && (truthy(getCI(sc, "privileged")) || truthy(getPath(sc, "allowPrivilegeEscalation")))) return true;
      const caps = isObject(sc) ? getPath(sc, "capabilities.add") : undefined;
      if (Array.isArray(caps) && caps.some((x) => /^(sys_admin|all|net_admin|sys_ptrace)$/i.test(str(x)))) return true;
    }
  }
  const volumes = getCI(spec, "volumes");
  if (Array.isArray(volumes) && volumes.some((v) => isObject(v) && getCI(v, "hostPath") != null)) return true;
  return false;
}

// Curated (verb, resource, subresource) → severity + MITRE. Everything not matched is Info evidence.
function classify(
  verb: string,
  resource: string,
  subresource: string,
  username: string,
  code: number,
  reqObj: unknown,
): { severity: Severity; mitre: string[] } {
  const v = verb.toLowerCase();
  const r = resource.toLowerCase();
  const sub = subresource.toLowerCase();
  const succeeded = code === 0 || (code >= 200 && code < 300);

  // Anonymous / unauthenticated API access that SUCCEEDED — a serious exposure (T1078).
  if (ANON_USERS.has(username.toLowerCase())) {
    return succeeded ? { severity: "High", mitre: ["T1078"] } : { severity: "Low", mitre: ["T1078"] };
  }
  // Shell into a running container (kubectl exec/attach) — T1609 Container Administration Command.
  if (sub === "exec" || sub === "attach") return { severity: "High", mitre: ["T1609"] };
  // Cluster secret access — T1552.007. Bulk (list) / destructive (delete) rank above a single read.
  if (r === "secrets") {
    return (v === "list" || v === "delete" || v === "watch")
      ? { severity: "High", mitre: ["T1552.007"] }
      : { severity: "Medium", mitre: ["T1552.007"] };
  }
  // RBAC grant/modification — T1098. Cluster-wide roles/bindings outrank namespaced ones.
  if (RBAC_RESOURCES.has(r) && WRITE_VERBS.has(v)) {
    return r.startsWith("cluster")
      ? { severity: "Critical", mitre: ["T1098", "T1098.003"] }
      : { severity: "High", mitre: ["T1098.003"] };
  }
  // Privileged-pod creation (privileged container / host namespace / hostPath) — container escape.
  if (r === "pods" && (v === "create" || v === "update") && isPrivilegedPodSpec(reqObj)) {
    return { severity: "High", mitre: ["T1610", "T1611"] };
  }
  // A forbidden/denied request (403/401) — reconnaissance / access probing.
  if (code === 403 || code === 401) return { severity: "Low", mitre: [] };
  return { severity: "Info", mitre: [] };
}

function mapRecord(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const verb = str(getCI(rec, "verb"));
  const objectRef = getCI(rec, "objectRef");
  if (!verb || !isObject(objectRef)) return null;

  const resource = str(getCI(objectRef, "resource"));
  const subresource = str(getCI(objectRef, "subresource"));
  const namespace = str(getCI(objectRef, "namespace"));
  const objName = str(getCI(objectRef, "name"));
  const username = str(getPath(rec, "user.username"));
  const code = Number(getPath(rec, "responseStatus.code")) || 0;
  const reason = str(getPath(rec, "responseStatus.reason"));
  const reqObj = getCI(rec, "requestObject");

  const ips = getCI(rec, "sourceIPs");
  const rawIp = Array.isArray(ips) ? str(ips[0]) : str(getCI(rec, "sourceIPs"));
  const ip = cleanIp(rawIp);

  const { severity, mitre } = classify(verb, resource, subresource, username, code, reqObj);

  if (ip) addIoc(sink, "ip", ip);

  const resLabel = subresource ? `${resource}/${subresource}` : (resource || "?");
  let description = `K8s ${verb} ${resLabel}`;
  if (objName) description += ` "${objName}"`;
  if (namespace) description += ` in ${namespace}`;
  if (username) description += ` by ${oneLine(username).slice(0, 120)}`;
  if (ip) description += ` from ${ip}`;
  if (code >= 400) description += ` [${code}${reason ? ` ${reason}` : ""}]`;
  description = description.slice(0, 600);

  return {
    timestamp: isoTime(str(getCI(rec, "requestReceivedTimestamp")) || str(getCI(rec, "stageTimestamp"))),
    description, severity, mitre,
    // Include the object name so distinct objects (a privileged vs a normal pod) stay separate rows;
    // repeated identical requests against the SAME object still aggregate.
    aggKey: `k8s|${verb}|${resLabel}|${namespace}|${objName}|${username}|${code}`.toLowerCase().slice(0, 400),
    sources: ["Kubernetes Audit"],
  };
}

export function parseK8sAudit(text: string, opts: K8sAuditImportOptions = {}): K8sAuditParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const rec of records) {
    const m = mapRecord(rec, iocSink);
    if (m) mapped.push(m);
  }
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty" };
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "k8s-audit",
  };
}
