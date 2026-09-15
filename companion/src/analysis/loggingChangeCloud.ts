// GCP Cloud Logging and Azure Monitor logging-configuration calls read for the STATE their
// request establishes (#931 item 14, coverage half — record part): sinks, exclusions, log
// buckets and the IAM audit-config deltas; diagnostic settings and log profiles. The shared
// helpers, the CloudTrail reader and the row renderer live in loggingChange.ts.

import type { LoggingFailureKind, LoggingState } from "./canonicalLogging.js";
import {
  TECHNIQUE,
  bool,
  factWords,
  field,
  has,
  lower,
  objects,
  reading,
  show,
  type Fact,
  type LoggingReading,
} from "./loggingChange.js";
import { getCI, isObject } from "./siemImport.js";

type Row = Record<string, unknown>;

// ───────────────────────────── GCP ─────────────────────────────

/** Classifies a GCP `status.code` (#1081): `google.rpc.Code` is a small, stable, DOCUMENTED
 * integer enum — an exact match, never a heuristic. 5 = NOT_FOUND; 7 = PERMISSION_DENIED; 16 =
 * UNAUTHENTICATED. Everything else (3 INVALID_ARGUMENT, 6 ALREADY_EXISTS, 8 RESOURCE_EXHAUSTED, 9
 * FAILED_PRECONDITION, 10 ABORTED, 13 INTERNAL, 14 UNAVAILABLE, and anything unrecognized) is
 * `"failed"` — this evidence does not distinguish it from either other outcome. */
export function classifyGcpFailure(code: string): LoggingFailureKind {
  const c = code.trim();
  if (c === "5") return "not-found";
  if (c === "7" || c === "16") return "denied";
  return "failed";
}

/** The update mask's paths, whatever shape the export used: a comma string, `{ paths: [] }`, snake_case, qualified, or `*`. */
function maskPaths(request: Row): string[] {
  const raw = getCI(request, "updateMask") ?? getCI(request, "update_mask");
  const values = Array.isArray(raw)
    ? raw
    : isObject(raw)
      ? Array.isArray(getCI(raw, "paths"))
        ? (getCI(raw, "paths") as unknown[])
        : []
      : typeof raw === "string"
        ? raw.split(",")
        : [];
  return values
    .map((v) => String(v).trim())
    .filter(Boolean)
    .map((v) =>
      v.replace(/^(sink|exclusion|bucket)\./, "").replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase()),
    );
}
const maskHas = (request: Row, path: string): boolean => {
  const paths = maskPaths(request);
  return paths.includes("*") || paths.includes(path);
};

/** A Cloud Logging config call's reading (ConfigServiceV2 sinks, exclusions, buckets), or null. */
export function decodeGcpLogging(
  service: string,
  method: string,
  request: unknown,
  failure: LoggingFailureKind | null,
): LoggingReading | null {
  if (!/^logging\.googleapis\.com$/i.test(service.trim())) return null;
  const m = lower(method).replace(/^.*\./, "");
  const req: Row = isObject(request) ? request : {};
  if (m === "deletesink") {
    const name = field(req, "sinkName") || "(sink not recorded)";
    return reading(
      "gcp",
      "sink",
      name,
      "deleted",
      "High",
      `sink ${failure ? "deletion requested" : "deleted"}: ${show(name)}`,
      [],
      [],
      failure,
    );
  }
  if (m === "createsink") {
    const sink = isObject(getCI(req, "sink")) ? (getCI(req, "sink") as Row) : {};
    const name = field(sink, "name") || "(sink not recorded)";
    const filter = field(sink, "filter");
    return reading(
      "gcp",
      "sink",
      name,
      "created",
      "Low",
      `sink created: ${show(name, 60)} → ${show(field(sink, "destination"), 80) || "(destination not recorded)"}${filter ? `; filter ${show(filter, 100)}` : ""}`,
      [],
      [],
      failure,
    );
  }
  if (m === "updatesink") {
    const name = field(req, "sinkName") || "(sink not recorded)";
    const sink = isObject(getCI(req, "sink")) ? (getCI(req, "sink") as Row) : {};
    if (maskHas(req, "disabled")) {
      const off = bool(getCI(sink, "disabled"));
      if (off === true)
        return reading(
          "gcp",
          "sink",
          name,
          "disabled",
          "High",
          `sink disabled: ${show(name)}`,
          [],
          [],
          failure,
        );
      if (off === false)
        return reading("gcp", "sink", name, "enabled", "Low", `sink enabled: ${show(name)}`, [], [], failure);
    }
    const facts = ["filter", "destination", "description"]
      .filter((f) => maskHas(req, f) && has(sink, f))
      .map((f) => ({ name: f, value: field(sink, f) }));
    return reading(
      "gcp",
      "sink",
      name,
      "prior-state-not-in-record",
      "Medium",
      `sink reconfigured: ${factWords(facts) || `(mask ${show(field(req, "updateMask"), 60) || "not recorded"})`}`,
      [],
      [],
      failure,
      { key: facts.map((f) => f.value).join(",") },
    );
  }
  if (m === "createexclusion") {
    const ex = isObject(getCI(req, "exclusion")) ? (getCI(req, "exclusion") as Row) : {};
    const name = field(ex, "name") || "(exclusion not recorded)";
    return reading(
      "gcp",
      "exclusion",
      name,
      "created",
      "High",
      `exclusion created: ${show(name, 60)}; filter ${show(field(ex, "filter"), 120) || "(not recorded)"}`,
      [],
      [],
      failure,
      { mitre: [TECHNIQUE] },
    );
  }
  if (m === "deleteexclusion") {
    const name = field(req, "name") || "(exclusion not recorded)";
    return reading(
      "gcp",
      "exclusion",
      name,
      "deleted",
      "Low",
      `exclusion deleted: ${show(name)}`,
      [],
      [],
      failure,
      { mitre: [] },
    );
  }
  if (m === "updateexclusion") {
    const ex = isObject(getCI(req, "exclusion")) ? (getCI(req, "exclusion") as Row) : {};
    const name = field(req, "name") || field(ex, "name") || "(exclusion not recorded)";
    const off = maskHas(req, "disabled") ? bool(getCI(ex, "disabled")) : undefined;
    if (off === true)
      return reading(
        "gcp",
        "exclusion",
        name,
        "disabled",
        "Low",
        `exclusion disabled: ${show(name)}`,
        [],
        [],
        failure,
        { mitre: [] },
      );
    if (off === false)
      return reading(
        "gcp",
        "exclusion",
        name,
        "enabled",
        "High",
        `exclusion enabled: ${show(name)}`,
        [],
        [],
        failure,
        { mitre: [TECHNIQUE] },
      );
    const facts = ["filter"]
      .filter((f) => maskHas(req, f) && has(ex, f))
      .map((f) => ({ name: f, value: field(ex, f) }));
    return reading(
      "gcp",
      "exclusion",
      name,
      "prior-state-not-in-record",
      "Medium",
      `exclusion reconfigured: ${factWords(facts) || "(no read field in the mask)"}`,
      [],
      [],
      failure,
    );
  }
  if (m === "updatebucket" || m === "updatebucketasync") {
    const name = field(req, "name") || "(bucket not recorded)";
    const bucket = isObject(getCI(req, "bucket")) ? (getCI(req, "bucket") as Row) : {};
    if (maskHas(req, "retentionDays") && has(bucket, "retentionDays"))
      return reading(
        "gcp",
        "log-bucket",
        name,
        "prior-state-not-in-record",
        "Medium",
        `log bucket ${show(name, 80)}: retention set to ${show(field(bucket, "retentionDays"), 10)} days; previous retention not in this record`,
        [{ name: "retentionDays", value: field(bucket, "retentionDays") }],
        [],
        failure,
      );
    return null;
  }
  return null;
}

/** One reading per IAM audit-config delta of a SetIamPolicy record — exact, effective outcome never established. */
export function decodeGcpAuditConfigDelta(delta: Row, failure: LoggingFailureKind | null): LoggingReading {
  const action = lower(field(delta, "action"));
  const service = field(delta, "service") || "(service not recorded)";
  const logType = field(delta, "logType") || "(log type not recorded)";
  const member = field(delta, "exemptedMember");
  const known = action === "add" || action === "remove";
  const add = action === "add";
  const target = `${service}|${logType}`;
  const facts: Fact[] = [
    { name: "action", value: field(delta, "action") || "(not recorded)" },
    { name: "service", value: service },
    { name: "logType", value: logType },
    ...(member ? [{ name: "exemptedMember", value: member }] : []),
  ];
  // An action the record does not name as ADD or REMOVE is quoted, never read as a removal.
  const posture = !known
    ? `audit-config entry changed (action ${show(field(delta, "action"), 20) || "not recorded"}) for ${show(logType, 20)} on ${show(service, 60)}${member ? `, exempted member ${show(member, 80)}` : ""}`
    : member
      ? `audit-config exemption ${add ? "added" : "removed"} for ${show(member, 80)} on ${show(logType, 20)} (${show(service, 60)})`
      : `audit-config log type ${show(logType, 20)} entry ${add ? "added" : "removed"} for ${show(service, 60)}`;
  const high = known && (member ? add : !add);
  return reading(
    "gcp",
    "audit-config",
    target,
    "reconfigured",
    !known ? "Medium" : high ? "High" : "Low",
    posture,
    facts,
    [],
    failure,
    {
      effectiveNotEstablished: true,
      key: `${action}|${member}`,
      mitre: high ? [TECHNIQUE] : [],
    },
  );
}

// ───────────────────────────── Azure ─────────────────────────────

/** Microsoft's own documented common values for `subStatus` (activity-log-schema): the field is
 * "usually the HTTP status code of the corresponding REST call." Matched ONLY as the field's own
 * WHOLE value — never a substring — since Microsoft also documents it can "include other strings"
 * (#1096, Codex design review findings #2/#3: a loose substring search risked misfiring on an
 * unrelated provider-specific string that happens to contain a status-like token). */
const HTTP_STATUS_WORDS: Record<string, number> = {
  ok: 200,
  created: 201,
  accepted: 202,
  "no content": 204,
  "bad request": 400,
  unauthorized: 401,
  forbidden: 403,
  "not found": 404,
  conflict: 409,
  "internal server error": 500,
  "service unavailable": 503,
  "gateway timeout": 504,
};
/** Microsoft's own documented structured form is `"<Word...> (HTTP Status Code: <N>)"`. */
const AZURE_HTTP_STATUS_RE = /\(http status code:\s*(\d{3})\)\s*$/i;

function azureHttpStatus(subStatus: string): number | null {
  const s = subStatus.trim();
  if (!s) return null;
  const structured = AZURE_HTTP_STATUS_RE.exec(s);
  if (structured) return Number(structured[1]);
  if (/^\d{3}$/.test(s)) return Number(s);
  return HTTP_STATUS_WORDS[s.toLowerCase()] ?? null;
}

/** Classifies Azure's `subStatus` field (#1096) — "usually the HTTP status code of the
 * corresponding REST call" per Microsoft's own schema reference, present across all three
 * documented Azure export shapes this codebase already reads `status` from (REST/portal
 * `subStatus.value`; Log Analytics `ActivitySubstatusValue`; storage/event-hub
 * `resultSignature`). 404 = not-found; 401/403 = denied. Everything else — absent, a non-HTTP
 * value, 400/409/5xx, or anything not matching one of Microsoft's own documented shapes exactly —
 * is `"failed"`: the same conservative default #1081 established for AWS/GCP, never guessed. */
export function classifyAzureFailure(subStatus: string): LoggingFailureKind {
  const code = azureHttpStatus(subStatus);
  if (code === 404) return "not-found";
  if (code === 401 || code === 403) return "denied";
  return "failed";
}

const DESTINATIONS: Record<string, string> = {
  workspaceId: "workspace",
  storageAccountId: "storage account",
  eventHubAuthorizationRuleId: "event hub",
  marketplacePartnerId: "partner",
};
const tail = (id: string): string => {
  const parts = id.split("/").filter(Boolean);
  return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : id;
};

/**
 * The request body of an Azure write, whatever envelope the export used: a JSON string or an
 * object. Exported so other Azure joins (e.g. `azureCompute.ts`, #1066) can read a top-level
 * sibling of `properties` — such as `identity` on a VM write — that `azureBody` below discards.
 */
export function parseAzureRequestBody(requestBody: unknown): Row | null {
  let body: unknown = requestBody;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  }
  return isObject(body) ? body : null;
}

/** An Azure diagnostic-setting / log-profile operation's reading, or null. */
/** The request body of an Azure write, whatever envelope the export used: a JSON string or an object, under `properties` or flat. */
function azureBody(requestBody: unknown): Row | null {
  const body = parseAzureRequestBody(requestBody);
  if (!body) return null;
  const props = getCI(body, "properties");
  return isObject(props) ? props : body;
}

export function decodeAzureLogging(
  operation: string,
  resourceId: string,
  requestBody: unknown,
  failure: LoggingFailureKind | null,
): LoggingReading | null {
  const op = lower(operation);
  const settingName = resourceId.slice(resourceId.lastIndexOf("/") + 1) || "(setting not recorded)";
  const parent = resourceId.replace(/\/providers\/microsoft\.insights\/diagnosticsettings\/[^/]+$/i, "");
  const scope = parent.split("/").filter(Boolean).slice(-2).join("/") || "(scope not recorded)";
  if (/microsoft\.insights\/logprofiles\/delete$/.test(op))
    return reading(
      "azure",
      "log-profile",
      resourceId,
      "deleted",
      "High",
      `log profile deleted: ${show(settingName, 60)}`,
      [],
      [],
      failure,
    );
  if (/microsoft\.insights\/diagnosticsettings\/delete$/.test(op))
    return reading(
      "azure",
      "diagnostic-setting",
      resourceId,
      "deleted",
      "High",
      `diagnostic setting deleted: ${show(settingName, 60)} on ${show(scope, 80)}`,
      [],
      [],
      failure,
    );
  if (!/microsoft\.insights\/diagnosticsettings\/write$/.test(op)) return null;
  const props = azureBody(requestBody);
  if (!props || (!has(props, "logs") && !has(props, "metrics")))
    return reading(
      "azure",
      "diagnostic-setting",
      resourceId,
      "prior-state-not-in-record",
      "Medium",
      `diagnostic setting written: ${show(settingName, 60)} on ${show(scope, 80)} — the request body is not in this record`,
      [],
      [],
      failure,
    );
  // `enabled` is read only when the entry states it: a missing or malformed flag is "not stated", never "off".
  const entries = (v: unknown, max: number) =>
    objects(getCI(props, v as string), max).map((l) => ({
      name: field(l, "category") || field(l, "categoryGroup") || "(category not recorded)",
      on: bool(getCI(l, "enabled")),
    }));
  const logs = entries("logs", 32);
  const metrics = entries("metrics", 16);
  const destinations = Object.entries(DESTINATIONS)
    .filter(([k]) => field(props, k))
    .map(([k, label]) => ({ label, id: field(props, k) }));
  const on = logs.filter((l) => l.on === true).map((l) => show(l.name, 40));
  const off = logs.filter((l) => l.on === false).map((l) => show(l.name, 40));
  const unstated = logs.filter((l) => l.on === undefined).map((l) => show(l.name, 40));
  const allOff = logs.length > 0 && off.length === logs.length;
  const metricsOn = metrics.filter((m) => m.on === true).map((m) => show(m.name, 40));
  const metricsOff = metrics.filter((m) => m.on === false).map((m) => show(m.name, 40));
  const parts = [
    ...(allOff
      ? [`every log category disabled in the resulting setting (${off.join(", ")})`]
      : logs.length
        ? [
            `log categories on: ${on.join(", ") || "none"}; off: ${off.join(", ") || "none"}${unstated.length ? `; not stated: ${unstated.join(", ")}` : ""}`,
          ]
        : []),
    ...(metrics.length
      ? [`metrics on: ${metricsOn.join(", ") || "none"}; off: ${metricsOff.join(", ") || "none"}`]
      : []),
    ...(destinations.length
      ? [`destination ${destinations.map((d) => `${d.label} ${show(tail(d.id), 80)}`).join(", ")}`]
      : []),
  ];
  const facts: Fact[] = [
    ...logs.map((l) => ({ name: `log:${l.name}`, value: l.on === undefined ? "not stated" : String(l.on) })),
    ...metrics.map((m) => ({
      name: `metric:${m.name}`,
      value: m.on === undefined ? "not stated" : String(m.on),
    })),
    ...destinations.map((d) => ({ name: d.label, value: d.id })),
  ];
  const state: LoggingState = allOff ? "reconfigured" : "prior-state-not-in-record";
  return reading(
    "azure",
    "diagnostic-setting",
    resourceId,
    state,
    allOff ? "High" : "Medium",
    `diagnostic setting written: ${show(settingName, 60)} on ${show(scope, 80)} — ${parts.join("; ")}`,
    facts,
    logs.length && !allOff ? ["the prior setting is not in this record"] : [],
    failure,
    { key: parts.join(";"), mitre: allOff ? [TECHNIQUE] : [] },
  );
}
