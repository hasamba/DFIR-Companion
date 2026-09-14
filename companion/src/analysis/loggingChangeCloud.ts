// GCP Cloud Logging and Azure Monitor logging-configuration calls read for the STATE their
// request establishes (#931 item 14, coverage half — record part): sinks, exclusions, log
// buckets and the IAM audit-config deltas; diagnostic settings and log profiles. The shared
// helpers, the CloudTrail reader and the row renderer live in loggingChange.ts.

import type { LoggingState } from "./canonicalLogging.js";
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

const maskHas = (request: Row, path: string): boolean =>
  field(request, "updateMask")
    .split(",")
    .map((s) => s.trim())
    .includes(path);

/** A Cloud Logging config call's reading (ConfigServiceV2 sinks, exclusions, buckets), or null. */
export function decodeGcpLogging(
  service: string,
  method: string,
  request: unknown,
  denied: boolean,
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
      `sink ${denied ? "deletion requested" : "deleted"}: ${show(name)}`,
      [],
      [],
      denied,
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
      denied,
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
          denied,
        );
      if (off === false)
        return reading("gcp", "sink", name, "enabled", "Low", `sink enabled: ${show(name)}`, [], [], denied);
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
      denied,
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
      denied,
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
      denied,
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
        denied,
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
        denied,
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
      denied,
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
        denied,
      );
    return null;
  }
  return null;
}

/** One reading per IAM audit-config delta of a SetIamPolicy record — exact, effective outcome never established. */
export function decodeGcpAuditConfigDelta(delta: Row, denied: boolean): LoggingReading {
  const action = lower(field(delta, "action"));
  const service = field(delta, "service") || "(service not recorded)";
  const logType = field(delta, "logType") || "(log type not recorded)";
  const member = field(delta, "exemptedMember");
  const add = action === "add";
  const target = `${service}|${logType}`;
  const facts: Fact[] = [
    { name: "service", value: service },
    { name: "logType", value: logType },
    ...(member ? [{ name: "exemptedMember", value: member }] : []),
  ];
  const posture = member
    ? `audit-config exemption ${add ? "added" : "removed"} for ${show(member, 80)} on ${show(logType, 20)} (${show(service, 60)})`
    : `audit-config log type ${show(logType, 20)} entry ${add ? "added" : "removed"} for ${show(service, 60)}`;
  const high = member ? add : !add;
  return reading(
    "gcp",
    "audit-config",
    target,
    "reconfigured",
    high ? "High" : "Low",
    posture,
    facts,
    [],
    denied,
    { effectiveNotEstablished: true, key: `${action}|${member}` },
  );
}

// ───────────────────────────── Azure ─────────────────────────────

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

/** An Azure diagnostic-setting / log-profile operation's reading, or null. */
export function decodeAzureLogging(
  operation: string,
  resourceId: string,
  requestBody: unknown,
  failed: boolean,
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
      `log profile ${failed ? "deletion requested" : "deleted"}: ${show(settingName, 60)}`,
      [],
      [],
      failed,
    );
  if (/microsoft\.insights\/diagnosticsettings\/delete$/.test(op))
    return reading(
      "azure",
      "diagnostic-setting",
      resourceId,
      "deleted",
      "High",
      `diagnostic setting ${failed ? "deletion requested" : "deleted"}: ${show(settingName, 60)} on ${show(scope, 80)}`,
      [],
      [],
      failed,
    );
  if (!/microsoft\.insights\/diagnosticsettings\/write$/.test(op)) return null;
  let body: unknown = requestBody;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = undefined;
    }
  }
  const props =
    isObject(body) && isObject(getCI(body, "properties"))
      ? (getCI(body, "properties") as Row)
      : isObject(body)
        ? body
        : null;
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
      failed,
    );
  const logs = objects(getCI(props, "logs"), 32).map((l) => ({
    name: field(l, "category") || field(l, "categoryGroup") || "(category not recorded)",
    on: bool(getCI(l, "enabled")) === true,
  }));
  const metrics = objects(getCI(props, "metrics"), 16).map((l) => ({
    name: field(l, "category") || "(category not recorded)",
    on: bool(getCI(l, "enabled")) === true,
  }));
  const destinations = Object.entries(DESTINATIONS)
    .filter(([k]) => field(props, k))
    .map(([k, label]) => `${label} ${show(tail(field(props, k)), 80)}`);
  const on = logs.filter((l) => l.on).map((l) => show(l.name, 40));
  const off = logs.filter((l) => !l.on).map((l) => show(l.name, 40));
  const allOff = logs.length > 0 && on.length === 0;
  const parts = [
    ...(allOff
      ? [`every log category disabled in the resulting setting (${off.join(", ")})`]
      : logs.length
        ? [`log categories on: ${on.join(", ") || "none"}; off: ${off.join(", ") || "none"}`]
        : []),
    ...(metrics.length
      ? [
          `metrics ${
            metrics.some((m) => m.on)
              ? `on: ${metrics
                  .filter((m) => m.on)
                  .map((m) => show(m.name, 40))
                  .join(", ")}`
              : `off: ${metrics.map((m) => show(m.name, 40)).join(", ")}`
          }`,
        ]
      : []),
    ...(destinations.length ? [`destination ${destinations.join(", ")}`] : []),
  ];
  const facts: Fact[] = [
    ...logs.map((l) => ({ name: `log:${l.name}`, value: String(l.on) })),
    ...metrics.map((m) => ({ name: `metric:${m.name}`, value: String(m.on) })),
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
    failed,
    { key: parts.join(";"), mitre: allOff ? [TECHNIQUE] : [] },
  );
}
