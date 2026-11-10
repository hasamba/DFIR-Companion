// The log sources the import-time Sigma engine reads (#2202): for each, which Sigma `logsource` it
// answers, and what every Sigma field name means in the raw records its importer sees.
//
// A field is mapped only when the record carries the SAME fact under that name or an alias
// (Codex plan review): Log Analytics `ResultType` is Graph `status.errorCode`, AuditLogs
// `OperationName` is Graph `activityDisplayName`. A field with no true equivalent is not mapped,
// and a rule that uses it is refused at load with a sentence naming the field — it never runs
// half-matched. Adding a log source is one entry here plus the importer passing its records.

import { gcpMethodAliases } from "./sigmaGcpMethodAliases.js";
import { lookupPath, type SigmaFieldLookup } from "./sigmaLookup.js";
import type { SigmaFieldResolver } from "./sigmaMatch.js";
import type { SigmaLogsource } from "./sigmaRuleTypes.js";

type Row = Record<string, unknown>;

/** A path to read, or a function that derives the value from the record. */
type Resolver = string | ((record: Row) => SigmaFieldLookup);

export interface SigmaFieldTable {
  /** Lower-cased Sigma field name → where to read it (all are read and their values merged). */
  exact: Readonly<Record<string, readonly Resolver[]>>;
  /** Lower-cased prefix → replacement prefixes, for open-ended nested objects. `derive` builds the
   * resolvers from the rest of the field name instead, for shapes a path cannot express (#2500). */
  prefixes?: readonly { from: string; to: readonly string[]; derive?: (rest: string) => Resolver[] }[];
  /** Lower-cased field names that look mappable but have no equivalent, with the reason. */
  unavailable?: Readonly<Record<string, string>>;
  /** For an open-ended name space (#2522: a Workspace event's parameters): where a field the table
   * does not name is read, or undefined to refuse it as usual. Consulted after exact and prefixes. */
  fallback?: (field: string) => Resolver[] | undefined;
}

export interface SigmaLogSourceDef {
  /** Stable id, recorded on every match. */
  id: string;
  /** Analyst-facing name, used in refusal sentences. */
  label: string;
  matches(logsource: SigmaLogsource): boolean;
  fields: SigmaFieldTable;
  /** Fields whose literal values index the rules, so a record is checked only against candidates. */
  indexFields: readonly string[];
  /** The super-timeline origin labels its importer stamps on graded rows (#2217 coverage card). */
  origins: readonly string[];
}

// The importers' own `sources` labels (awsImport.ts, m365Import.ts + entraAuditImport.ts,
// combinedLogImport.ts COMBINED_LOG_SOURCE, gcpRow.ts, cloudActivityImport.ts mapAzure). sigmaCoverage.test.ts pins them to those files.
export const SIGMA_ORIGIN_CLOUDTRAIL = "AWS CloudTrail";
export const SIGMA_ORIGIN_ENTRA = "Entra ID";
export const SIGMA_ORIGIN_WEB = "Web Access Log";
export const SIGMA_ORIGIN_GCP = "GCP Audit";
export const SIGMA_ORIGIN_M365 = "Microsoft 365";
export const SIGMA_ORIGIN_AZURE_ACTIVITY = "Azure Activity";
export const SIGMA_ORIGIN_GWS = "Google Workspace";

const same = (...names: string[]): Record<string, string[]> =>
  Object.fromEntries(names.map((n) => [n.toLowerCase(), [n]]));

const is = (ls: SigmaLogsource, product: string, service: string): boolean =>
  ls.product?.toLowerCase() === product && ls.service?.toLowerCase() === service && !ls.category;

// ── Derived values ────────────────────────────────────────────────────────────────────────────

const found = (values: (string | null)[]): SigmaFieldLookup => ({
  present: values.length > 0,
  values,
  incomplete: false,
});

/** The first non-empty text value of a path, or undefined. */
function firstText(record: Row, path: string): string | undefined {
  const l = lookupPath(record, path);
  return l.values.find((v): v is string => typeof v === "string" && v.trim() !== "");
}

/** Sign-in `Status` as Sigma rules write it: a plain status string when the export has one,
 * else Success / Failure from the error code (Graph and Log Analytics nest it in an object). */
function signInStatus(record: Row): SigmaFieldLookup {
  const raw = firstText(record, "Status");
  if (raw && !/^\s*[{[]/.test(raw)) return found([raw]);
  const code = firstText(record, "status.errorCode") ?? firstText(record, "ResultType");
  if (code === undefined) return found([]);
  return found([code.trim() === "0" ? "Success" : "Failure"]);
}

/** Sign-in `Location`: Log Analytics writes the country code as a string; Graph nests it. */
function signInLocation(record: Row): SigmaFieldLookup {
  const raw = firstText(record, "Location");
  if (raw && !/^\s*[{[]/.test(raw)) return found([raw]);
  const country = firstText(record, "location.countryOrRegion");
  return found(country === undefined ? [] : [country]);
}

// ── Sources ───────────────────────────────────────────────────────────────────────────────────

const CLOUDTRAIL_OPEN = [
  "userIdentity",
  "requestParameters",
  "responseElements",
  "additionalEventData",
  "serviceEventDetails",
  "tlsDetails",
  "resources",
  "addendum",
  "edgeDeviceDetails",
  "insightDetails",
];

export const AWS_CLOUDTRAIL: SigmaLogSourceDef = {
  id: "aws-cloudtrail",
  label: "AWS CloudTrail",
  matches: (ls) => is(ls, "aws", "cloudtrail"),
  fields: {
    exact: same(
      "eventVersion",
      "eventTime",
      "eventSource",
      "eventName",
      "awsRegion",
      "sourceIPAddress",
      "userAgent",
      "errorCode",
      "errorMessage",
      "requestID",
      "eventID",
      "eventType",
      "eventCategory",
      "apiVersion",
      "managementEvent",
      "readOnly",
      "recipientAccountId",
      "sharedEventID",
      "vpcEndpointId",
      "vpcEndpointAccountId",
      "sessionCredentialFromConsole",
      ...CLOUDTRAIL_OPEN,
    ),
    prefixes: CLOUDTRAIL_OPEN.map((p) => ({ from: `${p.toLowerCase()}.`, to: [`${p}.`] })),
  },
  indexFields: ["eventName", "eventSource"],
  origins: [SIGMA_ORIGIN_CLOUDTRAIL],
};

export const AZURE_SIGNIN_LOGS: SigmaLogSourceDef = {
  id: "azure-signinlogs",
  label: "Entra ID sign-in logs",
  matches: (ls) => is(ls, "azure", "signinlogs"),
  fields: {
    exact: {
      ...same(
        "AuthenticationRequirement",
        "ConditionalAccessStatus",
        "RiskState",
        "RiskLevelDuringSignIn",
        "RiskLevelAggregated",
        "RiskDetail",
        "ResourceDisplayName",
        "ResourceId",
        "AppId",
        "AppDisplayName",
        "UserAgent",
        "HomeTenantId",
        "ResourceTenantId",
        "UserPrincipalName",
        "UserDisplayName",
        "UserId",
        "IPAddress",
        "IsInteractive",
        "TokenIssuerType",
        "CorrelationId",
        "DeviceDetail",
        "AuthenticationDetails",
        "MfaDetail",
      ),
      resulttype: ["ResultType", "status.errorCode"],
      resultdescription: ["ResultDescription", "status.failureReason"],
      username: ["UserPrincipalName"],
      clientapp: ["ClientAppUsed"],
      clientappused: ["ClientAppUsed"],
      status: [signInStatus],
      location: [signInLocation],
    },
    prefixes: [
      { from: "devicedetail.", to: ["DeviceDetail."] },
      { from: "locationdetails.", to: ["LocationDetails.", "location."] },
      { from: "authenticationdetails.", to: ["AuthenticationDetails."] },
      { from: "mfadetail.", to: ["MfaDetail."] },
      { from: "status.", to: ["Status."] },
    ],
    unavailable: {
      "properties.message": "no Entra sign-in export the Companion reads carries properties.message",
      count: "Count is a count over time, which a single sign-in record cannot answer",
    },
  },
  indexFields: [],
  origins: [SIGMA_ORIGIN_ENTRA],
};

const AUDIT_OPEN = ["TargetResources", "InitiatedBy", "AdditionalDetails"];

export const AZURE_AUDIT_LOGS: SigmaLogSourceDef = {
  id: "azure-auditlogs",
  label: "Entra ID audit logs",
  matches: (ls) => is(ls, "azure", "auditlogs"),
  fields: {
    exact: {
      ...same("Category", "LoggedByService", "Result", "ResultReason", "CorrelationId", "Id", ...AUDIT_OPEN),
      operationname: ["activityDisplayName", "OperationName"],
      activitydisplayname: ["activityDisplayName", "OperationName"],
      status: ["result"],
      "properties.activitydisplayname": ["activityDisplayName"],
      "properties.result": ["result"],
      "properties.category": ["category"],
      "properties.loggedbyservice": ["loggedByService"],
      "properties.targetresources": ["targetResources"],
      "properties.initiatedby": ["initiatedBy"],
      "properties.additionaldetails": ["additionalDetails"],
    },
    prefixes: [
      ...AUDIT_OPEN.map((p) => ({ from: `${p.toLowerCase()}.`, to: [`${p}.`] })),
      ...AUDIT_OPEN.map((p) => ({ from: `properties.${p.toLowerCase()}.`, to: [`${p}.`] })),
    ],
    unavailable: {
      "properties.message":
        "no Entra audit export the Companion reads carries properties.message, and it has no equivalent field",
    },
  },
  indexFields: ["OperationName", "ActivityDisplayName"],
  origins: [SIGMA_ORIGIN_ENTRA],
};

// GCP Cloud Audit Logs (#2346): a Cloud Logging LogEntry whose `protoPayload` is an AuditLog, as
// cloudActivityImport.ts reads it. SigmaHQ's GCP rules use two naming schemes: the Elastic
// integration's `gcp.audit.*` names and a `data.protoPayload.*` export wrapper. Both name AuditLog
// fields, read at their LogEntry paths. Two wrapper names point at fields that are NOT inside
// protoPayload in a real LogEntry — the monitored-resource type and the log name — so those read
// the LogEntry's own top-level fields (an exact entry wins over the prefix below). The importer
// accepts `jsonPayload` in place of `protoPayload`, so every payload path reads both.

/** A LogEntry `logName` (`projects/p/logs/cloudaudit.googleapis.com%2Factivity`) as a rule may
 * write it: the whole name, the log id after `/logs/`, and that id URL-decoded. */
function gcpLogName(record: Row): SigmaFieldLookup {
  const raw = firstText(record, "logName");
  if (raw === undefined) return found([]);
  const at = raw.lastIndexOf("/logs/");
  if (at < 0) return found([raw]);
  const id = raw.slice(at + "/logs/".length);
  let decoded = id;
  try {
    decoded = decodeURIComponent(id);
  } catch {
    // A malformed escape is kept as written.
  }
  return found([...new Set([raw, id, decoded])]);
}

const payload = (path: string): string[] => [`protoPayload.${path}`, `jsonPayload.${path}`];

/** The rule-side alias(es) of the record's exact service + method (sigmaGcpMethodAliases.ts, with
 * the 15-rule audit). Read beside the raw methodName paths, so a rule matches either spelling. */
function gcpMethodAlias(record: Row): SigmaFieldLookup {
  const root = firstText(record, "protoPayload.methodName") !== undefined ? "protoPayload" : "jsonPayload";
  return found(
    gcpMethodAliases(firstText(record, `${root}.serviceName`), firstText(record, `${root}.methodName`)),
  );
}
const methodName: Resolver[] = [...payload("methodName"), gcpMethodAlias];

export const GCP_AUDIT: SigmaLogSourceDef = {
  id: "gcp-audit",
  label: "GCP Cloud Audit Logs",
  matches: (ls) => is(ls, "gcp", "gcp.audit"),
  fields: {
    exact: {
      // Elastic GCP integration names, each the AuditLog field of the same meaning.
      "gcp.audit.method_name": methodName,
      "gcp.audit.service_name": payload("serviceName"),
      "gcp.audit.resource_name": payload("resourceName"),
      "gcp.audit.authentication_info.principal_email": payload("authenticationInfo.principalEmail"),
      "gcp.audit.authorization_info.permission": payload("authorizationInfo.permission"),
      "gcp.audit.authorization_info.granted": payload("authorizationInfo.granted"),
      "gcp.audit.request_metadata.caller_ip": payload("requestMetadata.callerIp"),
      "gcp.audit.status.code": payload("status.code"),
      "gcp.audit.status.message": payload("status.message"),
      // The two top-level LogEntry fields under the `data.protoPayload` wrapper (see above).
      "data.protopayload.resource.type": ["resource.type"],
      "data.protopayload.logname": [gcpLogName],
      // The method name under the wrapper, with the same aliases (not the bare prefix below).
      "data.protopayload.methodname": methodName,
    },
    prefixes: [
      { from: "data.protopayload.", to: ["protoPayload.", "jsonPayload."] },
      { from: "protopayload.", to: ["protoPayload."] },
    ],
  },
  indexFields: ["gcp.audit.method_name"],
  origins: [SIGMA_ORIGIN_GCP],
};

// ── Microsoft 365 unified audit log + Azure Activity Log (#2500) ─────────────────────────────

/** Most elements one UAL name/value collection is scanned for before the lookup stops (incomplete). */
export const SIGMA_NAME_VALUE_MAX_ELEMENTS = 1_000;

const keyOf = (row: Row, key: string): unknown => {
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
};

/** A UAL `Value` as the text Sigma compares: arrays give one value per item, objects their JSON. */
function nameValueTexts(v: unknown): (string | null)[] {
  if (v === null || v === undefined) return [null];
  if (Array.isArray(v)) return v.flatMap(nameValueTexts);
  if (typeof v === "object") return [JSON.stringify(v)];
  return [String(v)];
}

/** The elements one collection leaf holds: an element's JSON text, or a whole array written as a
 * JSON string (lookupPath hands back a string leaf as written). Leaves past the JSON cap were
 * already marked incomplete by lookupPath. */
function collectionElements(text: string | null): Row[] {
  if (typeof text !== "string") return [];
  const t = text.trimStart();
  if (t[0] !== "{" && t[0] !== "[") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items.filter((x): x is Row => !!x && typeof x === "object" && !Array.isArray(x));
}

/**
 * A field inside a UAL name/value collection — `Parameters`, `ExtendedProperties`,
 * `OperationProperties` — which Microsoft writes as `[{ "Name": "X", "Value": "…" }, …]`. Suzaku's
 * rules name the member directly (`Parameters.ForwardingSmtpAddress`), so `<collection>.<key>` reads
 * the Value of every element whose Name is key (case-insensitively; duplicates give every value).
 * The collection is read through lookupPath, so a stringified array and its incomplete flag carry
 * over; a scan past the element cap is incomplete, never "absent". An element with no such Name is
 * absent, so `|exists` is false. `ModifiedProperties` is not one of these: its elements carry
 * OldValue / NewValue, two different facts, and a field under it stays refused.
 */
export function ualNameValue(collection: string, key: string): (record: Row) => SigmaFieldLookup {
  return (record) => {
    const coll = lookupPath(record, collection);
    let incomplete = coll.incomplete;
    const elements = coll.values.flatMap(collectionElements);
    if (elements.length > SIGMA_NAME_VALUE_MAX_ELEMENTS) incomplete = true;
    const values: (string | null)[] = [];
    let present = false;
    for (const el of elements.slice(0, SIGMA_NAME_VALUE_MAX_ELEMENTS)) {
      const name = keyOf(el, "Name");
      if (typeof name !== "string" || name.trim().toLowerCase() !== key.toLowerCase()) continue;
      present = true;
      values.push(...nameValueTexts(keyOf(el, "Value")));
    }
    return { present, values, incomplete };
  };
}

const UAL_NAME_VALUE = ["Parameters", "ExtendedProperties", "OperationProperties"];

export const AZURE_M365: SigmaLogSourceDef = {
  id: "azure-m365",
  label: "Microsoft 365 unified audit log",
  matches: (ls) => is(ls, "azure", "m365"),
  fields: {
    exact: {
      ...same(
        "Workload",
        "RecordType",
        "UserId",
        "UserKey",
        "UserType",
        "ClientIP",
        "ResultStatus",
        "ObjectId",
        "OrganizationId",
        ...UAL_NAME_VALUE,
      ),
      // A UAL CSV export names the column `Operations`; its AuditData JSON says `Operation`.
      operation: ["Operation", "Operations"],
    },
    // Both readings are merged: an export that already flattened the collection into an object (or
    // a dotted column) is read at the plain path, Microsoft's own array shape through Name/Value.
    prefixes: UAL_NAME_VALUE.map((c) => ({
      from: `${c.toLowerCase()}.`,
      to: [`${c}.`],
      derive: (rest: string) => [ualNameValue(c, rest)],
    })),
    unavailable: {
      modifiedproperties:
        "its elements hold an old and a new value — two facts — and the Companion does not pick one",
    },
  },
  indexFields: ["Operation"],
  // Entra directory changes exported through the UAL are written as Entra ID rows (m365Import.ts).
  origins: [SIGMA_ORIGIN_M365, SIGMA_ORIGIN_ENTRA],
};

export const AZURE_ACTIVITY: SigmaLogSourceDef = {
  id: "azure-activitylogs",
  label: "Azure Activity Log",
  matches: (ls) => is(ls, "azure", "activitylogs"),
  fields: {
    // The three export shapes cloudActivityImport.ts reads: REST (`operationName.value`), the
    // diagnostic-settings PT1H.json (`operationName` as a string) and Log Analytics AzureActivity
    // (`OperationNameValue`, `CategoryValue`, `Properties` / `Properties_d` as JSON text).
    exact: {
      operationname: ["operationName.value", "operationName", "OperationNameValue", "OperationName"],
      operationnamevalue: ["OperationNameValue", "operationName.value", "operationName"],
      categoryvalue: ["CategoryValue", "category.value", "category"],
      category: ["category.value", "category", "CategoryValue"],
      resourceprovidervalue: ["ResourceProviderValue", "resourceProviderName.value", "resourceProviderName"],
      resourceid: ["resourceId", "ResourceId"],
      caller: ["caller", "Caller"],
      calleripaddress: ["callerIpAddress", "CallerIpAddress", "httpRequest.clientIpAddress"],
      activitystatusvalue: ["ActivityStatusValue", "status.value", "status"],
    },
    prefixes: [{ from: "properties.", to: ["properties.", "Properties_d."] }],
  },
  indexFields: ["operationName"],
  origins: [SIGMA_ORIGIN_AZURE_ACTIVITY],
};

// ── Google Workspace audit activity (#2522) ──────────────────────────────────────────────────

/** A Reports API parameter's value(s) as the text Sigma compares, by its wire kind. */
function gwsParamTexts(el: Row): (string | null)[] {
  const out: (string | null)[] = [];
  for (const kind of ["value", "boolValue", "intValue"]) {
    const v = keyOf(el, kind);
    if (v !== undefined) out.push(...nameValueTexts(v));
  }
  for (const kind of ["multiValue", "multiIntValue"]) {
    const v = keyOf(el, kind);
    if (Array.isArray(v)) out.push(...v.flatMap(nameValueTexts));
  }
  for (const kind of ["messageValue", "multiMessageValue"]) {
    const v = keyOf(el, kind);
    if (v !== undefined && v !== null) out.push(JSON.stringify(v));
  }
  return out;
}

/**
 * A Workspace event parameter. The Reports API writes an event's parameters as
 * `[{ "name": "NEW_VALUE", "value": "true" }, { "name": "is_suspicious", "boolValue": true }, …]`, and
 * Suzaku and SigmaHQ rules name the parameter directly (`NEW_VALUE`, `new_value`, `is_suspicious`), so
 * a field reads every element of that name, case-insensitively. Read through lookupPath, so a
 * stringified array and its incomplete flag carry over; a scan past the element cap is incomplete,
 * never "absent". The record is one event (the importer narrows it), so a sibling event's parameters
 * are never read.
 */
export function gwsParameter(key: string): (record: Row) => SigmaFieldLookup {
  return (record) => {
    const coll = lookupPath(record, "events.parameters");
    let incomplete = coll.incomplete;
    const elements = coll.values.flatMap(collectionElements);
    if (elements.length > SIGMA_NAME_VALUE_MAX_ELEMENTS) incomplete = true;
    const values: (string | null)[] = [];
    let present = false;
    for (const el of elements.slice(0, SIGMA_NAME_VALUE_MAX_ELEMENTS)) {
      const name = keyOf(el, "name");
      if (typeof name !== "string" || name.trim().toLowerCase() !== key.toLowerCase()) continue;
      present = true;
      values.push(...gwsParamTexts(el));
    }
    return { present, values, incomplete };
  };
}

/** The Workspace applications whose Cloud Logging service is `<app>.googleapis.com` — the name
 * SigmaHQ's Workspace rules select on (`eventService`, `protoPayload.serviceName`). */
const GWS_LOGGING_SERVICES: ReadonlySet<string> = new Set(["admin", "login"]);

function gwsService(record: Row): SigmaFieldLookup {
  const app = firstText(record, "id.applicationName")?.trim().toLowerCase();
  return found(app && GWS_LOGGING_SERVICES.has(app) ? [`${app}.googleapis.com`] : []);
}

/** The Workspace applications a Sigma rule can name (`service: google_workspace.<app>`). Calendar
 * records import as generic rows; the one bundled calendar rule is a correlation and is refused. */
export const GWS_SIGMA_APPS = ["admin", "login", "drive", "calendar"] as const;

const GWS_PARAMETER_NAME = /^[A-Za-z0-9_]+$/;

function googleWorkspaceSource(app: (typeof GWS_SIGMA_APPS)[number]): SigmaLogSourceDef {
  return {
    id: `gws-${app}`,
    label: `Google Workspace ${app} activity`,
    matches: (ls) => is(ls, "gcp", `google_workspace.${app}`),
    fields: {
      exact: {
        // Suzaku names the Reports API event `eventName`; SigmaHQ uses the Cloud Logging spelling.
        eventname: ["events.name"],
        "protopayload.metadata.event.eventname": ["events.name"],
        eventtype: ["events.type"],
        eventservice: [gwsService],
        "protopayload.servicename": [gwsService],
        ...same(
          "id.time",
          "id.applicationName",
          "id.customerId",
          "id.uniqueQualifier",
          "actor.email",
          "actor.profileId",
          "actor.callerType",
          "actor.key",
          "ipAddress",
          "ownerDomain",
        ),
      },
      fallback: (field) => (GWS_PARAMETER_NAME.test(field) ? [gwsParameter(field)] : undefined),
    },
    indexFields: ["eventName"],
    origins: [SIGMA_ORIGIN_GWS],
  };
}

export const GWS_SOURCES: readonly SigmaLogSourceDef[] = GWS_SIGMA_APPS.map(googleWorkspaceSource);

/** The source that grades one Workspace application's events, or undefined when none does. */
export function gwsSourceFor(app: string): SigmaLogSourceDef | undefined {
  return GWS_SOURCES.find((d) => d.id === `gws-${app.trim().toLowerCase()}`);
}

const category = (ls: SigmaLogsource, name: string): boolean =>
  ls.category?.toLowerCase() === name && !ls.product && !ls.service;

// Web access logs (#2203). The combined-log importer builds a record in these exact names
// (sigmaWebRecord.ts), so every entry reads its own name. A field the format never logs — the
// request content type, cookies, the destination address — is not here, and a rule needing it is
// refused at load with the field named.
const WEB_UNAVAILABLE = {
  "cs-content-type": "a combined access log does not record the request's content type",
  "cs-cookie": "a combined access log does not record cookies",
  dst_ip: "a combined access log does not record the destination address",
  "": "the rule names an empty field",
};

export const WEB_SERVER: SigmaLogSourceDef = {
  id: "web-server",
  label: "web server access logs",
  matches: (ls) => category(ls, "webserver"),
  fields: {
    exact: same(
      "cs-method",
      "cs-uri-query",
      "cs-uri-stem",
      "sc-status",
      "cs-user-agent",
      "cs-referer",
      "cs-username",
      "cs-host",
      "c-ip",
    ),
    unavailable: WEB_UNAVAILABLE,
  },
  indexFields: [],
  origins: [SIGMA_ORIGIN_WEB],
};

export const WEB_PROXY: SigmaLogSourceDef = {
  id: "web-proxy",
  label: "web proxy access logs",
  matches: (ls) => category(ls, "proxy"),
  fields: {
    exact: same(
      "c-uri",
      "cs-uri",
      "c-uri-stem",
      "cs-uri-stem",
      "c-uri-query",
      "c-uri-extension",
      "cs-method",
      "cs-host",
      "sc-status",
      "c-useragent",
      "cs-referer",
      "cs-username",
      "c-ip",
    ),
    unavailable: WEB_UNAVAILABLE,
  },
  indexFields: [],
  origins: [SIGMA_ORIGIN_WEB],
};

/** Every log source the engine grades, in the order a rule is offered to them. */
export const SIGMA_LOG_SOURCES: readonly SigmaLogSourceDef[] = [
  AWS_CLOUDTRAIL,
  AZURE_SIGNIN_LOGS,
  AZURE_AUDIT_LOGS,
  GCP_AUDIT,
  AZURE_M365,
  AZURE_ACTIVITY,
  ...GWS_SOURCES,
  WEB_SERVER,
  WEB_PROXY,
];

// ── Resolution ────────────────────────────────────────────────────────────────────────────────

/** Where a field is read in this source, or a refusal sentence when it is not available. */
export function fieldResolvers(def: SigmaLogSourceDef, field: string): Resolver[] | { refused: string } {
  const lower = field.toLowerCase();
  const reason = def.fields.unavailable?.[lower];
  if (reason) return { refused: `the field ${field} is not available in ${def.label}: ${reason}` };
  const exact = def.fields.exact[lower];
  if (exact) return [...exact];
  for (const p of def.fields.prefixes ?? []) {
    if (!lower.startsWith(p.from)) continue;
    const rest = field.slice(p.from.length);
    return [...p.to.map((t) => t + rest), ...(p.derive?.(rest) ?? [])];
  }
  const fallback = def.fields.fallback?.(field);
  if (fallback) return fallback;
  return { refused: `the field ${field} is not available in ${def.label}` };
}

function merge(lookups: readonly SigmaFieldLookup[]): SigmaFieldLookup {
  return {
    present: lookups.some((l) => l.present),
    values: lookups.flatMap((l) => l.values),
    incomplete: lookups.some((l) => l.incomplete),
  };
}

/** A resolver for one source. Fields are resolved once and cached; unknown fields read nothing. */
export function sourceResolver(def: SigmaLogSourceDef): SigmaFieldResolver {
  const cache = new Map<string, Resolver[]>();
  return (record, field) => {
    // An importer that clipped a field lists it here (#2203): what remains is not complete evidence.
    const clipped = record.__sigmaIncomplete;
    const incomplete = Array.isArray(clipped) && clipped.includes(field);
    let resolvers = cache.get(field);
    if (!resolvers) {
      const r = fieldResolvers(def, field);
      resolvers = Array.isArray(r) ? r : [];
      cache.set(field, resolvers);
    }
    const merged = merge(resolvers.map((r) => (typeof r === "string" ? lookupPath(record, r) : r(record))));
    return incomplete ? { ...merged, incomplete: true } : merged;
  };
}
