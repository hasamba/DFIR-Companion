// The log sources the import-time Sigma engine reads (#2202): for each, which Sigma `logsource` it
// answers, and what every Sigma field name means in the raw records its importer sees.
//
// A field is mapped only when the record carries the SAME fact under that name or an alias
// (Codex plan review): Log Analytics `ResultType` is Graph `status.errorCode`, AuditLogs
// `OperationName` is Graph `activityDisplayName`. A field with no true equivalent is not mapped,
// and a rule that uses it is refused at load with a sentence naming the field — it never runs
// half-matched. Adding a log source is one entry here plus the importer passing its records.

import { lookupPath, type SigmaFieldLookup } from "./sigmaLookup.js";
import type { SigmaFieldResolver } from "./sigmaMatch.js";
import type { SigmaLogsource } from "./sigmaRuleTypes.js";

type Row = Record<string, unknown>;

/** A path to read, or a function that derives the value from the record. */
type Resolver = string | ((record: Row) => SigmaFieldLookup);

export interface SigmaFieldTable {
  /** Lower-cased Sigma field name → where to read it (all are read and their values merged). */
  exact: Readonly<Record<string, readonly Resolver[]>>;
  /** Lower-cased prefix → replacement prefixes, for open-ended nested objects. */
  prefixes?: readonly { from: string; to: readonly string[] }[];
  /** Lower-cased field names that look mappable but have no equivalent, with the reason. */
  unavailable?: Readonly<Record<string, string>>;
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
}

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
};

/** Every log source the engine grades, in the order a rule is offered to them. */
export const SIGMA_LOG_SOURCES: readonly SigmaLogSourceDef[] = [
  AWS_CLOUDTRAIL,
  AZURE_SIGNIN_LOGS,
  AZURE_AUDIT_LOGS,
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
    if (lower.startsWith(p.from)) return p.to.map((t) => t + field.slice(p.from.length));
  }
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
    let resolvers = cache.get(field);
    if (!resolvers) {
      const r = fieldResolvers(def, field);
      resolvers = Array.isArray(r) ? r : [];
      cache.set(field, resolvers);
    }
    return merge(resolvers.map((r) => (typeof r === "string" ? lookupPath(record, r) : r(record))));
  };
}
