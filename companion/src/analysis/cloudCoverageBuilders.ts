// Per-provider coverage builders (#1063): each reads the SAME un-aggregated `records` array its
// importer already has in scope at the top-level parse function, and produces coverage drafts —
// never a second read of the raw upload, never a claim the importer's own decoder does not
// already support. Every category list is the provider's OWN documented set; anything else is an
// `unknown` bucket, never guessed into an existing category.

import type { CloudCoverageCategory, CloudCoverageDraft } from "./cloudCoverage.js";
import { projectRefOf } from "./gcpIdentity.js";
import { getCI, isObject, normalizeTime, str } from "./siemImport.js";

type Row = Record<string, unknown>;

const field = (o: unknown, ...path: string[]): string => {
  let cur: unknown = o;
  for (const p of path) cur = isObject(cur) ? getCI(cur, p) : undefined;
  return str(cur).trim();
};

/** Deterministic scope ordering: record count desc, then value asc — never first-seen. */
export function sortScopesDeterministically<T extends { recordCount: number; scope: { value: string } }>(
  scopes: readonly T[],
): T[] {
  return [...scopes].sort(
    (a, b) => b.recordCount - a.recordCount || a.scope.value.localeCompare(b.scope.value),
  );
}

function bumpCategory(
  map: Map<string, CloudCoverageCategory>,
  name: string,
  apply: (c: CloudCoverageCategory) => void,
): void {
  const c = map.get(name) ?? { name, count: 0 };
  apply(c);
  map.set(name, c);
}

// ───────────────────────────── AWS CloudTrail ─────────────────────────────

const CLOUDTRAIL_CATEGORIES = new Set(["management", "data", "insight"]);
/** `eventCategory` exists only from CloudTrail record version 1.07 onward. */
const MIN_EVENT_CATEGORY_VERSION = 1.07;

export function awsCloudTrailCoverage(records: readonly Row[]): CloudCoverageDraft[] {
  const byAccount = new Map<
    string,
    { count: number; first: string; last: string; categories: Map<string, CloudCoverageCategory> }
  >();
  for (const rec of records) {
    if (!isObject(rec)) continue;
    const account = field(rec, "recipientAccountId") || field(rec, "accountId");
    const key = account || "(unknown)";
    const entry = byAccount.get(key) ?? { count: 0, first: "", last: "", categories: new Map() };
    entry.count += 1;
    const t = normalizeTime(field(rec, "eventTime"));
    if (t) {
      if (!entry.first || t < entry.first) entry.first = t;
      if (!entry.last || t > entry.last) entry.last = t;
    }
    const version = parseFloat(field(rec, "eventVersion"));
    const rawCategory = field(rec, "eventCategory").toLowerCase();
    const category =
      Number.isFinite(version) &&
      version >= MIN_EVENT_CATEGORY_VERSION &&
      CLOUDTRAIL_CATEGORIES.has(rawCategory)
        ? rawCategory
        : "unknown";
    const label =
      category === "management"
        ? "Management"
        : category === "data"
          ? "Data"
          : category === "insight"
            ? "Insight"
            : "unknown";
    bumpCategory(entry.categories, label, (c) => {
      c.count += 1;
      if (category === "management" || category === "data") {
        const ro = c.readOnly ?? { true: 0, false: 0, unknown: 0 };
        const raw = getCI(rec, "readOnly");
        if (raw === undefined || raw === null || raw === "") ro.unknown += 1;
        else if (raw === true || raw === "true") ro.true += 1;
        else if (raw === false || raw === "false") ro.false += 1;
        else ro.unknown += 1;
        c.readOnly = ro;
      }
    });
    byAccount.set(key, entry);
  }
  const drafts: CloudCoverageDraft[] = [...byAccount.entries()].map(([value, entry]) => ({
    provider: "aws-cloudtrail",
    scope: { kind: value === "(unknown)" ? "unknown" : "account", value: value === "(unknown)" ? "" : value },
    uploadId: "", // filled by the caller, which knows sourceArtifactHash(text)
    recordCount: entry.count,
    first: entry.first,
    last: entry.last,
    categories: [...entry.categories.values()],
  }));
  return sortScopesDeterministically(drafts);
}

// ───────────────────────────── GCP ─────────────────────────────

const GCP_LOG_TYPES = new Set(["activity", "data_access", "system_event", "policy"]);

export function gcpCoverage(records: readonly Row[]): CloudCoverageDraft[] {
  const byScope = new Map<
    string,
    {
      kind: string;
      value: string;
      count: number;
      first: string;
      last: string;
      categories: Map<string, CloudCoverageCategory>;
    }
  >();
  for (const rec of records) {
    if (!isObject(rec)) continue;
    const pp = isObject(getCI(rec, "protoPayload"))
      ? (getCI(rec, "protoPayload") as Row)
      : isObject(getCI(rec, "jsonPayload"))
        ? (getCI(rec, "jsonPayload") as Row)
        : null;
    if (!pp) continue;
    const logName = str(getCI(rec, "logName")).trim();
    const ref =
      projectRefOf(logName) ?? projectRefOf(`projects/${field(rec, "resource", "labels", "project_id")}`);
    const scopeKind = ref?.namespace ?? "unknown";
    const scopeValue = ref?.value ?? "";
    const key = `${scopeKind}|${scopeValue}`;
    const entry = byScope.get(key) ?? {
      kind: scopeKind,
      value: scopeValue,
      count: 0,
      first: "",
      last: "",
      categories: new Map(),
    };
    entry.count += 1;
    const t = normalizeTime(str(getCI(rec, "timestamp")) || str(getCI(rec, "receiveTimestamp")));
    if (t) {
      if (!entry.first || t < entry.first) entry.first = t;
      if (!entry.last || t > entry.last) entry.last = t;
    }
    // The CloudAudit log type is the trailing `%2F<type>` (URL-encoded `/`) segment of logName.
    const m = /cloudaudit\.googleapis\.com%2F([a-z_]+)/i.exec(logName);
    const logType = m ? m[1].toLowerCase() : "";
    const label = GCP_LOG_TYPES.has(logType) ? logType : "unknown";
    bumpCategory(entry.categories, label, (c) => (c.count += 1));
    byScope.set(key, entry);
  }
  const drafts: CloudCoverageDraft[] = [...byScope.values()].map((entry) => ({
    provider: "gcp",
    scope: { kind: entry.kind, value: entry.value },
    uploadId: "",
    recordCount: entry.count,
    first: entry.first,
    last: entry.last,
    categories: [...entry.categories.values()],
  }));
  return sortScopesDeterministically(drafts);
}

// ───────────────────────────── Azure ─────────────────────────────

const AZURE_CATEGORIES = new Set([
  "administrative",
  "security",
  "servicehealth",
  "alert",
  "autoscale",
  "recommendation",
  "policy",
  "resourcehealth",
]);
const AZURE_CATEGORY_LABEL: Record<string, string> = {
  administrative: "Administrative",
  security: "Security",
  servicehealth: "ServiceHealth",
  alert: "Alert",
  autoscale: "Autoscale",
  recommendation: "Recommendation",
  policy: "Policy",
  resourcehealth: "ResourceHealth",
};
const SUBSCRIPTION_FROM_RESOURCE_ID = /^\/subscriptions\/([^/]+)/i;

function azureSubscription(rec: Row): string {
  const explicit = field(rec, "subscriptionId") || field(rec, "SubscriptionId");
  if (explicit) return explicit;
  const resourceId = field(rec, "resourceId") || field(rec, "ResourceId");
  const m = SUBSCRIPTION_FROM_RESOURCE_ID.exec(resourceId);
  return m ? m[1] : "";
}

function azureCategory(rec: Row): string {
  const categoryField = getCI(rec, "category");
  const fromObject = isObject(categoryField) ? field(categoryField, "value") : "";
  const raw = (
    fromObject ||
    (typeof categoryField === "string" ? categoryField : "") ||
    field(rec, "Category") ||
    field(rec, "CategoryValue")
  ).toLowerCase();
  return AZURE_CATEGORIES.has(raw) ? AZURE_CATEGORY_LABEL[raw] : "unknown";
}

export function azureCoverage(records: readonly Row[]): CloudCoverageDraft[] {
  const byScope = new Map<
    string,
    {
      value: string;
      count: number;
      first: string;
      last: string;
      categories: Map<string, CloudCoverageCategory>;
    }
  >();
  for (const rec of records) {
    if (!isObject(rec)) continue;
    const hasOp = !!(
      getCI(rec, "operationName") ||
      getCI(rec, "OperationNameValue") ||
      getCI(rec, "OperationName")
    );
    if (!hasOp) continue;
    const sub = azureSubscription(rec);
    const key = sub || "(unknown)";
    const entry = byScope.get(key) ?? { value: sub, count: 0, first: "", last: "", categories: new Map() };
    entry.count += 1;
    const t = normalizeTime(
      field(rec, "eventTimestamp") ||
        field(rec, "time") ||
        field(rec, "TimeGenerated") ||
        field(rec, "timeStamp"),
    );
    if (t) {
      if (!entry.first || t < entry.first) entry.first = t;
      if (!entry.last || t > entry.last) entry.last = t;
    }
    bumpCategory(entry.categories, azureCategory(rec), (c) => (c.count += 1));
    byScope.set(key, entry);
  }
  const drafts: CloudCoverageDraft[] = [...byScope.entries()].map(([key, entry]) => ({
    provider: "azure",
    scope: { kind: key === "(unknown)" ? "unknown" : "subscription", value: entry.value },
    uploadId: "",
    recordCount: entry.count,
    first: entry.first,
    last: entry.last,
    categories: [...entry.categories.values()],
  }));
  return sortScopesDeterministically(drafts);
}

// ───────────────────────────── Microsoft 365 ─────────────────────────────

export function m365Coverage(records: readonly Row[]): CloudCoverageDraft[] {
  const byTenant = new Map<
    string,
    { count: number; first: string; last: string; categories: Map<string, CloudCoverageCategory> }
  >();
  for (const rec of records) {
    if (!isObject(rec)) continue;
    if (!getCI(rec, "Workload") || !getCI(rec, "RecordType")) continue;
    const org = field(rec, "OrganizationId");
    const key = org || "(unknown)";
    const entry = byTenant.get(key) ?? { count: 0, first: "", last: "", categories: new Map() };
    entry.count += 1;
    const t = normalizeTime(field(rec, "CreationTime"));
    if (t) {
      if (!entry.first || t < entry.first) entry.first = t;
      if (!entry.last || t > entry.last) entry.last = t;
    }
    const workload = field(rec, "Workload");
    const operation = field(rec, "Operation");
    const label = workload && operation ? `${workload}/${operation}` : "unknown/unknown";
    const recordTypeRaw = field(rec, "RecordType");
    const recordTypeId = recordTypeRaw && /^\d+$/.test(recordTypeRaw) ? Number(recordTypeRaw) : null;
    bumpCategory(entry.categories, label, (c) => {
      c.count += 1;
      if (recordTypeId !== null) {
        const ids = c.recordTypeIds ?? [];
        if (!ids.includes(recordTypeId) && ids.length < 64) ids.push(recordTypeId);
        c.recordTypeIds = ids;
      }
    });
    byTenant.set(key, entry);
  }
  const drafts: CloudCoverageDraft[] = [...byTenant.entries()].map(([value, entry]) => ({
    provider: "m365",
    scope: { kind: value === "(unknown)" ? "unknown" : "tenant", value: value === "(unknown)" ? "" : value },
    uploadId: "",
    recordCount: entry.count,
    first: entry.first,
    last: entry.last,
    categories: [...entry.categories.values()],
  }));
  return sortScopesDeterministically(drafts);
}

// ───────────────────────────── Google Workspace ─────────────────────────────

export function workspaceCoverage(records: readonly Row[]): CloudCoverageDraft[] {
  const byTenant = new Map<
    string,
    { count: number; first: string; last: string; categories: Map<string, CloudCoverageCategory> }
  >();
  for (const rec of records) {
    if (!isObject(rec)) continue;
    const events = getCI(rec, "events");
    if (!Array.isArray(events)) continue;
    const tenant = field(rec, "id", "customerId");
    const key = tenant || "(unknown)";
    const entry = byTenant.get(key) ?? { count: 0, first: "", last: "", categories: new Map() };
    entry.count += 1;
    const t = normalizeTime(field(rec, "id", "time"));
    if (t) {
      if (!entry.first || t < entry.first) entry.first = t;
      if (!entry.last || t > entry.last) entry.last = t;
    }
    const app = field(rec, "id", "applicationName");
    bumpCategory(entry.categories, app || "unknown", (c) => (c.count += 1));
    byTenant.set(key, entry);
  }
  const drafts: CloudCoverageDraft[] = [...byTenant.entries()].map(([value, entry]) => ({
    provider: "google-workspace",
    scope: { kind: value === "(unknown)" ? "unknown" : "tenant", value: value === "(unknown)" ? "" : value },
    uploadId: "",
    recordCount: entry.count,
    first: entry.first,
    last: entry.last,
    categories: [...entry.categories.values()],
  }));
  return sortScopesDeterministically(drafts);
}
