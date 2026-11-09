// Entra directory-audit rows and service-principal sign-ins (#931 item 1) — the ingest half.
//
// Every audit record, in either export shape, becomes one row per atomic change the decoder finds
// (entraAppChange.ts), each with a reserved-budget description (the posture, the object and the
// qualifiers survive the clip) and a canonical envelope keyed on ids, so nothing downstream has to
// re-parse prose to know which application changed. A record the decoder does not narrate keeps
// the plain row it always had, with the envelope added.
//
// Service-principal sign-ins used to be dropped (no userPrincipalName, so nothing recognised
// them). They are the "credential use" evidence and get a row: a token issued to an application,
// with the credential type from `clientCredentialType` — never inferred from a key id — and the
// workload-identity failure codes told apart from every other failure.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import { renderAwsDescription } from "./awsDescription.js";
import { decodeEntraAppChanges, type Resolver } from "./entraAppChange.js";
export type { Resolver };
import {
  isGuid,
  outcomeWord,
  readEntraAuditRecord,
  type EntraAuditRecord,
  type EntraProp,
} from "./entraAuditRecord.js";
import { KNOWN_APIS } from "./entraCapabilities.js";
import {
  addIoc,
  cleanIp,
  getCI,
  isObject,
  normalizeTime,
  oneLine,
  str,
  type MappedEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

const WHO_MAX = 50;
const CODE_MAX = 30;

// AADSTS codes that mean the APPLICATION'S CREDENTIAL was rejected — the workload-identity
// counterpart of the user-password allow-list in m365Import.ts. Every other non-zero code is a
// failure without a technique (a Conditional Access block, a missing resource).
const WORKLOAD_CREDENTIAL_FAILURES: Record<number, string> = {
  7000215: "invalid client secret",
  7000222: "client secret expired",
  700027: "client assertion signature invalid",
  700024: "client assertion outside its validity",
};

/**
 * A tenant-scoped map from a service principal's OBJECT id to its immutable app id, learned only
 * from records that state the relationship by construction: an app-role assignment names the
 * resource's object id (the target that carries the property) and its ServicePrincipalNames,
 * which Entra populates with the app id; a service-principal sign-in names
 * `resourceServicePrincipalId` and `resourceId`. Consent records name the resource by object id
 * only; without this map they cannot identify the API and grade Medium. Two records that disagree
 * about one object id leave it unresolved — a fact this importer cannot pick between.
 */
export function learnApiResolver(records: readonly Row[]): Resolver {
  const learner = createApiResolverLearner();
  learner.add(records);
  return learner.finish();
}

/**
 * learnApiResolver, one batch at a time (#2303): the streaming import's preliminary pass feeds
 * every batch of the file, then `finish()` gives the resolver the whole-file read would. Facts are
 * kept raw until the end, because whether a tenant-less record may learn depends on the WHOLE file.
 */
export function createApiResolverLearner(): { add(records: readonly Row[]): void; finish(): Resolver } {
  // Deduplicated as they arrive (a million sign-ins name the same few APIs): key → app ids seen.
  const facts = new Map<string, Set<string>>();
  let anyTenant = false;
  // A record without a tenant id may only learn from, and resolve against, other tenant-less
  // records when the WHOLE file is tenant-less — a single export from one tenant by construction
  // (Graph directoryAudits carries no tenant field). The moment one record names a tenant, a
  // tenant-less record is of unknown tenant and neither learns nor resolves.
  const tenantOf = (rec: Row): string =>
    str(getCI(rec, "resourceTenantId")).trim() ||
    str(getCI(rec, "homeTenantId")).trim() ||
    str(getCI(rec, "tenantId")).trim() ||
    str(getCI(rec, "OrganizationId")).trim() ||
    str(getCI(rec, "TargetContextId")).trim();
  const add = (records: readonly Row[]): void => {
    for (const rec of records) {
      if (!anyTenant && tenantOf(rec) !== "") anyTenant = true;
      for (const f of recordFacts(rec)) {
        const k = `${f.tenant.toLowerCase()}|${f.objectId.toLowerCase()}`;
        facts.set(k, (facts.get(k) ?? new Set()).add(f.appId));
      }
    }
  };
  const finish = (): Resolver => {
    const usable = (tenant: string): boolean => tenant !== "" || !anyTenant;
    const map = new Map<string, string>();
    const conflicts = new Set<string>();
    for (const [k, appIds] of facts) {
      if (!usable(k.slice(0, k.indexOf("|")))) continue;
      if (appIds.size > 1) conflicts.add(k);
      else map.set(k, [...appIds][0]);
    }
    return (objectId, tenant) => {
      if (!usable(tenant)) return "";
      const k = `${tenant.toLowerCase()}|${objectId.trim().toLowerCase()}`;
      return conflicts.has(k) ? "" : (map.get(k) ?? "");
    };
  };
  return { add, finish };
}

/** The object-id → app-id facts one record states by construction (see learnApiResolver). */
function recordFacts(rec: Row): Array<{ tenant: string; objectId: string; appId: string }> {
  const out: Array<{ tenant: string; objectId: string; appId: string }> = [];
  const spId = str(getCI(rec, "resourceServicePrincipalId")).trim().toLowerCase();
  const appId = str(getCI(rec, "resourceId")).trim().toLowerCase();
  const tenant = str(getCI(rec, "resourceTenantId")).trim() || str(getCI(rec, "homeTenantId")).trim();
  if (isGuid(spId) && isGuid(appId) && KNOWN_APIS[appId]) out.push({ tenant, objectId: spId, appId });
  const audit = readEntraAuditRecord(rec);
  if (!audit || !/^add app role assignment to service principal$/i.test(audit.operation)) return out;
  const prop = audit.props.find((p) => /^targetid\.serviceprincipalnames$/i.test(p.name));
  if (!prop || !Array.isArray(prop.newValue)) return out;
  const target = prop.targetIndex >= 0 ? audit.targets[prop.targetIndex] : audit.targets[0];
  if (!target?.id) return out;
  const known = prop.newValue
    .map((n) => String(n).trim().toLowerCase())
    .filter((n) => isGuid(n) && KNOWN_APIS[n]);
  if (known.length === 1) out.push({ tenant: audit.tenant, objectId: target.id, appId: known[0] });
  return out;
}

function head(r: EntraAuditRecord): { who: string; ip: string; head: string } {
  const who = oneLine(r.initiator.upn || r.initiator.name || r.initiator.id).slice(0, WHO_MAX);
  // initiatedBy.user.ipAddress (graph shape) / ActorIpAddress (the other export shape) — both
  // Entra's own audit log fields, recorded by Microsoft's own directory-service infrastructure at
  // call time — edge-observed, not client-asserted (#1184 audit).
  const ip = cleanIp(r.initiator.ip);
  return {
    who,
    ip,
    head: `Entra audit: ${r.operation}${who ? ` by ${who}` : ""}${ip ? ` from ${ip}` : ""}`,
  };
}

// ───────────────────────────── the row's details ─────────────────────────────

// Entra repeats the changed property NAMES in one extra property; the real properties carry the values.
const INCLUDED = /^included updated properties$/i;
const DETAIL_VALUE_MAX = 200;
const DETAIL_PROPS_MAX = 25;
const DETAIL_TOTAL_MAX = 6000;
const DETAIL_TARGETS_MAX = 5;
// Controls and bidi overrides become spaces: the text is adversary-reachable and is shown verbatim.
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]+/g;

function detailText(s: string, max: number): string {
  const t = s.replace(UNSAFE_CHARS, " ").trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

function detailValue(p: EntraProp, which: "oldValue" | "newValue"): string {
  if (p.unreadable) return "(too large to read)";
  const v = p[which];
  if (v === null || v === undefined || v === "") return "(empty)";
  return detailText(typeof v === "string" ? v : JSON.stringify(v), DETAIL_VALUE_MAX);
}

/** The names Entra lists in "Included Updated Properties"; empty when it lists none. */
function includedNames(r: EntraAuditRecord): string[] {
  return r.props
    .filter((p) => INCLUDED.test(p.name) && !p.unreadable)
    .flatMap((p) => (typeof p.newValue === "string" ? p.newValue.split(",") : []))
    .map((n) => n.trim())
    .filter(Boolean);
}

/** An app refreshing its own service principal with no changed property: Microsoft's own upkeep. */
function isEmptySelfRefresh(r: EntraAuditRecord): boolean {
  if (r.initiator.kind !== "app" || !/^update service principal$/i.test(r.operation)) return false;
  if (r.props.some((p) => !INCLUDED.test(p.name)) || includedNames(r).length) return false;
  const own = new Set((r.initiator.objectIds ?? []).map((x) => x.toLowerCase()));
  return r.targets.length > 0 && r.targets.every((t) => t.id && own.has(t.id.toLowerCase()));
}

/** Who acted, what was changed, and every changed property — the text of the row's [details] panel. */
function auditDetails(r: EntraAuditRecord): string {
  const who = r.initiator.upn || r.initiator.name || r.initiator.id || r.initiator.appId;
  const lines = [
    `Initiated by: ${who ? detailText(who, 200) : "(not recorded)"} (${r.initiator.kind}${r.initiator.id ? ` ${detailText(r.initiator.id, 80)}` : ""})`,
  ];
  const changed = r.props.filter((p) => !INCLUDED.test(p.name));
  const targets = r.targets.length ? r.targets : [{ type: "", id: "", name: "", upn: "" }];
  let shown = 0;
  targets.slice(0, DETAIL_TARGETS_MAX).forEach((t, i) => {
    const label = t.upn || t.name;
    if (label || t.id) {
      lines.push(
        `Target: ${label ? detailText(label, 200) : "(no name)"} (${detailText(t.type || "object", 40)}${t.id ? ` ${detailText(t.id, 80)}` : ""})`,
      );
    }
    for (const p of changed.filter((c) => c.targetIndex === i || (i === 0 && c.targetIndex < 0))) {
      if (shown++ >= DETAIL_PROPS_MAX) continue;
      lines.push(
        `  ${detailText(p.name, 120)}: ${detailValue(p, "oldValue")} → ${detailValue(p, "newValue")}`,
      );
    }
  });
  if (r.targets.length > DETAIL_TARGETS_MAX)
    lines.push(`+${r.targets.length - DETAIL_TARGETS_MAX} more targets`);
  if (shown > DETAIL_PROPS_MAX) lines.push(`+${shown - DETAIL_PROPS_MAX} more properties`);
  if (!changed.length) {
    const names = includedNames(r);
    lines.push(
      names.length
        ? `Changed properties (values not recorded): ${detailText(names.join(", "), 600)}`
        : 'Microsoft recorded no changed property for this change ("Included Updated Properties" is empty).',
    );
  }
  const text = lines.join("\n");
  return text.length > DETAIL_TOTAL_MAX ? `${text.slice(0, DETAIL_TOTAL_MAX)}…` : text;
}

function envelope(
  r: EntraAuditRecord,
  index: number,
  outcome: string,
  detail: {
    object?: { id: string; name: string };
    target?: { kind: "cloud_principal" | "account" | "other"; id: string; name: string };
    resource?: string;
  },
): CanonicalEventEnvelope {
  // Same Entra audit log field as head() above — edge-observed, not client-asserted (#1184 audit).
  const ip = cleanIp(r.initiator.ip);
  const actorId = r.initiator.id || r.initiator.appId;
  const actorName = r.initiator.upn || r.initiator.name;
  const observed = r.time;
  return createCanonicalEvent({
    event: { category: "cloud", type: "directory-change", action: r.operation, outcome },
    ...(actorId || actorName
      ? {
          actor: {
            kind: r.initiator.kind === "app" ? "cloud_principal" : "account",
            ...(actorId ? { id: actorId } : {}),
            ...(actorName ? { name: actorName } : {}),
          },
        }
      : {}),
    ...(detail.object?.id || detail.object?.name
      ? {
          object: {
            kind: "cloud_principal",
            ...(detail.object.id ? { id: detail.object.id } : {}),
            ...(detail.object.name ? { name: detail.object.name } : {}),
          },
        }
      : {}),
    ...(detail.target?.id || detail.target?.name
      ? {
          target: {
            kind: detail.target.kind,
            ...(detail.target.id ? { id: detail.target.id } : {}),
            ...(detail.target.name ? { name: detail.target.name } : {}),
          },
        }
      : {}),
    ...(ip ? { network: { source: { address: ip, provenance: "edge-observed" } } } : {}),
    cloud: {
      provider: "entra",
      ...(r.tenant ? { tenant: r.tenant } : {}),
      ...(actorId ? { principalId: actorId } : {}),
      principalType: r.initiator.kind === "app" ? "application" : r.initiator.kind,
      ...(detail.resource ? { resource: detail.resource } : {}),
    },
    time: { observed, normalized: normalizeTime(observed) },
    evidence: {
      rawRecords: [
        {
          source: r.shape === "graph" ? "entra-audit" : "m365-ual",
          locator: `record:${index}`,
          ...(r.recordId ? { recordId: r.recordId } : {}),
        },
      ],
    },
    producer: {
      importer: "m365-audit",
      parserVersion: "1",
      mappingVersion: r.shape === "graph" ? "entra-audit-v2" : "m365-ual-entra-v1",
      ruleVersions: ["entra-app-change-v1"],
    },
    rawFieldMap: {
      "event.action": [r.shape === "graph" ? "activityDisplayName" : "Operation"],
      "event.outcome": [r.shape === "graph" ? "result" : "ResultStatus"],
      "time.observed": [r.shape === "graph" ? "activityDateTime" : "CreationTime"],
      ...(actorId ? { "actor.id": [r.shape === "graph" ? "initiatedBy.user.id" : "Actor[].ID"] } : {}),
      ...(ip
        ? {
            "network.source.address": [r.shape === "graph" ? "initiatedBy.user.ipAddress" : "ActorIpAddress"],
          }
        : {}),
    },
  });
}

/**
 * Map one Entra audit record (either shape) to its rows: one per decoded change, or the plain row
 * when nothing was decoded. `index` is the record's position in the file — the locator.
 */
export function mapEntraAuditRows(
  rec: Row,
  sink: Map<string, SiemIoc>,
  index: number,
  resolve: Resolver,
  plainSeverity: (activity: string) => { severity: Severity; mitre?: string[] },
): MappedEvent[] {
  const r = readEntraAuditRecord(rec);
  if (!r) return [];
  const h = head(r);
  if (h.ip) addIoc(sink, "ip", h.ip);
  const timestamp = normalizeTime(r.time);
  const outcome = r.outcome;
  const tail = r.outcome === "success" ? "" : `[${r.outcome}]`;
  const changes = decodeEntraAppChanges(r, resolve);
  const details = auditDetails(r);
  if (!changes.length) {
    // The plain row, as before: the first target's label and "+n more", the table's grade.
    const labels = r.targets.map((t) => t.upn || t.name).filter(Boolean);
    const target = labels.length
      ? `${labels[0]}${labels.length > 1 ? ` +${labels.length - 1} more` : ""}`
      : "";
    // An app's empty refresh of its own service principal names no change at all, so it is no
    // evidence of the credential tampering the table's grade assumes.
    const def = isEmptySelfRefresh(r)
      ? { severity: "Low" as Severity, mitre: [] }
      : plainSeverity(r.operation);
    const targetIds = [
      ...new Set(
        r.targets
          .map((t) => `${t.type || "resource"}:${t.id || t.upn || t.name}`)
          .filter((x) => !x.endsWith(":")),
      ),
    ].sort();
    const first = r.targets[0];
    return [
      {
        timestamp,
        description:
          `${h.head}${target ? ` → ${oneLine(target).slice(0, 120)}` : ""}${tail ? ` ${tail}` : ""}`.slice(
            0,
            600,
          ),
        severity: def.severity,
        mitre: [...(def.mitre ?? [])],
        aggKey: boundedAggKey(
          `entra-audit|${r.operation}|${outcome}|${r.initiator.id || r.initiator.appId || h.who}|${targetIds.join(",")}`.toLowerCase(),
        ),
        sources: ["Entra ID"],
        message: details,
        canonical: envelope(
          r,
          index,
          outcome,
          first
            ? {
                target: {
                  kind: /user/i.test(first.type)
                    ? "account"
                    : /serviceprincipal|application/i.test(first.type)
                      ? "cloud_principal"
                      : "other",
                  id: first.id,
                  name: first.upn || first.name,
                },
              }
            : {},
        ),
      },
    ];
  }
  return changes.map((c) => ({
    timestamp,
    description: renderAwsDescription({
      head: h.head,
      posture: c.posture,
      outcome: outcomeWord(r.outcome),
      object: c.object,
      optional: [c.words],
      tail,
      qualifiers: c.qualifiers,
    }),
    severity: c.severity,
    mitre: [...c.mitre],
    aggKey: boundedAggKey(c.aggKey),
    sources: ["Entra ID"],
    message: details,
    canonical: envelope(r, index, outcome, {
      object: { id: c.subject.id, name: c.subject.name },
      ...(c.role
        ? {
            target: {
              kind: /serviceprincipal|application/i.test(c.role.memberType) ? "cloud_principal" : "account",
              id: c.role.memberId,
              name: c.role.memberName,
            },
          }
        : c.resource.id || c.resource.name
          ? { target: { kind: "other", id: c.resource.id, name: c.resource.api || c.resource.name } }
          : {}),
      resource: c.resource.id || c.subject.id,
    }),
  }));
}

// ───────────────────────────── service-principal sign-ins ─────────────────────────────

/** A Graph sign-in record for an application: a service principal id and no user. */
export function isServicePrincipalSignIn(rec: Row): boolean {
  return (
    !str(getCI(rec, "userPrincipalName")) &&
    !!(str(getCI(rec, "servicePrincipalId")) || str(getCI(rec, "servicePrincipalName"))) &&
    (getCI(rec, "status") !== undefined ||
      getCI(rec, "resourceDisplayName") !== undefined ||
      getCI(rec, "appId") !== undefined)
  );
}

/** The fields a service-principal sign-in record carries, read once for the row and for the privilege path (#973). */
export interface SpSignIn {
  spId: string;
  appId: string;
  name: string;
  resourceSp: string;
  resourceAppId: string;
  resourceName: string;
  ip: string;
  credType: string;
  /** The key id and the certificate thumbprint the sign-in names, kept apart: a key id matches only a key id. */
  credKeyId: string;
  credThumbprint: string;
  /** Whichever of the two the sign-in names, for the words and the aggregation key. */
  credKey: string;
  tenant: string;
  code: number | null;
  rejected: string | false;
  outcome: "success" | "failure" | "unknown";
  observed: string;
}

export function readSpSignIn(rec: Row): SpSignIn {
  const spId = str(getCI(rec, "servicePrincipalId")).trim();
  const appId = str(getCI(rec, "appId")).trim();
  const name = oneLine(str(getCI(rec, "servicePrincipalName")) || str(getCI(rec, "appDisplayName"))).slice(
    0,
    WHO_MAX,
  );
  const resourceSp = str(getCI(rec, "resourceServicePrincipalId")).trim();
  const resourceAppId = str(getCI(rec, "resourceId")).trim();
  const resourceName = oneLine(
    str(getCI(rec, "resourceDisplayName")) || KNOWN_APIS[resourceAppId.toLowerCase()] || "",
  ).slice(0, WHO_MAX);
  // Entra sign-in log's own `ipAddress` field, recorded by Microsoft's own directory-service
  // infrastructure at call time — edge-observed, not client-asserted (#1184 audit).
  const ip = cleanIp(str(getCI(rec, "ipAddress")));
  const credType = str(getCI(rec, "clientCredentialType")).trim();
  const credKeyId = str(getCI(rec, "servicePrincipalCredentialKeyId")).trim();
  const credThumbprint = str(getCI(rec, "servicePrincipalCredentialThumbprint")).trim();
  const credKey = credKeyId || credThumbprint;
  const tenant = str(getCI(rec, "resourceTenantId")).trim() || str(getCI(rec, "homeTenantId")).trim();
  const status = getCI(rec, "status");
  const rawCode = isObject(status) ? getCI(status, "errorCode") : undefined;
  const code =
    typeof rawCode === "number"
      ? rawCode
      : /^\d+$/.test(str(rawCode).trim())
        ? Number(str(rawCode).trim())
        : null;
  const rejected = code !== null && code !== 0 ? (WORKLOAD_CREDENTIAL_FAILURES[code] ?? false) : false;
  const outcome = code === 0 ? "success" : code === null ? "unknown" : "failure";
  return {
    spId,
    appId,
    name,
    resourceSp,
    resourceAppId,
    resourceName,
    ip,
    credType,
    credKeyId,
    credThumbprint,
    credKey,
    tenant,
    code,
    rejected,
    outcome,
    observed: str(getCI(rec, "createdDateTime")),
  };
}

export function mapSpSignIn(rec: Row, sink: Map<string, SiemIoc>, index: number): MappedEvent {
  const {
    spId,
    appId,
    name,
    resourceSp,
    resourceAppId,
    resourceName,
    ip,
    credType,
    credKey,
    tenant,
    code,
    rejected,
    outcome,
  } = readSpSignIn(rec);
  const isSecret = /clientsecret/i.test(credType);
  const severity: Severity = rejected
    ? "Medium"
    : outcome === "failure"
      ? "Low"
      : outcome === "unknown"
        ? "Info"
        : isSecret
          ? "Low"
          : "Info";
  if (ip) addIoc(sink, "ip", ip);
  const verdict = rejected
    ? `credential rejected (${rejected}, AADSTS${code})`
    : outcome === "failure"
      ? `failed (AADSTS${code})`
      : outcome === "unknown"
        ? "outcome unknown"
        : "token issued";
  const description = renderAwsDescription({
    head: `Entra sign-in: application ${name || "(unnamed)"}${appId ? ` (${appId})` : ""}`,
    posture: verdict,
    outcome: "",
    object: `${resourceName ? `→ ${resourceName}` : ""}${ip ? ` from ${ip}` : ""}`.trim(),
    optional: [
      credType
        ? `credential: ${credType.slice(0, CODE_MAX)}${credKey ? ` ${credKey.slice(0, 36)}` : ""}`
        : "",
    ],
    tail: "",
    qualifiers: [],
  });
  const observed = readSpSignIn(rec).observed;
  return {
    timestamp: normalizeTime(observed),
    description,
    severity,
    mitre: rejected ? ["T1078.004"] : [],
    aggKey: boundedAggKey(
      `entra-spsignin|${tenant}|${spId || appId || name}|${resourceSp || resourceAppId}|${credKey || "-"}|${credType}|${outcome}|${code ?? ""}|${ip}`.toLowerCase(),
    ),
    sources: ["Entra ID"],
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "sign-in", action: "service-principal", outcome },
      actor: {
        kind: "cloud_principal",
        ...(spId || appId ? { id: spId || appId } : {}),
        ...(name ? { name } : {}),
      },
      ...(resourceSp || resourceName
        ? {
            target: {
              kind: "other",
              ...(resourceSp ? { id: resourceSp } : {}),
              ...(resourceName ? { name: resourceName } : {}),
            },
          }
        : {}),
      ...(ip ? { network: { source: { address: ip, provenance: "edge-observed" } } } : {}),
      cloud: {
        provider: "entra",
        ...(tenant ? { tenant } : {}),
        ...(spId || appId ? { principalId: spId || appId } : {}),
        principalType: "application",
        ...(resourceSp ? { resource: resourceSp } : {}),
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: [
          {
            source: "entra-signin",
            locator: `record:${index}`,
            ...(str(getCI(rec, "id")) ? { recordId: str(getCI(rec, "id")) } : {}),
          },
        ],
      },
      producer: {
        importer: "m365-audit",
        parserVersion: "1",
        mappingVersion: "entra-spsignin-v1",
        ruleVersions: ["entra-workload-credential-v1"],
      },
      rawFieldMap: {
        "event.outcome": ["status.errorCode"],
        "time.observed": ["createdDateTime"],
        "actor.id": ["servicePrincipalId", "appId"],
        ...(ip ? { "network.source.address": ["ipAddress"] } : {}),
      },
    }),
  };
}
