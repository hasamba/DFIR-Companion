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
import { isGuid, outcomeWord, readEntraAuditRecord, type EntraAuditRecord } from "./entraAuditRecord.js";
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
 * A tenant-scoped map from a service principal's OBJECT id to its immutable app id, learned from
 * records that state both — an app-role assignment names the resource's object id and its
 * ServicePrincipalNames; a service-principal sign-in names `resourceServicePrincipalId` and
 * `resourceId`. Consent records name the resource by object id only; without this map they cannot
 * identify the API and grade Medium.
 */
export function learnApiResolver(records: readonly Row[]): Resolver {
  const map = new Map<string, string>();
  for (const rec of records) {
    const spId = str(getCI(rec, "resourceServicePrincipalId")).trim().toLowerCase();
    const appId = str(getCI(rec, "resourceId")).trim().toLowerCase();
    if (isGuid(spId) && isGuid(appId) && KNOWN_APIS[appId]) map.set(spId, appId);
    const audit = readEntraAuditRecord(rec);
    if (!audit) continue;
    const names = audit.props.find((p) => /^targetid\.serviceprincipalnames$/i.test(p.name))?.newValue;
    const target = audit.targets[0];
    if (!target?.id || !Array.isArray(names)) continue;
    const known = names.map((n) => String(n).trim().toLowerCase()).find((n) => isGuid(n) && KNOWN_APIS[n]);
    if (known) map.set(target.id.toLowerCase(), known);
  }
  return (objectId) => map.get(objectId.trim().toLowerCase()) ?? "";
}

function head(r: EntraAuditRecord): { who: string; ip: string; head: string } {
  const who = oneLine(r.initiator.upn || r.initiator.name || r.initiator.id).slice(0, WHO_MAX);
  const ip = cleanIp(r.initiator.ip);
  return {
    who,
    ip,
    head: `Entra audit: ${r.operation}${who ? ` by ${who}` : ""}${ip ? ` from ${ip}` : ""}`,
  };
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
    ...(ip ? { network: { source: { address: ip } } } : {}),
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
  if (!changes.length) {
    // The plain row, as before: the first target's label and "+n more", the table's grade.
    const labels = r.targets.map((t) => t.upn || t.name).filter(Boolean);
    const target = labels.length
      ? `${labels[0]}${labels.length > 1 ? ` +${labels.length - 1} more` : ""}`
      : "";
    const def = plainSeverity(r.operation);
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

export function mapSpSignIn(rec: Row, sink: Map<string, SiemIoc>, index: number): MappedEvent {
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
  const ip = cleanIp(str(getCI(rec, "ipAddress")));
  const credType = str(getCI(rec, "clientCredentialType")).trim();
  const credKey =
    str(getCI(rec, "servicePrincipalCredentialKeyId")).trim() ||
    str(getCI(rec, "servicePrincipalCredentialThumbprint")).trim();
  const tenant = str(getCI(rec, "resourceTenantId")).trim() || str(getCI(rec, "homeTenantId")).trim();
  const status = getCI(rec, "status");
  const rawCode = isObject(status) ? getCI(status, "errorCode") : undefined;
  const code =
    typeof rawCode === "number"
      ? rawCode
      : /^\d+$/.test(str(rawCode).trim())
        ? Number(str(rawCode).trim())
        : null;
  const rejected = code !== null && code !== 0 && WORKLOAD_CREDENTIAL_FAILURES[code];
  const outcome = code === 0 ? "success" : code === null ? "unknown" : "failure";
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
  const observed = str(getCI(rec, "createdDateTime"));
  return {
    timestamp: normalizeTime(observed),
    description,
    severity,
    mitre: rejected ? ["T1078.004"] : [],
    aggKey: boundedAggKey(
      `entra-spsignin|${tenant}|${spId || appId || name}|${resourceSp || resourceAppId}|${credKey || "-"}|${credType}|${outcome}|${code ?? ""}`.toLowerCase(),
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
      ...(ip ? { network: { source: { address: ip } } } : {}),
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
