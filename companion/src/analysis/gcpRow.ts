// One GCP audit row from one reading (#931 item 12): the existing head (`GCP <method> (<svc>) by
// <principal> from <ip> on <resource>`), then the action's posture and object when the record
// is a binding delta, a credential fact or a key step, then the identity facts every row
// carries, each slot bounded — and the canonical envelope with the `gcp` block. The table grade
// and the denied bump stay the importer's; a reading only raises or, for a removal, states Low.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { GcpBlock } from "./canonicalGcp.js";
import { identityWords, readDelegation, readPrincipal, readProjects } from "./gcpIdentity.js";
import { decodeGcpAction, type GcpActionReading } from "./gcpIamRecord.js";
import { getCI, normalizeTime, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const BASIS =
  "this record only; capabilities are the role's documented permissions, nominal; no effective permission is evaluated";
const HEAD_MAX = 300;
const POSTURE_MAX = 220;
const OBJECT_MAX = 330;
const IDENTITY_MAX = 320;
const QUALIFIERS_MAX = 200;
const TOTAL_MAX = 600;

export interface GcpRowInput {
  rec: Row;
  pp: Row;
  method: string;
  service: string;
  principal: string;
  ip: string;
  resource: string;
  statusCode: number;
  head: string;
  severity: Severity;
  mitre: string[];
  baseKey: string;
  locator: string;
}

const clip = (s: string, max: number): string => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);

/** Every row of one GCP record: one per action reading, or the one generic row with the identity facts appended. */
export function gcpRows(input: GcpRowInput): MappedEvent[] {
  const { rec, pp, method, service } = input;
  const principal = readPrincipal(pp);
  const delegation = readDelegation(pp);
  const projects = readProjects(rec, pp);
  const identity = identityWords(principal, delegation, projects);
  const readings = decodeGcpAction(pp, rec, method, service);
  const base: GcpBlock = { principal, delegation, projects, basis: BASIS };
  if (readings.length === 0) return [row(input, null, identity, base)];
  return readings.map((r) => row(input, r, identity, base));
}

function row(
  input: GcpRowInput,
  reading: GcpActionReading | null,
  identityFacts: string[],
  base: GcpBlock,
): MappedEvent {
  const { rec, pp, method, statusCode, locator } = input;
  // A binding delta says more than the table and its grade replaces the blanket SetIamPolicy
  // grade; any other reading only raises the table grade.
  const severity: Severity = reading
    ? reading.replacesTableGrade
      ? reading.severity
      : RANK[reading.severity] > RANK[input.severity]
        ? reading.severity
        : input.severity
    : input.severity;
  const mitre = [
    ...new Set([
      ...(reading?.mitre ?? []),
      ...(reading
        ? input.mitre.filter(
            (t) => reading.kind !== "binding" || t !== "T1098.003" || reading.mitre.includes(t),
          )
        : input.mitre),
    ]),
  ];
  // The head, the posture and the qualifiers (a condition, a denial, a differing copy) are
  // reserved; the object and the identity facts share what is left, the object first.
  // The head keeps a digest of what its clip removed (#940): two object reads never fold by text.
  const head = boundedTextTo(input.head, HEAD_MAX);
  const posture = reading ? clip(reading.posture, POSTURE_MAX) : "";
  const qualifiers = clip((reading?.qualifiers ?? []).filter(Boolean).join("; "), QUALIFIERS_MAX);
  const reserved =
    head.length + (posture ? posture.length + 3 : 0) + (qualifiers ? qualifiers.length + 3 : 0);
  let room = TOTAL_MAX - reserved;
  const objectWords = reading?.object
    ? clip(reading.object, Math.max(0, Math.min(OBJECT_MAX, room - 3)))
    : "";
  room -= objectWords ? objectWords.length + 3 : 0;
  const identity = identityFacts.length
    ? clip(identityFacts.join("; "), Math.max(0, Math.min(IDENTITY_MAX, room - 3)))
    : "";
  const parts = [
    head,
    posture,
    objectWords.length > 8 ? objectWords : "",
    identity.length > 8 ? identity : "",
  ].filter(Boolean);
  const description = boundedTextTo(`${parts.join(" — ")}${qualifiers ? ` [${qualifiers}]` : ""}`, TOTAL_MAX);
  const block: GcpBlock = {
    ...base,
    ...(reading?.binding ? { binding: reading.binding } : {}),
    ...(reading?.credential ? { credential: reading.credential } : {}),
    ...(reading?.key ? { key: reading.key } : {}),
  };
  const observed = str(getCI(rec, "timestamp")) || str(getCI(rec, "receiveTimestamp"));
  const type = reading
    ? reading.kind === "binding"
      ? "iam-binding"
      : reading.kind === "credential"
        ? "credential"
        : "service-account-key"
    : "api-call";
  const actorEmail = base.principal.email ?? "";
  const actorKind =
    base.principal.kind === "service-account" || base.principal.kind === "service-agent"
      ? "cloud_principal"
      : "account";
  const firstDelegation = delegationSubject(base);
  const sa = reading?.serviceAccount;
  const object =
    sa && (sa.email || sa.uniqueId)
      ? {
          kind: "cloud_principal" as const,
          ...(sa.uniqueId ? { id: sa.uniqueId } : {}),
          ...(sa.email ? { name: sa.email } : {}),
        }
      : undefined;
  const resource = str(getCI(pp, "resourceName")).trim();
  return {
    timestamp: normalizeTime(observed),
    description,
    severity,
    mitre,
    aggKey: boundedAggKey(`${input.baseKey}${reading?.keySegment ?? ""}`.toLowerCase()),
    sources: ["GCP Audit"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type, action: method, outcome: statusCode !== 0 ? "failure" : "success" },
      ...(actorEmail
        ? { actor: { kind: actorKind, name: actorEmail } }
        : base.principal.subject
          ? { actor: { kind: "cloud_principal", id: base.principal.subject.value } }
          : {}),
      ...(firstDelegation ? { subject: { kind: "account", name: firstDelegation } } : {}),
      ...(object ? { object } : {}),
      ...(input.ip ? { network: { source: { address: input.ip } } } : {}),
      cloud: {
        provider: "gcp",
        ...(base.projects.log?.namespace === "projects" ? { tenant: base.projects.log.value } : {}),
        ...(actorEmail ? { principalId: actorEmail } : {}),
        ...(base.principal.kind !== "none" ? { principalType: base.principal.kind } : {}),
        ...(resource ? { resource } : {}),
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: [
          {
            source: "gcp-audit",
            locator,
            ...(str(getCI(rec, "insertId")).trim() ? { recordId: str(getCI(rec, "insertId")).trim() } : {}),
          },
        ],
      },
      producer: {
        importer: "gcp-audit",
        parserVersion: "1",
        mappingVersion: "gcp-identity-v1",
        ruleVersions: ["gcp-identity-v1"],
      },
      rawFieldMap: {
        "event.action": ["protoPayload.methodName"],
        "event.outcome": ["protoPayload.status.code"],
        "time.observed": ["timestamp"],
        ...(actorEmail
          ? { "actor.name": ["protoPayload.authenticationInfo.principalEmail"] }
          : base.principal.subject
            ? { "actor.id": ["protoPayload.authenticationInfo.principalSubject"] }
            : {}),
        ...(firstDelegation
          ? {
              "subject.name": [
                "protoPayload.authenticationInfo.serviceAccountDelegationInfo[].firstPartyPrincipal.principalEmail",
              ],
            }
          : {}),
        ...(object?.id ? { "object.id": ["protoPayload.resourceName", "resource.labels.unique_id"] } : {}),
        ...(object?.name
          ? {
              "object.name": [
                "protoPayload.request.name",
                "resource.labels.email_id",
                "protoPayload.resourceName",
              ],
            }
          : {}),
        ...(input.ip ? { "network.source.address": ["protoPayload.requestMetadata.callerIp"] } : {}),
        "cloud.provider": ["protoPayload.serviceName"],
        ...(base.projects.log?.namespace === "projects"
          ? { "cloud.tenant": ["logName", "resource.labels.project_id"] }
          : {}),
        ...(actorEmail ? { "cloud.principalId": ["protoPayload.authenticationInfo.principalEmail"] } : {}),
        ...(resource ? { "cloud.resource": ["protoPayload.resourceName"] } : {}),
      },
      derivationMap: {
        ...(base.principal.kind !== "none"
          ? {
              "cloud.principalType":
                "gcp-identity-v1: typed only by a documented service-account address shape; anything else is user-or-unknown",
            }
          : {}),
      },
      gcp: block,
    }),
  };
}

/** The first recorded delegation authority when it is a first-party principal — the record's own first entry, not a selected impersonator. */
function delegationSubject(base: GcpBlock): string {
  const first = base.delegation[0];
  return first && first.kind === "first-party" && first.value ? first.value : "";
}
