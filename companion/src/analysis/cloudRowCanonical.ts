// The default canonical envelope for the two Microsoft cloud row families that had none (#2485):
// a plain Unified Audit Log row (no Exchange / Entra decoder narrates it) and an Azure Activity row
// that is neither a logging change nor a storage key listing. Without one, the row reached the case
// bare and the read-time legacy upgrade cited it as `legacy-forensic-event` / `event:<id>` — losing
// the record it came from — and the import's sourceArtifactHash (stamped only on canonical rows)
// never reached it.
//
// Both envelopes are deliberately `event.category: "cloud"` with no `authentication` block: a UAL
// UserLoggedIn row stays out of the Login Graph exactly as before (it reads authentication/logon
// only). The actor is the record's own principal field, not a guess from the display text. The
// source IP is edge-observed on the same basis the importers already document (#1184).

import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";

/** What mapUal has already read from one plain UAL record. */
export interface UalRowFacts {
  operation: string;
  user: string;
  ip: string;
  observed: string;
  normalized: string;
  failed: boolean;
  tenant: string;
  /** The record's own Id (Graph `id`) — bare, as the Exchange / Entra-UAL siblings cite it. */
  recordId: string;
  /** The record's place in the whole upload. */
  index: number;
}

/** A plain UAL row's envelope: m365-ual / record:N / recordId (#2485). */
export function ualRowCanonical(f: UalRowFacts): CanonicalEventEnvelope {
  return createCanonicalEvent({
    event: {
      category: "cloud",
      type: "audit-operation",
      action: f.operation,
      outcome: f.failed ? "failure" : "success",
    },
    ...(f.user ? { actor: { kind: "account", name: f.user } } : {}),
    ...(f.ip ? { network: { source: { address: f.ip, provenance: "edge-observed" } } } : {}),
    cloud: { provider: "m365", ...(f.tenant ? { tenant: f.tenant } : {}) },
    time: { observed: f.observed, normalized: f.normalized },
    evidence: {
      rawRecords: [
        { source: "m365-ual", locator: `record:${f.index}`, ...(f.recordId ? { recordId: f.recordId } : {}) },
      ],
    },
    producer: { importer: "m365", parserVersion: "1", mappingVersion: "m365-ual-v1" },
    rawFieldMap: {
      "event.action": ["Operation", "Operations"],
      "event.outcome": ["ResultStatus", "ResultStatusDetail"],
      "time.observed": ["CreationTime", "CreationDate", "TimeGenerated"],
      ...(f.user ? { "actor.name": ["UserId", "UserKey", "UserIds"] } : {}),
      ...(f.ip
        ? { "network.source.address": ["ClientIP", "ClientIPAddress", "ActorIpAddress", "ClientInfoString"] }
        : {}),
      ...(f.tenant ? { "cloud.tenant": ["OrganizationId"] } : {}),
    },
  });
}

/** What mapAzure has already read from one Azure Activity record. */
export interface AzureRowFacts {
  operation: string;
  caller: string;
  ip: string;
  resource: string;
  observed: string;
  normalized: string;
  failed: boolean;
  /** The record's place in the whole upload. */
  index: number;
  /** azureActivityRecordId(rec) — the key the Azure record dedup already uses. */
  recordId: string | null;
}

/** The raw-record citation every Azure Activity envelope carries (#2485). */
export function azureRawRecords(index: number, recordId: string | null) {
  return [{ source: "azure-activity", locator: `record:${index}`, ...(recordId ? { recordId } : {}) }];
}

/** The default envelope for an Azure row that is neither a logging change nor a listKeys (#2485). */
export function azureRowCanonical(f: AzureRowFacts): CanonicalEventEnvelope {
  return createCanonicalEvent({
    event: {
      category: "cloud",
      type: "activity-operation",
      action: f.operation,
      outcome: f.failed ? "failure" : "success",
    },
    ...(f.caller ? { actor: { kind: "account", name: f.caller } } : {}),
    ...(f.ip ? { network: { source: { address: f.ip, provenance: "edge-observed" } } } : {}),
    cloud: { provider: "azure", ...(f.resource ? { resource: f.resource } : {}) },
    time: { observed: f.observed, normalized: f.normalized },
    evidence: { rawRecords: azureRawRecords(f.index, f.recordId) },
    producer: { importer: "azure-activity", parserVersion: "1", mappingVersion: "azure-activity-v1" },
    rawFieldMap: {
      "event.action": ["operationName.value", "operationName", "OperationNameValue", "OperationName"],
      "event.outcome": ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"],
      "time.observed": ["eventTimestamp", "time", "TimeGenerated", "timeStamp"],
      ...(f.caller ? { "actor.name": ["caller", "Caller", "identity.claims.name"] } : {}),
      ...(f.ip
        ? {
            "network.source.address": [
              "httpRequest.clientIpAddress",
              "claims.ipaddr",
              "CallerIpAddress",
              "callerIpAddress",
            ],
          }
        : {}),
      ...(f.resource
        ? { "cloud.resource": ["resourceId", "ResourceId", "resourceGroupName", "ResourceGroup"] }
        : {}),
    },
  });
}
