// Mocks for the GCP collector tests (#2314): synthetic audit entries (documentation addresses,
// example.com principals) and a scripted wire that records every request the collector sends.

import type {
  GcpWire,
  GcpWireRequest,
  GcpWireResponse,
} from "../../../src/integrations/cloudCollectGcp/gcpWire.js";

export const PROJECT = "test-project-01";

const LOG_OF: Record<string, string> = {
  SetIamPolicy: "activity",
  "google.iam.admin.v1.CreateServiceAccountKey": "activity",
  "google.logging.v2.ConfigServiceV2.DeleteSink": "activity",
  "storage.objects.get": "data_access",
};

/** One Cloud Audit Log entry, as entries:list and a GCS sink return it. */
export function gcpAuditEntry(i: number, methodName = "SetIamPolicy", timestamp?: string) {
  const ts = timestamp ?? `2026-11-01T15:${String(i % 60).padStart(2, "0")}:00.000000Z`;
  const log = LOG_OF[methodName] ?? "activity";
  return {
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      status: {},
      authenticationInfo: { principalEmail: `admin${i}@example.com` },
      requestMetadata: { callerIp: "203.0.113.60", callerSuppliedUserAgent: "google-cloud-sdk" },
      serviceName: "iam.googleapis.com",
      methodName,
      resourceName: `projects/${PROJECT}/serviceAccounts/sa${i}@${PROJECT}.iam.gserviceaccount.com`,
    },
    insertId: `insert${String(i).padStart(6, "0")}`,
    resource: { type: "service_account", labels: { project_id: PROJECT } },
    timestamp: ts,
    severity: "NOTICE",
    logName: `projects/${PROJECT}/logs/cloudaudit.googleapis.com%2F${log}`,
    receiveTimestamp: ts,
  };
}

export interface MockReply {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

/** A wire answered by `handler`; every request is recorded, its JSON body parsed. */
export function mockWire(handler: (req: GcpWireRequest & { json?: Record<string, unknown> }) => MockReply): {
  wire: GcpWire;
  calls: Array<GcpWireRequest & { json?: Record<string, unknown> }>;
} {
  const calls: Array<GcpWireRequest & { json?: Record<string, unknown> }> = [];
  const wire: GcpWire = async (req): Promise<GcpWireResponse> => {
    const json = req.body ? (JSON.parse(req.body) as Record<string, unknown>) : undefined;
    const call = { ...req, ...(json ? { json } : {}) };
    calls.push(call);
    const reply = handler(call);
    const raw = typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body ?? {});
    return {
      status: reply.status ?? 200,
      headers: new Headers(reply.headers ?? {}),
      body: new Uint8Array(Buffer.from(raw)),
    };
  };
  return { wire, calls };
}

/** A Google API error body. */
export function googleError(code: number, status: string, message: string) {
  return { error: { code, status, message } };
}
