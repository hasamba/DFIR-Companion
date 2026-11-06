// GCP audit-log samples for the detection-overlap check (#2348), copied from tagsYamlCloudGaps and
// tagsYamlRemainingSources (Timesketch GCS). The originals stay in their tests. No bundled Sigma
// rule reads GCP audit logs, so these check the importer against the tagger only.
import { sample, type DetectionSample } from "./types.js";

const GAPS = "tagsYamlCloudGaps";
const TS = "tagsYamlRemainingSources (Timesketch GCS)";

const setIam = (role: string, member: string, action = "ADD") => ({
  timestamp: "2026-01-01T00:00:00Z",
  insertId: "1",
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "project", labels: { project_id: "p1" } },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName: "SetIamPolicy",
    serviceName: "cloudresourcemanager.googleapis.com",
    resourceName: "projects/p1",
    authenticationInfo: { principalEmail: "bob@example.com" },
    requestMetadata: { callerIp: "203.0.113.9" },
    serviceData: { policyDelta: { bindingDeltas: [{ action, role, member }] } },
  },
});

const storage = (methodName: string, serviceData?: unknown) => ({
  insertId: "1",
  timestamp: "2023-06-01T10:00:00Z",
  protoPayload: {
    methodName,
    serviceName: "storage.googleapis.com",
    authenticationInfo: { principalEmail: "a@example.com" },
    resourceName: "projects/p/buckets/b",
    ...(serviceData ? { serviceData } : {}),
  },
});
const delta = (action: string, member: string) => ({
  policyDelta: { bindingDeltas: [{ action, role: "roles/storage.objectViewer", member }] },
});

export const GCP_SAMPLES: readonly DetectionSample[] = [
  sample("gcp", "gcp.SetIamPolicy.ownerAdded", GAPS, setIam("roles/owner", "user:carol@example.com")),
  sample(
    "gcp",
    "gcp.SetIamPolicy.ownerRemoved",
    GAPS,
    setIam("roles/owner", "user:carol@example.com", "REMOVE"),
  ),
  sample("gcp", "gcp.SetIamPolicy.externalMember", GAPS, setIam("roles/viewer", "user:mallory@example.net")),
  sample("gcp", "gcp.SetIamPolicy.allUsers", GAPS, setIam("roles/viewer", "allUsers")),
  sample("gcp", "gcp.storage.buckets.create", TS, storage("storage.buckets.create")),
  sample(
    "gcp",
    "gcp.storage.setIamPermissions.add",
    TS,
    storage("storage.setIamPermissions", delta("ADD", "user:x@example.net")),
  ),
  sample(
    "gcp",
    "gcp.storage.setIamPermissions.remove",
    TS,
    storage("storage.setIamPermissions", delta("REMOVE", "user:x@example.net")),
  ),
  sample(
    "gcp",
    "gcp.storage.setIamPermissions.world",
    TS,
    storage("storage.setIamPermissions", delta("ADD", "allUsers")),
  ),
];
