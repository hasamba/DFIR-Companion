// GCP audit-log samples for the detection-overlap check (#2348), copied from tagsYamlCloudGaps and
// tagsYamlRemainingSources (Timesketch GCS), plus one sample per graded gcp_* tagger rule (#2346,
// copied from tagsYamlGcpPorted). The originals stay in their tests. The bundled SigmaHQ GCP audit
// rules (#2346) are checked with the real-shaped SIGMA_REAL_SAMPLES below, never built samples.
import { sample, type DetectionSample } from "./types.js";

/** A neutral GCP read call for the built Sigma samples: no importer table entry, no tagger rule. */
export const gcpBase = (): Record<string, unknown> => ({
  timestamp: "2026-01-01T00:00:00Z",
  insertId: "sigma-base",
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "project", labels: { project_id: "p1" } },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName: "google.cloud.resourcemanager.v3.Projects.GetProject",
    serviceName: "cloudresourcemanager.googleapis.com",
    resourceName: "projects/p1",
    authenticationInfo: { principalEmail: "bob@example.com" },
    requestMetadata: { callerIp: "203.0.113.9" },
  },
});

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

// #2346 — one sample per graded gcp_* tagger rule (copied from tagsYamlGcpPorted), and the bundled
// Sigma break-glass rule, whose keyword selection the Sigma sample builder cannot build.
const PORTED = "tagsYamlGcpPorted";
const call = (methodName: string, serviceName: string, extra: Record<string, unknown> = {}, top = {}) => ({
  timestamp: "2026-03-01T10:00:00Z",
  insertId: `ported-${methodName}`,
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "project", labels: { project_id: "p1" } },
  ...top,
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName,
    serviceName,
    resourceName: "projects/p1/things/t1",
    authenticationInfo: { principalEmail: "alice@example.com" },
    requestMetadata: { callerIp: "198.51.100.7" },
    ...extra,
  },
});
const ported = (id: string, methodName: string, serviceName: string, extra?: Record<string, unknown>) =>
  sample("gcp", id, PORTED, call(methodName, serviceName, extra));

const PORTED_SAMPLES: readonly DetectionSample[] = [
  ported("gcp.UpdateRole", "google.iam.admin.v1.UpdateRole", "iam.googleapis.com"),
  ported(
    "gcp.OrgPolicy.DeletePolicy",
    "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy",
    "orgpolicy.googleapis.com",
  ),
  ported("gcp.ClearOrgPolicy", "ClearOrgPolicy", "cloudresourcemanager.googleapis.com"),
  ported(
    "gcp.InsertProjectOwnershipInvite",
    "InsertProjectOwnershipInvite",
    "cloudresourcemanager.googleapis.com",
  ),
  ported("gcp.storage.hmacKeys.create", "storage.hmacKeys.create", "storage.googleapis.com"),
  ported("gcp.ApiKeys.CreateKey", "google.api.apikeys.v2.ApiKeys.CreateKey", "apikeys.googleapis.com"),
  ported(
    "gcp.CreateWorkloadIdentityPoolProvider",
    "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
    "iam.googleapis.com",
  ),
  ported(
    "gcp.CreateWorkforcePool",
    "google.iam.admin.v1.WorkforcePools.CreateWorkforcePool",
    "iam.googleapis.com",
  ),
  ported(
    "gcp.inboundSsoProfileCreated",
    "google.admin.AdminService.inboundSsoProfileCreated",
    "admin.googleapis.com",
  ),
  ported(
    "gcp.ConfigServiceV2.DeleteBucket",
    "google.logging.v2.ConfigServiceV2.DeleteBucket",
    "logging.googleapis.com",
  ),
  ported(
    "gcp.DeleteVpcFlowLogsConfig",
    "google.cloud.networkmanagement.v1.VpcFlowLogsService.DeleteVpcFlowLogsConfig",
    "networkmanagement.googleapis.com",
  ),
  ported("gcp.storage.objects.create.ransomNote", "storage.objects.create", "storage.googleapis.com", {
    resourceName: "projects/_/buckets/b1/objects/HOW_TO_DECRYPT_YOUR_FILES.txt",
  }),
  sample(
    "gcp",
    "gcp.k8s.pods.create.breakGlass",
    "sigmaGcpImport (break-glass keyword rule)",
    call(
      "io.k8s.core.v1.pods.create",
      "k8s.io",
      { request: { metadata: { annotations: { "alpha.image-policy.k8s.io/break-glass": "true" } } } },
      { resource: { type: "k8s_cluster", labels: { project_id: "p1" } } },
    ),
  ),
];

// #2346 — one REAL-shaped record per other bundled SigmaHQ GCP rule (copied from sigmaGcpImport's
// SAMPLES): the methodName / serviceName a Cloud Audit Log really writes, so the overlap check sees
// what a real import grades. These replace the rule-shaped samples the builder makes for other
// sources (sigmaBuilt.ts does not build GCP samples); several match through the method aliases.
const SIGMA = "sigmaGcpImport (real method names)";
const real = (id: string, methodName: string, serviceName: string, extra?: Record<string, unknown>) =>
  sample("gcp", `gcp.sigma.${id}`, SIGMA, call(methodName, serviceName, extra));

const SIGMA_REAL_SAMPLES: readonly DetectionSample[] = [
  real(
    "DeleteAccessPolicy",
    "google.identity.accesscontextmanager.v1.AccessContextManager.DeleteAccessPolicy",
    "accesscontextmanager.googleapis.com",
    {
      authorizationInfo: [
        {
          resource: "accessPolicies/1",
          permission: "accesscontextmanager.accessPolicies.delete",
          granted: true,
        },
      ],
    },
  ),
  real("storage.buckets.delete", "storage.buckets.delete", "storage.googleapis.com"),
  real("ReidentifyContent", "google.privacy.dlp.v2.DlpService.ReidentifyContent", "dlp.googleapis.com"),
  real("dns.managedZones.delete", "dns.managedZones.delete", "dns.googleapis.com"),
  real("compute.firewalls.delete", "v1.compute.firewalls.delete", "compute.googleapis.com"),
  real("compute.packetMirrorings.insert", "v1.compute.packetMirrorings.insert", "compute.googleapis.com"),
  real(
    "k8s.mutatingwebhookconfigurations.create",
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.create",
    "k8s.io",
  ),
  real("k8s.cronjobs.create", "io.k8s.batch.v1.cronjobs.create", "k8s.io"),
  real("k8s.clusterrolebindings.create", "io.k8s.authorization.rbac.v1.clusterrolebindings.create", "k8s.io"),
  real("k8s.secrets.delete", "io.k8s.core.v1.secrets.delete", "k8s.io"),
  real("DisableServiceAccount", "google.iam.admin.v1.DisableServiceAccount", "iam.googleapis.com"),
  real("PatchServiceAccount", "google.iam.admin.v1.PatchServiceAccount", "iam.googleapis.com"),
  real("cloudsql.instances.delete", "cloudsql.instances.delete", "cloudsql.googleapis.com"),
  real("compute.vpnTunnels.delete", "v1.compute.vpnTunnels.delete", "compute.googleapis.com"),
];

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
  ...PORTED_SAMPLES,
  ...SIGMA_REAL_SAMPLES,
];
