// Service-aware method-name aliases for the bundled SigmaHQ GCP audit rules (#2346).
//
// Several SigmaHQ GCP rules spell the method the way another log pipeline does — a permission
// (`.serviceAccounts.disable`), a REST method (`projects.content.reidentify`), a JSON-API method
// (`storage.buckets.insert`) or a Kubernetes object type (`io.k8s.api.batch.v1.CronJob`) — while a
// real Cloud Audit Log record writes the RPC / audit method name (`google.iam.admin.v1.
// DisableServiceAccount`). The rules stay verbatim; the Sigma resolver offers the raw methodName
// AND the alias(es) listed here for that EXACT service + method. Nothing else is rewritten: no
// regex, no prefix stripping, and the event keeps the raw method name for display.
//
// Audit of the 15 bundled rules (rule value → the real Cloud Audit Log method name):
//
// | Rule                              | Rule matches                                   | Real methodName (service)                                             | How it matches    |
// |-----------------------------------|------------------------------------------------|-----------------------------------------------------------------------|-------------------|
// | Access Policy Deleted             | authorizationInfo.permission accesscontextmanager.accessPolicies*.delete + granted + serviceName | google.identity.accesscontextmanager.v1.AccessContextManager.DeleteAccessPolicy (accesscontextmanager) — permission is real | raw (permission)  |
// | Break-glass Container Workload    | io.k8s.core.v1.pods.create + k8s_cluster + activity log + annotation | io.k8s.core.v1.pods.create (k8s.io)                                  | raw               |
// | Storage Buckets Modified/Deleted  | storage.buckets.delete/insert/update/patch     | storage.buckets.delete / .update / .create (storage)                  | raw; create→insert alias; `patch` is logged as update |
// | DLP Re-identifies                 | projects.content.reidentify                    | google.privacy.dlp.v2.DlpService.ReidentifyContent (dlp)              | alias             |
// | DNS Zone Modified/Deleted         | Dns.ManagedZones.Delete/Update/Patch           | dns.managedZones.delete / .update / .patch (dns)                      | raw (case-insensitive) |
// | Firewall Modified/Deleted         | v*.Compute.Firewalls.Delete/Patch/Update/Insert | v1.compute.firewalls.delete / .patch / .update / .insert (compute)   | raw (`beta.` prefix not covered by the rule) |
// | Packet Mirroring                  | v*.Compute.PacketMirrorings.*                  | v1.compute.packetMirrorings.insert / .delete / .patch / .get / .list / .aggregatedList (compute) | raw |
// | K8s Admission Controller          | admissionregistration.k8s.io.v*.{mutating,validating}webhookconfigurations.{create,patch,replace} | io.k8s.admissionregistration.v1.{mutating,validating}webhookconfigurations.{create,patch,update} (k8s.io) | alias (update→replace, the PUT verb) |
// | K8s CronJob                       | io.k8s.api.batch.v*.Job / CronJob (object types) | io.k8s.batch.v1.jobs.create, io.k8s.batch.v1.cronjobs.create, io.k8s.batch.v1beta1.cronjobs.create (k8s.io) | alias (create only, the rule's intent) |
// | K8s RoleBinding                   | io.k8s.authorization.rbac.v*.{cluster,}rolebindings.{create,patch,update,delete} | same (k8s.io)                                       | raw               |
// | K8s Secrets Modified/Deleted      | io.k8s.core.v*.secrets.{create,update,patch,delete} | same (k8s.io)                                                    | raw               |
// | Service Account Disabled/Deleted  | endswith .serviceAccounts.disable / .delete    | google.iam.admin.v1.DisableServiceAccount / DeleteServiceAccount (iam) | alias (permission) |
// | Service Account Modified          | endswith .serviceAccounts.patch/create/update/enable/undelete | google.iam.admin.v1.CreateServiceAccount / UpdateServiceAccount / PatchServiceAccount / EnableServiceAccount / UndeleteServiceAccount (iam) | alias (permission; Patch uses iam.serviceAccounts.update) |
// | SQL Database Modified/Deleted     | cloudsql.instances.create/delete, cloudsql.users.update/delete | same (cloudsql)                                       | raw               |
// | VPN Tunnel Modified/Deleted       | compute.vpnTunnels.insert/delete (no version prefix) | v1.compute.vpnTunnels.insert / .delete, beta.compute.vpnTunnels.* (compute) | alias        |
//
// Every bundled rule is reached by at least one real method name; tests/analysis/sigmaGcpImport.test.ts
// pins that (and that each alias below fires a rule, and that neighbours such as
// DisableServiceAccountKey, GetServiceAccount or DeidentifyContent fire none).

/** serviceName → exact methodName → the alias(es) the bundled rules spell. Keys are exact. */
export const GCP_METHOD_ALIASES: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>> = {
  "iam.googleapis.com": {
    // The IAM permission each call checks (the rule matches `endswith .serviceAccounts.<verb>`).
    "google.iam.admin.v1.DisableServiceAccount": ["iam.serviceAccounts.disable"],
    "google.iam.admin.v1.DeleteServiceAccount": ["iam.serviceAccounts.delete"],
    "google.iam.admin.v1.CreateServiceAccount": ["iam.serviceAccounts.create"],
    "google.iam.admin.v1.UpdateServiceAccount": ["iam.serviceAccounts.update"],
    "google.iam.admin.v1.PatchServiceAccount": ["iam.serviceAccounts.update"],
    "google.iam.admin.v1.EnableServiceAccount": ["iam.serviceAccounts.enable"],
    "google.iam.admin.v1.UndeleteServiceAccount": ["iam.serviceAccounts.undelete"],
  },
  "dlp.googleapis.com": {
    // The REST method the rule names exactly.
    "google.privacy.dlp.v2.DlpService.ReidentifyContent": ["projects.content.reidentify"],
  },
  "storage.googleapis.com": {
    // The JSON API calls bucket creation `buckets.insert`; the audit log calls it create.
    "storage.buckets.create": ["storage.buckets.insert"],
  },
  "compute.googleapis.com": {
    // The rule names the method without the API-version prefix the audit log writes.
    "v1.compute.vpnTunnels.insert": ["compute.vpnTunnels.insert"],
    "v1.compute.vpnTunnels.delete": ["compute.vpnTunnels.delete"],
    "beta.compute.vpnTunnels.insert": ["compute.vpnTunnels.insert"],
    "beta.compute.vpnTunnels.delete": ["compute.vpnTunnels.delete"],
  },
  "k8s.io": {
    // GKE writes the reversed API group; the rule names the forward group and the PUT verb `replace`.
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.create": [
      "admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.create",
    ],
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.patch": [
      "admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.patch",
    ],
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.update": [
      "admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.replace",
    ],
    "io.k8s.admissionregistration.v1.validatingwebhookconfigurations.create": [
      "admissionregistration.k8s.io.v1.validatingwebhookconfigurations.create",
    ],
    "io.k8s.admissionregistration.v1.validatingwebhookconfigurations.patch": [
      "admissionregistration.k8s.io.v1.validatingwebhookconfigurations.patch",
    ],
    "io.k8s.admissionregistration.v1.validatingwebhookconfigurations.update": [
      "admissionregistration.k8s.io.v1.validatingwebhookconfigurations.replace",
    ],
    // The rule names the created object's type; GKE logs the create call.
    "io.k8s.batch.v1.jobs.create": ["io.k8s.api.batch.v1.Job"],
    "io.k8s.batch.v1.cronjobs.create": ["io.k8s.api.batch.v1.CronJob"],
    "io.k8s.batch.v1beta1.cronjobs.create": ["io.k8s.api.batch.v1beta1.CronJob"],
  },
};

/** The aliases for one exact service + method, or none. Lookup is exact (case as logged). */
export function gcpMethodAliases(serviceName: string | undefined, methodName: string | undefined): string[] {
  if (!serviceName || !methodName) return [];
  const byService = Object.hasOwn(GCP_METHOD_ALIASES, serviceName)
    ? GCP_METHOD_ALIASES[serviceName]
    : undefined;
  if (!byService || !Object.hasOwn(byService, methodName)) return [];
  return [...byService[methodName]];
}
