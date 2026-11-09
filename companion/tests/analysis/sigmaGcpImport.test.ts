import { describe, expect, it } from "vitest";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { GCP_METHOD_ALIASES } from "../../src/analysis/sigmaGcpMethodAliases.js";
import { GCP_AUDIT, fieldResolvers, sourceResolver } from "../../src/analysis/sigmaLogSources.js";
import { reparseForRegrade, SIGMA_REGRADE_IMPORTERS } from "../../src/analysis/sigmaRegradeSources.js";

// Import-time Sigma grading of GCP Cloud Audit Logs (#2346): the bundled SigmaHQ
// rules/cloud/gcp/audit folder, read through the real cloud-activity importer. Records are
// synthetic (documentation IPs, example.com principals, fake project ids) but every methodName /
// serviceName is the shape Cloud Audit Logs really write — never the rule's own spelling.

const { set } = loadBundledSigmaRuleSet();
const sigma = createSigmaImportGrader(set).snapshot();
const sigmaMedium = createSigmaImportGrader(set, { minLevel: () => "medium" }).snapshot();

type Row = Record<string, unknown>;

const gcp = (methodName: string, serviceName: string, extra: Row = {}, top: Row = {}): Row => ({
  timestamp: "2026-03-01T10:00:00Z",
  insertId: `id-${methodName}`,
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

const parse = (records: Row[], s = sigma) =>
  parseCloudActivity(JSON.stringify(records), { aggregate: false, sigma: s });

/**
 * One REAL-shaped record per bundled GCP rule: the methodName / serviceName a Cloud Audit Log
 * really carries for the operation the rule is about (Google's audit-logging method names, e.g.
 * `google.iam.admin.v1.DisableServiceAccount`, `v1.compute.vpnTunnels.delete`). Several rules spell
 * the method the way another pipeline does (`.serviceAccounts.disable`); those match through the
 * resolver's exact service + method aliases (sigmaGcpMethodAliases.ts), never by rewriting the rule.
 */
const SAMPLES: Record<string, Row> = {
  "GCP Access Policy Deleted": gcp(
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
  "GCP Break-glass Container Workload Deployed": gcp(
    "io.k8s.core.v1.pods.create",
    "k8s.io",
    { request: { metadata: { annotations: { "alpha.image-policy.k8s.io/break-glass": "true" } } } },
    { resource: { type: "k8s_cluster", labels: { project_id: "p1" } } },
  ),
  "Google Cloud Storage Buckets Modified or Deleted": gcp("storage.buckets.create", "storage.googleapis.com"),
  "Google Cloud Re-identifies Sensitive Information": gcp(
    "google.privacy.dlp.v2.DlpService.ReidentifyContent",
    "dlp.googleapis.com",
  ),
  "Google Cloud DNS Zone Modified or Deleted": gcp("dns.managedZones.delete", "dns.googleapis.com"),
  "Google Cloud Firewall Modified or Deleted": gcp("v1.compute.firewalls.delete", "compute.googleapis.com"),
  "Google Full Network Traffic Packet Capture": gcp(
    "v1.compute.packetMirrorings.insert",
    "compute.googleapis.com",
  ),
  "Google Cloud Kubernetes Admission Controller": gcp(
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.create",
    "k8s.io",
  ),
  "Google Cloud Kubernetes CronJob": gcp("io.k8s.batch.v1.cronjobs.create", "k8s.io"),
  "Google Cloud Kubernetes RoleBinding": gcp(
    "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
    "k8s.io",
  ),
  "Google Cloud Kubernetes Secrets Modified or Deleted": gcp("io.k8s.core.v1.secrets.delete", "k8s.io"),
  "Google Cloud Service Account Disabled or Deleted": gcp(
    "google.iam.admin.v1.DisableServiceAccount",
    "iam.googleapis.com",
  ),
  "Google Cloud Service Account Modified": gcp(
    "google.iam.admin.v1.PatchServiceAccount",
    "iam.googleapis.com",
  ),
  "Google Cloud SQL Database Modified or Deleted": gcp(
    "cloudsql.instances.delete",
    "cloudsql.googleapis.com",
  ),
  "Google Cloud VPN Tunnel Modified or Deleted": gcp(
    "v1.compute.vpnTunnels.delete",
    "compute.googleapis.com",
  ),
};

/** Bundled rules no real Cloud Audit Log method name reaches, even through an alias. Pinned. */
const MATCHES_NO_REAL_METHOD: string[] = [];

/** More real method names, each with the one rule it must fire (aliases beyond the samples). */
const REAL_POSITIVES: Array<[string, string, string]> = [
  [
    "google.iam.admin.v1.DeleteServiceAccount",
    "iam.googleapis.com",
    "Google Cloud Service Account Disabled or Deleted",
  ],
  ["google.iam.admin.v1.CreateServiceAccount", "iam.googleapis.com", "Google Cloud Service Account Modified"],
  ["google.iam.admin.v1.UpdateServiceAccount", "iam.googleapis.com", "Google Cloud Service Account Modified"],
  ["google.iam.admin.v1.EnableServiceAccount", "iam.googleapis.com", "Google Cloud Service Account Modified"],
  [
    "google.iam.admin.v1.UndeleteServiceAccount",
    "iam.googleapis.com",
    "Google Cloud Service Account Modified",
  ],
  ["storage.buckets.delete", "storage.googleapis.com", "Google Cloud Storage Buckets Modified or Deleted"],
  ["storage.buckets.update", "storage.googleapis.com", "Google Cloud Storage Buckets Modified or Deleted"],
  ["v1.compute.vpnTunnels.insert", "compute.googleapis.com", "Google Cloud VPN Tunnel Modified or Deleted"],
  ["beta.compute.vpnTunnels.delete", "compute.googleapis.com", "Google Cloud VPN Tunnel Modified or Deleted"],
  ["io.k8s.batch.v1.jobs.create", "k8s.io", "Google Cloud Kubernetes CronJob"],
  ["io.k8s.batch.v1beta1.cronjobs.create", "k8s.io", "Google Cloud Kubernetes CronJob"],
  [
    "io.k8s.admissionregistration.v1.validatingwebhookconfigurations.update",
    "k8s.io",
    "Google Cloud Kubernetes Admission Controller",
  ],
  [
    "io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.patch",
    "k8s.io",
    "Google Cloud Kubernetes Admission Controller",
  ],
  ["dns.managedZones.patch", "dns.googleapis.com", "Google Cloud DNS Zone Modified or Deleted"],
  ["cloudsql.users.update", "cloudsql.googleapis.com", "Google Cloud SQL Database Modified or Deleted"],
];

/** Real neighbours of an aliased method that must match NO bundled GCP rule. */
const REAL_NEGATIVES: Array<[string, string]> = [
  ["google.iam.admin.v1.GetServiceAccount", "iam.googleapis.com"],
  ["google.iam.admin.v1.ListServiceAccounts", "iam.googleapis.com"],
  ["google.iam.admin.v1.DisableServiceAccountKey", "iam.googleapis.com"],
  ["google.iam.admin.v1.DeleteServiceAccountKey", "iam.googleapis.com"],
  ["google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com"],
  ["google.privacy.dlp.v2.DlpService.DeidentifyContent", "dlp.googleapis.com"],
  ["google.privacy.dlp.v2.DlpService.InspectContent", "dlp.googleapis.com"],
  ["storage.buckets.get", "storage.googleapis.com"],
  ["storage.objects.create", "storage.googleapis.com"],
  ["v1.compute.vpnTunnels.get", "compute.googleapis.com"],
  ["v1.compute.vpnTunnels.list", "compute.googleapis.com"],
  ["io.k8s.batch.v1.cronjobs.list", "k8s.io"],
  ["io.k8s.batch.v1.cronjobs.get", "k8s.io"],
  ["io.k8s.admissionregistration.v1.mutatingwebhookconfigurations.get", "k8s.io"],
  ["io.k8s.admissionregistration.v1.validatingwebhookconfigurations.delete", "k8s.io"],
  // The alias is service-aware: the same method under another service gets none.
  ["google.iam.admin.v1.DisableServiceAccount", "storage.googleapis.com"],
  ["storage.buckets.create", "compute.googleapis.com"],
  ["v1.compute.vpnTunnels.delete", "storage.googleapis.com"],
];

const gcpInventory = set.inventory.filter((e) => e.source === GCP_AUDIT.id);
const loaded = gcpInventory.filter((e) => e.outcome === "loaded");

describe("bundled SigmaHQ GCP audit rules (#2346)", () => {
  it("loads every rule of rules/cloud/gcp/audit — none refused, none disabled", () => {
    expect(gcpInventory.every((e) => e.path.startsWith("rules/cloud/gcp/audit/"))).toBe(true);
    expect(gcpInventory).toHaveLength(15);
    expect(gcpInventory.filter((e) => e.outcome !== "loaded")).toEqual([]);
  });

  it("has a sample for every loaded rule, and no sample for a rule that is not loaded", () => {
    expect(Object.keys(SAMPLES).sort()).toEqual(loaded.map((e) => e.title).sort());
  });

  // Coverage: every enabled GCP rule fires through the real importer on its sample.
  for (const [title, record] of Object.entries(SAMPLES)) {
    it(`fires through the importer: ${title}`, () => {
      const r = parse([record]);
      expect(r.events).toHaveLength(1);
      expect(r.events[0].message).toContain(`Sigma rule: ${title} [`);
      expect(r.sigmaRowsMatched).toBe(1);
    });
  }

  it("pins the bundled rules no real method name reaches (printed count)", () => {
    const reached = new Set(
      [...Object.values(SAMPLES), ...REAL_POSITIVES.map(([m, svc]) => gcp(m, svc))].flatMap((rec) =>
        loaded
          .map((e) => e.title)
          .filter((t) => (parse([rec]).events[0].message ?? "").includes(`Sigma rule: ${t} [`)),
      ),
    );
    const none = loaded.map((e) => e.title).filter((t) => !reached.has(t));
    console.log(`bundled GCP rules that match no real method name: ${none.length}`);
    expect(none.sort()).toEqual([...MATCHES_NO_REAL_METHOD].sort());
  });

  for (const [method, service, title] of REAL_POSITIVES) {
    it(`fires on the real method ${method} (${service}): ${title}`, () => {
      const r = parse([gcp(method, service)]);
      expect(r.events[0].message).toContain(`Sigma rule: ${title} [`);
      expect(r.sigmaRowsMatched).toBe(1);
    });
  }

  for (const [method, service] of REAL_NEGATIVES) {
    it(`matches no GCP rule on the neighbour ${method} (${service})`, () => {
      const r = parse([gcp(method, service)]);
      expect(r.sigmaRowsMatched).toBe(0);
      expect(r.events[0].message ?? "").not.toContain("Sigma rule:");
    });
  }

  it("EnableServiceAccount is a modification, never the disable rule", () => {
    const msg = parse([gcp("google.iam.admin.v1.EnableServiceAccount", "iam.googleapis.com")]).events[0]
      .message;
    expect(msg).toContain("Sigma rule: Google Cloud Service Account Modified [");
    expect(msg).not.toContain("Disabled or Deleted");
  });

  it("offers no alias when the record names no service", () => {
    const rec = gcp("google.iam.admin.v1.DisableServiceAccount", "");
    expect(parse([rec]).sigmaRowsMatched).toBe(0);
  });

  it("resolves the method name to the raw value plus its alias, for both rule spellings", () => {
    const resolve = sourceResolver(GCP_AUDIT);
    const rec = gcp("google.iam.admin.v1.DisableServiceAccount", "iam.googleapis.com");
    for (const field of ["gcp.audit.method_name", "data.protoPayload.methodName"]) {
      expect(resolve(rec, field).values).toEqual([
        "google.iam.admin.v1.DisableServiceAccount",
        "iam.serviceAccounts.disable",
      ]);
    }
    const plain = gcp("google.iam.admin.v1.GetServiceAccount", "iam.googleapis.com");
    expect(resolve(plain, "gcp.audit.method_name").values).toEqual(["google.iam.admin.v1.GetServiceAccount"]);
  });

  it("keeps the raw method name in the event; the alias is used only for matching", () => {
    const r = parse([SAMPLES["Google Cloud Service Account Disabled or Deleted"]]);
    // #2486: the title shows the method without its versioned package; the record keeps it whole.
    expect(r.events[0].description).toContain("GCP DisableServiceAccount (iam)");
    expect(r.events[0].canonical?.event?.action).toBe("google.iam.admin.v1.DisableServiceAccount");
    expect(r.events[0].description).not.toContain("serviceAccounts.disable");
  });

  it("every alias in the table makes some bundled rule fire on its exact service + method", () => {
    const dead = Object.entries(GCP_METHOD_ALIASES).flatMap(([service, methods]) =>
      Object.keys(methods).filter((m) => parse([gcp(m, service)]).sigmaRowsMatched !== 1),
    );
    expect(dead).toEqual([]);
  });

  it("tags only at the default minimum level (every GCP rule is medium), with the DRL credit", () => {
    const rec = SAMPLES["Google Cloud SQL Database Modified or Deleted"];
    const without = parseCloudActivity(JSON.stringify([rec]), { aggregate: false });
    const r = parse([rec]);
    expect(r.events[0].severity).toBe(without.events[0].severity);
    // #2486: a rule that did not grade leaves the description as the importer wrote it.
    expect(r.events[0].description).toBe(without.events[0].description);
    expect(r.events[0].message).toContain("Sigma rule: Google Cloud SQL Database Modified or Deleted [");
    expect(r.events[0].message).toMatch(
      /author Austin Songer @austinsonger, SigmaHQ r2026-07-01, https:\/\/github\.com\/SigmaHQ\/sigma\/blob\/552f3fee/,
    );
    expect(r.events[0].canonical?.producer.ruleVersions).toContain(sigma?.token);
  });

  it("raises a Low row to Medium when the minimum level is medium", () => {
    const rec = gcp("v1.compute.vpnTunnels.insert", "compute.googleapis.com");
    expect(parseCloudActivity(JSON.stringify([rec]), { aggregate: false }).events[0].severity).toBe("Low");
    const r = parse([rec], sigmaMedium);
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toMatch(/^Sigma: Google Cloud VPN Tunnel Modified or Deleted - GCP /);
  });

  it("never lowers the importer's own grade", () => {
    const rec = gcp("v1.compute.firewalls.delete", "compute.googleapis.com");
    expect(parse([rec], sigmaMedium).events[0].severity).toBe("Medium");
    const key = gcp("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com");
    expect(parse([key], sigmaMedium).events[0].severity).toBe("High");
  });

  it("does not match the break-glass rule without the annotation, or outside a k8s_cluster resource", () => {
    const plain = gcp("io.k8s.core.v1.pods.create", "k8s.io", {}, { resource: { type: "k8s_cluster" } });
    expect(parse([plain]).sigmaRowsMatched).toBe(0);
    const wrongType = {
      ...SAMPLES["GCP Break-glass Container Workload Deployed"],
      resource: { type: "gce_instance" },
    };
    expect(parse([wrongType]).sigmaRowsMatched).toBe(0);
  });

  it("does not match the access-policy rule when the permission was not granted", () => {
    const denied = gcp(
      "google.identity.accesscontextmanager.v1.AccessContextManager.DeleteAccessPolicy",
      "accesscontextmanager.googleapis.com",
      {
        authorizationInfo: [
          {
            resource: "accessPolicies/1",
            permission: "accesscontextmanager.accessPolicies.delete",
            granted: false,
          },
        ],
      },
    );
    expect(parse([denied]).sigmaRowsMatched).toBe(0);
  });

  it("reads the log name as written, as its log id, and URL-decoded", () => {
    const r = fieldResolvers(GCP_AUDIT, "data.protoPayload.logName");
    expect(Array.isArray(r)).toBe(true);
    const resolve = (r as Array<(rec: Row) => { values: readonly (string | null)[] }>)[0];
    expect(resolve({ logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity" }).values).toEqual([
      "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
      "cloudaudit.googleapis.com%2Factivity",
      "cloudaudit.googleapis.com/activity",
    ]);
  });

  it("reads the Elastic integration names from a jsonPayload record too", () => {
    const rec = gcp("storage.buckets.delete", "storage.googleapis.com");
    const asJson = { ...rec, jsonPayload: rec.protoPayload, protoPayload: undefined };
    expect(parse([asJson]).sigmaRowsMatched).toBe(1);
  });

  it("puts the verdict on the first row of a record that became several rows", () => {
    const rec = gcp("SetIamPolicy", "cloudresourcemanager.googleapis.com", {
      authorizationInfo: [{ permission: "accesscontextmanager.accessPolicies.delete", granted: true }],
      serviceData: {
        policyDelta: {
          bindingDeltas: [
            { action: "ADD", role: "roles/viewer", member: "user:bob@example.com" },
            { action: "ADD", role: "roles/browser", member: "user:bob@example.com" },
          ],
        },
      },
    });
    rec.protoPayload = { ...(rec.protoPayload as Row), serviceName: "accesscontextmanager.googleapis.com" };
    const r = parse([rec]);
    expect(r.events).toHaveLength(2);
    expect(r.events[0].message).toContain("Sigma rule: GCP Access Policy Deleted");
    expect(r.events[0].message).toContain("it is shown on the first");
    expect(r.events[1].message ?? "").not.toContain("Sigma rule:");
  });

  it("never grades an Azure Activity record in the same upload", () => {
    const azure = {
      operationName: { value: "Microsoft.Storage/storageAccounts/delete" },
      caller: "alice@example.com",
      resourceId: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
      status: { value: "Succeeded" },
      eventTimestamp: "2026-03-01T10:00:00Z",
    };
    const r = parse([azure, SAMPLES["Google Cloud Storage Buckets Modified or Deleted"]]);
    expect(r.format).toBe("mixed");
    const az = r.events.find((e) => e.description.startsWith("Azure "));
    expect(az?.message ?? "").not.toContain("Sigma");
    expect(r.sigmaRowsMatched).toBe(1);
  });

  it("is the pre-#2346 output exactly when no grader is given", () => {
    const rec = gcp("storage.buckets.delete", "storage.googleapis.com");
    const r = parseCloudActivity(JSON.stringify([rec]), { aggregate: false });
    expect(r.events[0].description).toMatch(/^GCP storage\.buckets\.delete \(storage\)/);
    expect(r.sigmaRowsMatched).toBe(0);
  });
});

describe("Re-grade this case reads GCP stored files (#2346)", () => {
  it("lists the GCP importer and re-parses its file with the snapshot", () => {
    expect(SIGMA_REGRADE_IMPORTERS.has("gcp-audit")).toBe(true);
    const text = JSON.stringify([gcp("v1.compute.vpnTunnels.insert", "compute.googleapis.com")]);
    const rows = reparseForRegrade("gcp-audit", text, sigmaMedium!);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("Medium");
    expect(rows[0].canonical?.producer.importer).toBe("gcp-audit");
    expect(rows[0].canonical?.producer.ruleVersions).toContain(sigmaMedium?.token);
  });
});
