// #2346 — the GCP rules ported from Panther / Sentinel / Chronicle (with the Rhino privilege-
// escalation list as reference) in the SHIPPED tags.yaml, each run over the REAL cloud-activity
// importer's rendered row, graded by the bundled Sigma rules at default settings, and then by the
// real tagger. Per graded rule: a synthetic Cloud Audit Log record that fires it (and that the
// importer and Sigma alone leave at the importer's floor, so the rule is what grades it), plus benign
// look-alikes that must not: a Google-managed service agent, a denied call, a neighbouring method.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";
import { readRecordedCommit, UPSTREAM_GROUPS } from "../../scripts/upstreamRulesDiff.mjs";

const YAML = readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8");
const RULES = compileText(YAML);
const SIGMA = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

type Row = Record<string, unknown>;
const USER = "alice@example.com";
const AGENT = "service-123456789012@gcp-sa-cloudbuild.iam.gserviceaccount.com";
const CLOUDSERVICES = "123456789012@cloudservices.gserviceaccount.com";

const rec = (methodName: string, serviceName: string, principal = USER, extra: Row = {}): Row => ({
  timestamp: "2026-03-01T10:00:00Z",
  insertId: `i-${methodName}-${principal}`,
  logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
  resource: { type: "project", labels: { project_id: "p1" } },
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName,
    serviceName,
    resourceName: "projects/p1/things/t1",
    authenticationInfo: { principalEmail: principal },
    requestMetadata: { callerIp: "198.51.100.7" },
    ...extra,
  },
});
const denied = (r: Row): Row => ({
  ...r,
  protoPayload: { ...(r.protoPayload as Row), status: { code: 7, message: "PERMISSION_DENIED" } },
});

function grade(r: Row, sigma = true) {
  const parsed = parseCloudActivity(JSON.stringify([r]), {
    aggregate: false,
    sigma: sigma ? SIGMA : undefined,
  });
  expect(parsed.events.length).toBeGreaterThan(0);
  const row = parsed.events[0];
  const event = {
    ...row,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
  } as unknown as ForensicEvent;
  const hit = runTagger([event], RULES).perEvent[0];
  const ids = hit?.ruleIds ?? [];
  const graded = ids
    .map((id) => RULES.rules.find((x) => x.id === id)?.severity)
    .filter((s): s is Severity => !!s && s !== "Info");
  const tagger = graded.reduce<Severity | undefined>((a, s) => (!a || RANK[s] > RANK[a] ? s : a), undefined);
  return { row, ids, importer: row.severity, tagger };
}

interface Case {
  rule: string;
  severity: Severity;
  fires: Row[];
  quiet: Row[];
}

const CASES: Case[] = [
  {
    rule: "gcp_iam_custom_role_updated",
    severity: "Medium",
    fires: [rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com")],
    quiet: [
      rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com", AGENT),
      denied(rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com")),
      rec("google.iam.admin.v1.CreateRole", "iam.googleapis.com"),
      rec("google.iam.admin.v1.GetRole", "iam.googleapis.com"),
    ],
  },
  {
    rule: "gcp_org_policy_removed",
    severity: "Medium",
    fires: [
      rec("google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy", "orgpolicy.googleapis.com"),
      rec("ClearOrgPolicy", "cloudresourcemanager.googleapis.com"),
    ],
    quiet: [
      rec("google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy", "orgpolicy.googleapis.com", CLOUDSERVICES),
      denied(rec("ClearOrgPolicy", "cloudresourcemanager.googleapis.com")),
      rec("google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy", "orgpolicy.googleapis.com"),
      rec("SetOrgPolicy", "cloudresourcemanager.googleapis.com"),
    ],
  },
  {
    rule: "gcp_project_ownership_invite",
    severity: "Medium",
    fires: [rec("InsertProjectOwnershipInvite", "cloudresourcemanager.googleapis.com")],
    quiet: [
      denied(rec("InsertProjectOwnershipInvite", "cloudresourcemanager.googleapis.com")),
      rec("InsertProjectOwnershipInvite", "cloudresourcemanager.googleapis.com", AGENT),
      rec("GetProject", "cloudresourcemanager.googleapis.com"),
    ],
  },
  {
    rule: "gcp_hmac_key_created",
    severity: "Medium",
    fires: [rec("storage.hmacKeys.create", "storage.googleapis.com")],
    quiet: [
      rec("storage.hmacKeys.create", "storage.googleapis.com", AGENT),
      denied(rec("storage.hmacKeys.create", "storage.googleapis.com")),
      rec("storage.hmacKeys.list", "storage.googleapis.com"),
    ],
  },
  {
    rule: "gcp_api_key_created",
    severity: "Medium",
    fires: [rec("google.api.apikeys.v2.ApiKeys.CreateKey", "apikeys.googleapis.com")],
    quiet: [
      rec("google.api.apikeys.v2.ApiKeys.CreateKey", "apikeys.googleapis.com", CLOUDSERVICES),
      denied(rec("google.api.apikeys.v2.ApiKeys.CreateKey", "apikeys.googleapis.com")),
      rec("google.api.apikeys.v2.ApiKeys.ListKeys", "apikeys.googleapis.com"),
    ],
  },
  {
    rule: "gcp_identity_federation_changed",
    severity: "Medium",
    fires: [
      rec("google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider", "iam.googleapis.com"),
      rec("google.iam.v1.WorkloadIdentityPools.UpdateWorkloadIdentityPoolProvider", "iam.googleapis.com"),
      rec("google.iam.admin.v1.WorkforcePools.CreateWorkforcePool", "iam.googleapis.com"),
      rec("google.iam.admin.v1.WorkforcePools.UpdateWorkforcePool", "iam.googleapis.com"),
    ],
    quiet: [
      rec(
        "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
        "iam.googleapis.com",
        AGENT,
      ),
      denied(rec("google.iam.admin.v1.WorkforcePools.CreateWorkforcePool", "iam.googleapis.com")),
      rec("google.iam.v1.WorkloadIdentityPools.ListWorkloadIdentityPoolProviders", "iam.googleapis.com"),
    ],
  },
  {
    rule: "gcp_inbound_sso_profile_changed",
    severity: "Medium",
    fires: [
      rec("google.admin.AdminService.inboundSsoProfileCreated", "admin.googleapis.com"),
      rec("google.admin.AdminService.inboundSsoProfileUpdated", "admin.googleapis.com"),
    ],
    quiet: [
      denied(rec("google.admin.AdminService.inboundSsoProfileCreated", "admin.googleapis.com")),
      rec("google.admin.AdminService.inboundSsoProfileDeleted", "admin.googleapis.com"),
    ],
  },
  {
    rule: "gcp_log_bucket_deleted",
    severity: "Medium",
    fires: [rec("google.logging.v2.ConfigServiceV2.DeleteBucket", "logging.googleapis.com")],
    quiet: [
      rec("google.logging.v2.ConfigServiceV2.DeleteBucket", "logging.googleapis.com", AGENT),
      denied(rec("google.logging.v2.ConfigServiceV2.DeleteBucket", "logging.googleapis.com")),
      rec("google.logging.v2.ConfigServiceV2.CreateBucket", "logging.googleapis.com"),
      rec("storage.buckets.delete", "storage.googleapis.com"),
    ],
  },
  {
    rule: "gcp_vpc_flow_logs_config_deleted",
    severity: "Medium",
    fires: [
      rec(
        "google.cloud.networkmanagement.v1.VpcFlowLogsService.DeleteVpcFlowLogsConfig",
        "networkmanagement.googleapis.com",
      ),
    ],
    quiet: [
      rec(
        "google.cloud.networkmanagement.v1.VpcFlowLogsService.DeleteVpcFlowLogsConfig",
        "networkmanagement.googleapis.com",
        CLOUDSERVICES,
      ),
      denied(
        rec(
          "google.cloud.networkmanagement.v1.VpcFlowLogsService.DeleteVpcFlowLogsConfig",
          "networkmanagement.googleapis.com",
        ),
      ),
      rec(
        "google.cloud.networkmanagement.v1.VpcFlowLogsService.UpdateVpcFlowLogsConfig",
        "networkmanagement.googleapis.com",
      ),
    ],
  },
  {
    rule: "gcp_gcs_ransom_note_uploaded",
    severity: "High",
    fires: [
      rec("storage.objects.create", "storage.googleapis.com", USER, {
        resourceName: "projects/_/buckets/b1/objects/HOW_TO_DECRYPT_YOUR_FILES.txt",
      }),
      rec("storage.objects.create", "storage.googleapis.com", USER, {
        resourceName: "projects/_/buckets/b1/objects/dir/RANSOM_NOTE.html",
      }),
    ],
    quiet: [
      rec("storage.objects.create", "storage.googleapis.com", USER, {
        resourceName: "projects/_/buckets/b1/objects/notes/payment-report-2026.csv",
      }),
      rec("storage.objects.create", "storage.googleapis.com", USER, {
        resourceName: "projects/_/buckets/b1/objects/docs/how_to_restore_backups.md",
      }),
      denied(
        rec("storage.objects.create", "storage.googleapis.com", USER, {
          resourceName: "projects/_/buckets/b1/objects/RANSOM_NOTE.txt",
        }),
      ),
      rec("storage.objects.get", "storage.googleapis.com", USER, {
        resourceName: "projects/_/buckets/b1/objects/RANSOM_NOTE.txt",
      }),
    ],
  },
];

const GRADED = RULES.rules.filter((r) => r.id.startsWith("gcp_") && r.severity && r.severity !== "Info");

describe("ported GCP rules (#2346) — the rendered head they read", () => {
  it("pins the GCP head the rules key on", () => {
    const { row } = grade(rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com"), false);
    expect(row.description).toMatch(
      /^GCP google\.iam\.admin\.v1\.UpdateRole \(iam\) by alice@example\.com from 198\.51\.100\.7 on things\/t1/,
    );
    const agent = grade(rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com", AGENT), false).row;
    expect(agent.description).toContain(` by ${AGENT} `);
    expect(
      grade(denied(rec("google.iam.admin.v1.UpdateRole", "iam.googleapis.com")), false).row.description,
    ).toContain("[DENIED");
  });

  it("has a test case for every graded gcp_* rule", () => {
    expect(GRADED.map((r) => r.id).sort()).toEqual(CASES.map((c) => c.rule).sort());
  });
});

describe("ported GCP rules (#2346) — graded rules", () => {
  for (const c of CASES) {
    describe(c.rule, () => {
      c.fires.forEach((r, i) => {
        it(`fires and grades ${c.severity} (positive ${i + 1})`, () => {
          const g = grade(r);
          expect(g.ids).toContain(c.rule);
          expect(g.tagger).toBe(c.severity);
          // The importer + Sigma alone leave it at the importer's floor: the rule is what grades it.
          expect(RANK[g.importer]).toBeLessThan(RANK[c.severity]);
        });
      });
      c.quiet.forEach((r, i) => {
        it(`stays quiet on a look-alike (${i + 1})`, () => {
          expect(grade(r).ids).not.toContain(c.rule);
        });
      });
    });
  }
});

describe("ported GCP rules (#2346) — tag-only rules", () => {
  const tagOnly: Array<[string, Row]> = [
    [
      "gcp_privilege_escalation_methods",
      rec("google.devtools.cloudbuild.v1.CloudBuild.CreateBuild", "cloudbuild.googleapis.com"),
    ],
    [
      "gcp_privilege_escalation_methods",
      rec("v2.deploymentmanager.deployments.insert", "deploymentmanager.googleapis.com"),
    ],
    [
      "gcp_privilege_escalation_methods",
      rec("google.cloud.functions.v1.CloudFunctionsService.CreateFunction", "cloudfunctions.googleapis.com"),
    ],
    [
      "gcp_privilege_escalation_methods",
      rec("google.cloud.run.v2.Services.CreateService", "run.googleapis.com"),
    ],
    [
      "gcp_privilege_escalation_methods",
      rec("v1.compute.projects.setCommonInstanceMetadata", "compute.googleapis.com"),
    ],
    ["gcp_privilege_escalation_methods", rec("google.iam.admin.v1.CreateRole", "iam.googleapis.com")],
    [
      "gcp_defense_evasion",
      rec("google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy", "orgpolicy.googleapis.com"),
    ],
    [
      "gcp_defense_evasion",
      rec("google.api.serviceusage.v1.ServiceUsage.DisableService", "serviceusage.googleapis.com"),
    ],
    [
      "gcp_defense_evasion",
      rec("google.logging.v2.ConfigServiceV2.UpdateSettings", "logging.googleapis.com"),
    ],
    [
      "gcp_defense_evasion",
      rec("google.cloud.securitycenter.v1.SecurityCenter.CreateMuteConfig", "securitycenter.googleapis.com"),
    ],
    ["gcp_impact", rec("DestroyCryptoKeyVersion", "cloudkms.googleapis.com")],
    [
      "gcp_impact",
      rec("google.cloud.secretmanager.v1.SecretManagerService.DeleteSecret", "secretmanager.googleapis.com"),
    ],
    ["gcp_credential_access", rec("google.api.apikeys.v2.ApiKeys.GetKeyString", "apikeys.googleapis.com")],
    ["gcp_discovery", rec("google.iam.admin.v1.ListServiceAccountKeys", "iam.googleapis.com")],
  ];
  for (const [id, r] of tagOnly) {
    it(`${id} tags ${String((r.protoPayload as Row).methodName)} without grading it`, () => {
      const rule = RULES.rules.find((x) => x.id === id);
      expect(rule?.severity).toBeUndefined();
      const g = grade(r);
      expect(g.ids).toContain(id);
      expect(g.tagger).toBeUndefined();
    });
  }

  it("does not tag compute.instances.insert, which the importer grades itself", () => {
    expect(
      grade(rec("v1.compute.instances.insert", "compute.googleapis.com")).ids.filter((i) =>
        i.startsWith("gcp_"),
      ),
    ).toEqual([]);
  });
});

describe("ported GCP rules (#2346) — credit", () => {
  it("records every source's upstream commit in the header", () => {
    for (const marker of [
      "Panther upstream commit",
      "Sentinel GCP Audit Logs upstream commit",
      "Sentinel GCP IAM upstream commit",
      "Chronicle upstream commit",
      "Rhino upstream commit",
    ]) {
      expect(readRecordedCommit(YAML, marker).sha).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("watches the Panther and both Sentinel folders in the weekly upstream check", () => {
    const markers = UPSTREAM_GROUPS.map((g) => g.marker);
    expect(markers).toEqual(
      expect.arrayContaining([
        "Panther upstream commit",
        "Sentinel GCP Audit Logs upstream commit",
        "Sentinel GCP IAM upstream commit",
      ]),
    );
  });

  it("credits each source in NOTICE", () => {
    const notice = readFileSync(fileURLToPath(new URL("../../../NOTICE", import.meta.url)), "utf8");
    for (const s of [
      "panther-analysis",
      "Azure-Sentinel",
      "chronicle/detection-rules",
      "GCP-IAM-Privilege-Escalation",
    ])
      expect(notice).toContain(s);
  });
});
