// #2345 — the TrailDiscover AWS rules in the SHIPPED tags.yaml, each run over the REAL CloudTrail
// importer's rendered row and the real tagger. Per graded rule: a synthetic record that fires it (and
// that the importer alone leaves at its floor, so the rule is what grades it), plus benign look-alikes
// that must not: an AWS-service caller, a failed call, a read-only neighbour, the same name in another
// service.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";
import { readRecordedCommit } from "../../scripts/upstreamRulesDiff.mjs";

const YAML = readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8");
const RULES = compileText(YAML);
const RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

const USER = {
  type: "IAMUser",
  userName: "alice",
  principalId: "AIDAEXAMPLEALICE",
  accountId: "111111111111",
  arn: "arn:aws:iam::111111111111:user/alice",
};
const SERVICE_ROLE = {
  type: "AssumedRole",
  principalId: "AROAEXAMPLESVC:autoscaling",
  arn: "arn:aws:sts::111111111111:assumed-role/AWSServiceRoleForExample/autoscaling",
  accountId: "111111111111",
  invokedBy: "application-autoscaling.amazonaws.com",
  sessionContext: {
    sessionIssuer: {
      type: "Role",
      userName: "AWSServiceRoleForExample",
      arn: "arn:aws:iam::111111111111:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample",
    },
  },
};
const ROOT = {
  type: "Root",
  principalId: "111111111111",
  accountId: "111111111111",
  arn: "arn:aws:iam::111111111111:root",
};

const record = (eventSource: string, eventName: string, extra: Record<string, unknown> = {}) => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: USER,
  recipientAccountId: "111111111111",
  readOnly: false,
  eventID: "00000000-0000-4000-8000-0000000000aa",
  eventSource,
  eventName,
  ...extra,
});

interface Row {
  description: string;
  importer: Severity;
  final: Severity;
  ruleIds: string[];
  mitre: string[];
}

function run(eventSource: string, eventName: string, extra: Record<string, unknown> = {}): Row {
  const events = parseCloudTrail(JSON.stringify({ Records: [record(eventSource, eventName, extra)] })).events;
  expect(events).toHaveLength(1);
  const e = events[0];
  const event = { ...e, id: "e0", relatedFindingIds: [], sourceScreenshots: [] } as unknown as ForensicEvent;
  const hit = runTagger([event], RULES).perEvent[0];
  const tagged = hit?.severity;
  return {
    description: e.description,
    importer: e.severity,
    final: tagged && RANK[tagged] > RANK[e.severity] ? tagged : e.severity,
    ruleIds: hit?.ruleIds ?? [],
    mitre: hit?.mitre ?? [],
  };
}

const tdRules = (r: Row) => r.ruleIds.filter((id) => id.startsWith("td_aws_"));

interface GradedCase {
  rule: string;
  source: string;
  names: string[];
  severity: Severity;
  mitre: string[];
  /** The service-caller exclusion does not apply (AWS records another account as the caller). */
  noServiceExclusion?: boolean;
  extra?: Record<string, unknown>;
}

const GRADED: GradedCase[] = [
  {
    rule: "td_aws_guardduty_member_disassociated",
    source: "guardduty.amazonaws.com",
    names: ["DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount"],
    severity: "High",
    mitre: ["T1562.001"],
    extra: { requestParameters: { detectorId: "12abc34d567e8fa901bc2d34e56789f0" } },
  },
  {
    rule: "td_aws_guardduty_invitations_deleted",
    source: "guardduty.amazonaws.com",
    names: ["DeleteInvitations"],
    severity: "Medium",
    mitre: ["T1562.001"],
    extra: { requestParameters: { accountIds: ["222222222222"] } },
  },
  {
    rule: "td_aws_org_handshake_accepted",
    source: "organizations.amazonaws.com",
    names: ["AcceptHandshake"],
    severity: "Medium",
    mitre: ["T1666"],
    extra: { requestParameters: { handshakeId: "h-examplehandshakeid111" } },
  },
  {
    rule: "td_aws_ses_production_access_requested",
    source: "ses.amazonaws.com",
    names: ["PutAccountDetails"],
    severity: "Medium",
    mitre: ["T1578.005"],
  },
  {
    rule: "td_aws_ec2_serial_console_enabled",
    source: "ec2.amazonaws.com",
    names: ["EnableSerialConsoleAccess"],
    severity: "Medium",
    mitre: ["T1021.008"],
  },
  {
    rule: "td_aws_ec2_serial_console_key_pushed",
    source: "ec2-instance-connect.amazonaws.com",
    names: ["SendSerialConsoleSSHPublicKey"],
    severity: "Medium",
    mitre: ["T1021.004"],
    extra: { requestParameters: { instanceId: "i-0123456789abcdef0", serialPort: 0 } },
  },
  {
    rule: "td_aws_ec2_instance_profile_replaced",
    source: "ec2.amazonaws.com",
    names: ["ReplaceIamInstanceProfileAssociation"],
    severity: "Medium",
    mitre: ["T1098.003"],
    extra: {
      requestParameters: {
        associationId: "iip-assoc-0123456789abcdef0",
        iamInstanceProfile: { name: "AdminProfile" },
      },
    },
  },
  {
    rule: "td_aws_ec2_shared_snapshot_copied",
    source: "ec2.amazonaws.com",
    names: ["SharedSnapshotCopyInitiated", "SharedSnapshotVolumeCreated"],
    severity: "Medium",
    mitre: ["T1537"],
    noServiceExclusion: true,
    extra: {
      eventType: "AwsServiceEvent",
      sourceIPAddress: "ec2.amazonaws.com",
      userIdentity: { type: "AWSAccount", principalId: "", accountId: "222222222222" },
      serviceEventDetails: { snapshotId: "snap-0123456789abcdef0" },
    },
  },
  {
    rule: "td_aws_iam_identity_provider_created",
    source: "iam.amazonaws.com",
    names: ["CreateSAMLProvider", "CreateOpenIDConnectProvider"],
    severity: "Medium",
    mitre: ["T1136.003", "T1484.002"],
    extra: { requestParameters: { name: "ExampleIdP" } },
  },
  {
    rule: "td_aws_rds_instance_deleted",
    source: "rds.amazonaws.com",
    names: ["DeleteDBInstance"],
    severity: "Medium",
    mitre: ["T1485"],
    extra: { requestParameters: { dBInstanceIdentifier: "prod-db-1", skipFinalSnapshot: true } },
  },
  {
    rule: "td_aws_bedrock_model_access_enabled",
    source: "bedrock.amazonaws.com",
    names: ["PutUseCaseForModelAccess", "CreateFoundationModelAgreement", "PutFoundationModelEntitlement"],
    severity: "Medium",
    mitre: ["T1496"],
  },
  {
    rule: "td_aws_root_password_recovery",
    source: "signin.amazonaws.com",
    names: ["PasswordRecoveryRequested"],
    severity: "Medium",
    mitre: ["T1078"],
    noServiceExclusion: true,
    extra: { eventType: "AwsConsoleSignIn", responseElements: { PasswordRecoveryRequested: "Success" } },
  },
];

describe("TrailDiscover AWS rules — the importer row format they key on (#2345)", () => {
  it("pins the `AWS <EventName> (<source>) by <who>` head the rules match", () => {
    expect(run("guardduty.amazonaws.com", "DisassociateFromMasterAccount").description).toMatch(
      /^AWS DisassociateFromMasterAccount \(guardduty\) by alice from 198\.51\.100\.7 /,
    );
    expect(run("lambda.amazonaws.com", "CreateFunction20150331").description).toMatch(
      /^AWS CreateFunction20150331 \(lambda\) by alice /,
    );
    expect(run("ec2-instance-connect.amazonaws.com", "SendSSHPublicKey").description).toMatch(
      /^AWS SendSSHPublicKey \(ec2-instance-connect\) /,
    );
  });

  it("pins the words the graded rules exclude: an AWS-service caller and a failed call", () => {
    const svc = run("rds.amazonaws.com", "DeleteDBInstance", { userIdentity: SERVICE_ROLE });
    expect(svc.description).toContain("request made by AWS service");
    const failed = run("rds.amazonaws.com", "DeleteDBInstance", { errorCode: "AccessDenied" });
    expect(failed.description).toMatch(/\[AccessDenied\]/);
    const root = run("guardduty.amazonaws.com", "DisassociateFromMasterAccount", { userIdentity: ROOT });
    expect(root.description).toContain("[root]");
  });
});

describe("TrailDiscover AWS rules — graded (#2345)", () => {
  for (const c of GRADED) {
    for (const name of c.names) {
      it(`${c.rule}: ${name} is graded ${c.severity} with ${c.mitre.join(", ")}`, () => {
        const row = run(c.source, name, c.extra);
        expect(tdRules(row)).toEqual([c.rule]);
        expect(RANK[row.importer]).toBeLessThanOrEqual(RANK.Low);
        expect(row.final).toBe(c.severity);
        for (const t of c.mitre) expect(row.mitre).toContain(t);
      });
    }

    const name = c.names[0];
    it(`${c.rule}: a failed ${name} keeps the importer's grade and is not tagged`, () => {
      const row = run(c.source, name, { ...c.extra, errorCode: "AccessDenied", errorMessage: "denied" });
      expect(tdRules(row)).toEqual([]);
      expect(row.final).toBe(row.importer);
    });

    if (!c.noServiceExclusion) {
      it(`${c.rule}: ${name} made by an AWS service stays at Info / Low`, () => {
        const row = run(c.source, name, {
          ...c.extra,
          userIdentity: SERVICE_ROLE,
          sourceIPAddress: "application-autoscaling.amazonaws.com",
        });
        expect(tdRules(row)).toEqual([]);
        expect(RANK[row.final]).toBeLessThanOrEqual(RANK.Low);
        const bare = run(c.source, name, {
          ...c.extra,
          userIdentity: { type: "AWSService", invokedBy: c.source },
          sourceIPAddress: c.source,
        });
        expect(tdRules(bare)).toEqual([]);
      });
    }
  }

  it("a root caller still fires the rule, at the rule's grade", () => {
    const row = run("guardduty.amazonaws.com", "DisassociateFromMasterAccount", { userIdentity: ROOT });
    expect(tdRules(row)).toEqual(["td_aws_guardduty_member_disassociated"]);
    expect(row.final).toBe("High");
  });

  it("read-only neighbours and same-named calls in other services stay at Info / Low", () => {
    const lookalikes: [string, string, Record<string, unknown>][] = [
      ["guardduty.amazonaws.com", "GetMasterAccount", { readOnly: true }],
      ["guardduty.amazonaws.com", "ListInvitations", { readOnly: true }],
      ["organizations.amazonaws.com", "ListHandshakesForAccount", { readOnly: true }],
      ["ec2.amazonaws.com", "GetSerialConsoleAccessStatus", { readOnly: true }],
      ["ec2.amazonaws.com", "DescribeIamInstanceProfileAssociations", { readOnly: true }],
      ["ec2.amazonaws.com", "DisableSerialConsoleAccess", {}],
      ["iam.amazonaws.com", "ListSAMLProviders", { readOnly: true }],
      ["iam.amazonaws.com", "GetOpenIDConnectProvider", { readOnly: true }],
      ["rds.amazonaws.com", "DescribeDBInstances", { readOnly: true }],
      ["rds.amazonaws.com", "DeleteDBInstanceAutomatedBackup", {}],
      ["bedrock.amazonaws.com", "GetUseCaseForModelAccess", { readOnly: true }],
      ["sesv2.amazonaws.com", "GetAccount", { readOnly: true }],
      ["ec2-instance-connect.amazonaws.com", "SendSSHPublicKey", {}],
    ];
    for (const [source, name, extra] of lookalikes) {
      const row = run(source, name, extra);
      const graded = tdRules(row).filter((id) => RULES.rules.find((r) => r.id === id)?.severity);
      expect(graded, `${name} (${source})`).toEqual([]);
      expect(RANK[row.final], `${name} (${source})`).toBeLessThanOrEqual(RANK.Low);
    }
  });
});

describe("TrailDiscover AWS rules — tag-only (#2345)", () => {
  const TAG_ONLY: [string, string, string, boolean][] = [
    ["td_aws_discovery", "guardduty.amazonaws.com", "ListDetectors", true],
    ["td_aws_discovery", "ses.amazonaws.com", "GetSendQuota", true],
    ["td_aws_discovery", "lambda.amazonaws.com", "ListFunctions20150331", true],
    ["td_aws_credential_access", "ec2.amazonaws.com", "GetPasswordData", true],
    ["td_aws_persistence", "lambda.amazonaws.com", "UpdateFunctionCode20150331v2", false],
    ["td_aws_persistence", "lambda.amazonaws.com", "AddPermission20150331v2", false],
    ["td_aws_privilege_escalation", "redshift.amazonaws.com", "GetClusterCredentials", false],
    ["td_aws_defense_evasion", "organizations.amazonaws.com", "InviteAccountToOrganization", false],
    ["td_aws_lateral_movement", "ec2-instance-connect.amazonaws.com", "SendSSHPublicKey", false],
    ["td_aws_execution", "cloudshell.amazonaws.com", "CreateSession", false],
    ["td_aws_collection", "redshift-data.amazonaws.com", "ExecuteStatement", false],
    ["td_aws_exfiltration", "rds.amazonaws.com", "ModifyDBSnapshotAttribute", false],
    ["td_aws_impact", "route53.amazonaws.com", "ChangeResourceRecordSets", false],
    ["td_aws_resource_development", "route53domains.amazonaws.com", "RegisterDomain", false],
  ];
  for (const [rule, source, name, readOnly] of TAG_ONLY) {
    it(`${rule}: ${name} is tagged and keeps the importer's grade`, () => {
      const row = run(source, name, { readOnly });
      expect(tdRules(row)).toEqual([rule]);
      expect(row.final).toBe(row.importer);
    });
  }

  it("keys on the source as well as the name, and never on a longer name", () => {
    // CreateUser (transfer) is graded by the importer and left out; ListClusters exists in ECS and EKS.
    expect(tdRules(run("iam.amazonaws.com", "ListClustersExample", { readOnly: true }))).toEqual([]);
    expect(tdRules(run("lambda.amazonaws.com", "GetFunctionConcurrency", { readOnly: true }))).toEqual([]);
    expect(tdRules(run("lambda.amazonaws.com", "InvokeAsync", {}))).toEqual([]);
    expect(tdRules(run("s3.amazonaws.com", "GetObject", { readOnly: true }))).toEqual([]);
    expect(tdRules(run("ecs.amazonaws.com", "ListClusters", { readOnly: true }))).toEqual([
      "td_aws_discovery",
    ]);
    expect(tdRules(run("eks.amazonaws.com", "ListClusters", { readOnly: true }))).toEqual([
      "td_aws_discovery",
    ]);
  });
});

describe("TrailDiscover AWS rules — the ruleset (#2345)", () => {
  const td = RULES.rules.filter((r) => r.id.startsWith("td_aws_"));
  const tactics = new Set([
    "td_aws_discovery",
    "td_aws_credential_access",
    "td_aws_initial_access",
    "td_aws_persistence",
    "td_aws_privilege_escalation",
    "td_aws_defense_evasion",
    "td_aws_lateral_movement",
    "td_aws_execution",
    "td_aws_collection",
    "td_aws_exfiltration",
    "td_aws_impact",
    "td_aws_resource_development",
  ]);

  it("every graded rule has a severity above Info and MITRE; every tactic rule is tag-only", () => {
    for (const r of td) {
      if (tactics.has(r.id)) {
        expect(r.severity, r.id).toBeUndefined();
        expect(r.mitre, r.id).toEqual([]);
      } else {
        expect(r.severity && RANK[r.severity] > 0, r.id).toBe(true);
        expect(r.mitre.length, r.id).toBeGreaterThan(0);
        expect(r.tags, r.id).toContain("traildiscover");
      }
    }
    expect(td.filter((r) => !tactics.has(r.id))).toHaveLength(GRADED.length);
  });

  it("records the TrailDiscover upstream commit the port came from", () => {
    const { sha, date } = readRecordedCommit(YAML, "TrailDiscover upstream commit");
    expect(sha).toMatch(/^[0-9a-f]{40}$/);
    expect(date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
