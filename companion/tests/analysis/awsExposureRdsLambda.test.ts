// #2605 — RDS ModifyDBSnapshotAttribute and Lambda AddPermission state the principal they share
// with, so the graded tags.yaml rules can tell a public share from an account-scoped one, and a
// public function from routine trigger wiring. Record shapes copied from the Stratus Red Team
// sample (values replaced with synthetic ones). Every assertion goes through the real importer.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { awsExposurePosture } from "../../src/analysis/awsExposure.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const OWN = "111111111111";
const OUTSIDE = "444455556666";
let n = 0;
const trail = (
  eventSource: string,
  eventName: string,
  requestParameters: unknown,
  over: Record<string, unknown> = {},
) => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  eventSource,
  eventName,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: { type: "IAMUser", userName: "alice", accountId: OWN, arn: `arn:aws:iam::${OWN}:user/alice` },
  recipientAccountId: OWN,
  requestParameters,
  eventID: `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`,
  ...over,
});
const rds = (req: Record<string, unknown>, name = "ModifyDBSnapshotAttribute", over = {}) =>
  trail(
    "rds.amazonaws.com",
    name,
    { attributeName: "restore", dBSnapshotIdentifier: "exfiltration", ...req },
    over,
  );
const lambda = (req: Record<string, unknown>, source = "lambda.amazonaws.com", over = {}) =>
  trail(
    source,
    "AddPermission20150331v2",
    {
      action: "lambda:InvokeFunction",
      functionName: "backdoor-func",
      statementId: "backdoor",
      ...req,
    },
    over,
  );

const TAGS = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
function row(r: Record<string, unknown>) {
  const res = parseCloudTrail(JSON.stringify({ Records: [r] }), { aggregate: false });
  const e = res.events.find((x) => x.description.startsWith("AWS "));
  if (!e) throw new Error("no row");
  const event = { ...e, id: "e0", relatedFindingIds: [], sourceScreenshots: [] } as unknown as ForensicEvent;
  const t = runTagger([event], TAGS).perEvent[0];
  return { description: e.description, ruleIds: t?.ruleIds ?? [], tagSeverity: t?.severity };
}

describe("RDS snapshot share (#2605)", () => {
  it("an outside account is stated and graded High by the share rule", () => {
    const r = row(rds({ valuesToAdd: [OUTSIDE] }));
    expect(r.description).toContain(`shares DB snapshot exfiltration with account ${OUTSIDE}`);
    expect(r.ruleIds).toContain("cloud_aws_rds_snapshot_shared");
    expect(r.tagSeverity).toBe("High");
  });

  it("'all' is a public share; the items form and the cluster call are read", () => {
    expect(row(rds({ valuesToAdd: { items: ["all"] } })).description).toContain(
      'shares DB snapshot exfiltration publicly (restore attribute "all")',
    );
    const c = row(
      trail("rds.amazonaws.com", "ModifyDBClusterSnapshotAttribute", {
        attributeName: "restore",
        dBClusterSnapshotIdentifier: "c1",
        valuesToAdd: ["all"],
      }),
    );
    expect(c.description).toContain("shares DB cluster snapshot c1 publicly");
    expect(c.ruleIds).toContain("cloud_aws_rds_snapshot_shared");
  });

  it("an un-share is stated and not graded by the share rule; another attribute reads nothing", () => {
    const r = row(rds({ valuesToRemove: [OUTSIDE] }));
    expect(r.description).toContain(`removes sharing of DB snapshot exfiltration from account ${OUTSIDE}`);
    expect(r.ruleIds).not.toContain("cloud_aws_rds_snapshot_shared");
    expect(
      awsExposurePosture(
        "ModifyDBSnapshotAttribute",
        { attributeName: "other", valuesToAdd: ["all"] },
        "",
        OWN,
        "rds.amazonaws.com",
      ),
    ).toBe("");
  });

  it("a failed share is 'requested … failed' and the rule leaves it out", () => {
    const r = row(rds({ valuesToAdd: [OUTSIDE] }, undefined, { errorCode: "AccessDenied" }));
    expect(r.description).toMatch(
      /requested: shares DB snapshot exfiltration with account \d+ — failed \(AccessDenied\)/,
    );
    expect(r.ruleIds).not.toContain("cloud_aws_rds_snapshot_shared");
  });

  it("a denied share stays out of every exposure rule even when a long user agent drops the error marker", () => {
    const ua = { userAgent: `aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 md/GOOS#linux ${"x".repeat(40)}` };
    const denied = { errorCode: "AccessDenied", ...ua };
    const r = row(rds({ valuesToAdd: [OUTSIDE] }, undefined, denied));
    expect(r.description).toContain("requested: shares DB snapshot");
    expect(r.ruleIds).not.toContain("cloud_aws_rds_snapshot_shared");
    const pub = row(lambda({ principal: "*" }, undefined, denied));
    expect(pub.ruleIds).not.toContain("cloud_aws_lambda_public_permission");
    const cross = row(lambda({ principal: OUTSIDE }, undefined, denied));
    expect(cross.ruleIds).not.toContain("cloud_aws_lambda_cross_account_permission");
  });
});

describe("Lambda AddPermission (#2605)", () => {
  it('principal "*" with no condition is any principal, graded High', () => {
    const r = row(lambda({ principal: "*" }));
    expect(r.description).toContain(
      'grants lambda:InvokeFunction to any principal ("*") on function backdoor-func',
    );
    expect(r.ruleIds).toContain("cloud_aws_lambda_public_permission");
    expect(r.tagSeverity).toBe("High");
  });

  it('"*" under a condition is said as conditional and not graded public', () => {
    const r = row(lambda({ principal: "*", sourceArn: "arn:aws:s3:::b1" }));
    expect(r.description).toContain("under a condition");
    expect(r.ruleIds).not.toContain("cloud_aws_lambda_public_permission");
  });

  it("an outside account is Medium; this account and a service principal are not graded", () => {
    const outside = row(lambda({ principal: OUTSIDE }));
    expect(outside.description).toContain(`to account ${OUTSIDE} (another account)`);
    expect(outside.ruleIds).toContain("cloud_aws_lambda_cross_account_permission");
    expect(outside.tagSeverity).toBe("Medium");
    const role = row(lambda({ principal: `arn:aws:iam::${OUTSIDE}:role/automation` }));
    expect(role.description).toContain("(another account)");
    expect(role.ruleIds).toContain("cloud_aws_lambda_cross_account_permission");
    const own = row(lambda({ principal: `arn:aws:iam::${OWN}:root` }));
    expect(own.description).toContain("(this account)");
    expect(own.ruleIds.filter((id) => id.startsWith("cloud_aws_lambda"))).toEqual([]);
    const svc = row(lambda({ principal: "s3.amazonaws.com", sourceArn: "arn:aws:s3:::b1" }));
    expect(svc.description).toContain("to service s3.amazonaws.com");
    expect(svc.ruleIds.filter((id) => id.startsWith("cloud_aws_lambda"))).toEqual([]);
  });

  it("a function URL with no authentication is stated", () => {
    expect(row(lambda({ principal: "*", functionUrlAuthType: "NONE" })).description).toContain(
      "function URL with no authentication",
    );
  });

  it("SNS / SQS AddPermission is not read as a Lambda grant", () => {
    for (const source of ["sns.amazonaws.com", "sqs.amazonaws.com"])
      expect(row(trail(source, "AddPermission", { principal: "*", action: "x" })).description).not.toContain(
        "any principal",
      );
  });

  it("two grants to different principals stay two rows under aggregation", () => {
    const res = parseCloudTrail(
      JSON.stringify({ Records: [lambda({ principal: "*" }), lambda({ principal: OUTSIDE })] }),
      { aggregate: true },
    );
    expect(res.events.filter((e) => /^AWS AddPermission/.test(e.description))).toHaveLength(2);
  });
});
