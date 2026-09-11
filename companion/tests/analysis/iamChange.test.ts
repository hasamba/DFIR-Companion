// The IAM change decoder (#931 item 6): what ONE CloudTrail record establishes — the posture of the
// call, the object it names, the words of the document it carries, the principals a trust policy
// names, the role a service call binds — and nothing a record cannot hold: no before/after, no
// direction, no content of a managed policy, no completed verb on a denied call.
import { describe, expect, it } from "vitest";
import { decodeIamChange, renderAwsDescription, type IamChange } from "../../src/analysis/iamChange.js";
import {
  CONDITIONAL_NOTE,
  ESCALATION_PRIMITIVES,
  POLICY_CAVEAT,
} from "../../src/analysis/iamPolicyDocument.js";
import { AWS_ACTIONS } from "../../src/analysis/awsImport.js";

const IAM = "iam.amazonaws.com";
const ACCT = "111122223333";
const OTHER = "999988887777";
const doc = (statements: unknown): string => JSON.stringify({ Version: "2012-10-17", Statement: statements });
const trust = (principal: unknown, extra: Record<string, unknown> = {}): string =>
  doc([{ Effect: "Allow", Principal: principal, Action: "sts:AssumeRole", ...extra }]);
const iam = (
  name: string,
  request: Record<string, unknown>,
  response: Record<string, unknown> = {},
  errorCode = "",
  errorMessage = "",
): IamChange => {
  const d = decodeIamChange(IAM, name, request, response, errorCode, errorMessage, ACCT);
  if (!d) throw new Error(`${name} not decoded`);
  return d;
};

describe("decodeIamChange — postures say what the call does, never which way access moved", () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    [
      "AttachRolePolicy",
      { roleName: "r", policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" },
      "attaches managed policy",
    ],
    [
      "DetachUserPolicy",
      { userName: "u", policyArn: "arn:aws:iam::111122223333:policy/p" },
      "detaches managed policy",
    ],
    [
      "PutRolePolicy",
      { roleName: "r", policyName: "inline", policyDocument: doc([]) },
      "replaces inline policy",
    ],
    ["DeleteGroupPolicy", { groupName: "g", policyName: "inline" }, "deletes inline policy"],
    ["CreatePolicy", { policyName: "p", policyDocument: doc([]) }, "creates policy"],
    [
      "CreatePolicyVersion",
      { policyArn: "arn:aws:iam::111122223333:policy/p", policyDocument: doc([]) },
      "adds policy version",
    ],
    [
      "SetDefaultPolicyVersion",
      { policyArn: "arn:aws:iam::111122223333:policy/p", versionId: "v3" },
      "activates policy version v3",
    ],
    [
      "DeletePolicyVersion",
      { policyArn: "arn:aws:iam::111122223333:policy/p", versionId: "v2" },
      "deletes non-default policy version v2",
    ],
    ["AddUserToGroup", { userName: "u", groupName: "g" }, "adds user to group"],
    ["RemoveUserFromGroup", { userName: "u", groupName: "g" }, "removes user from group"],
    ["CreateAccessKey", { userName: "u" }, "creates access key"],
    ["DeleteAccessKey", { userName: "u", accessKeyId: "AKID-EXAMPLE-0001" }, "deletes access key"],
    ["CreateLoginProfile", { userName: "u" }, "creates console password"],
    ["DeleteLoginProfile", { userName: "u" }, "deletes console password"],
    ["UpdateLoginProfile", { userName: "u" }, "resets console password"],
    [
      "PutRolePermissionsBoundary",
      { roleName: "r", permissionsBoundary: "arn:aws:iam::111122223333:policy/b" },
      "sets permissions boundary",
    ],
    ["DeleteUserPermissionsBoundary", { userName: "u" }, "removes permissions boundary"],
    [
      "UpdateAssumeRolePolicy",
      { roleName: "r", policyDocument: trust({ AWS: `arn:aws:iam::${ACCT}:root` }) },
      "replaces trust policy",
    ],
    [
      "CreateRole",
      { roleName: "r", assumeRolePolicyDocument: trust({ Service: "ec2.amazonaws.com" }) },
      "creates role with trust policy",
    ],
    ["CreateUser", { userName: "u" }, "creates user"],
    ["DeleteRole", { roleName: "r" }, "deletes role"],
    ["DeleteUser", { userName: "u" }, "deletes user"],
    [
      "DeactivateMFADevice",
      { userName: "u", serialNumber: "arn:aws:iam::111122223333:mfa/u" },
      "deactivates MFA device",
    ],
    [
      "DeleteVirtualMFADevice",
      { serialNumber: "arn:aws:iam::111122223333:mfa/u" },
      "deletes virtual MFA device",
    ],
    [
      "AddRoleToInstanceProfile",
      { roleName: "r", instanceProfileName: "p" },
      "binds role to instance profile",
    ],
  ];
  for (const [name, req, words] of cases) {
    it(`${name} → "${words}"`, () => {
      const d = iam(name, req);
      expect(d.posture).toBe(words);
      expect(d.attempted).toBe(false);
      expect(d.summary).not.toMatch(/\b(widen|narrow|tighten|escalat)/i);
    });
  }
  it("UpdateAccessKey reads the status: Inactive disables, Active re-enables (Medium floor)", () => {
    const off = iam("UpdateAccessKey", {
      userName: "u",
      accessKeyId: "AKID-EXAMPLE-0001",
      status: "Inactive",
    });
    expect(off.posture).toBe("disables access key");
    expect(off.severityFloor).toBeNull();
    const on = iam("UpdateAccessKey", {
      userName: "u",
      accessKeyId: "AKID-EXAMPLE-0001",
      status: "Active",
    });
    expect(on.posture).toBe("re-enables access key");
    expect(on.severityFloor).toBe("Medium");
    expect(on.mitre).toContain("T1098.001");
  });
  it("SetDefaultPolicyVersion and CreatePolicyVersion say what the record lacks", () => {
    const set = iam("SetDefaultPolicyVersion", {
      policyArn: "arn:aws:iam::111122223333:policy/p",
      versionId: "v3",
    });
    expect(set.summary).toContain("its document is not in this record");
    const add = iam("CreatePolicyVersion", {
      policyArn: "arn:aws:iam::111122223333:policy/p",
      policyDocument: doc([{ Effect: "Allow", Action: "*", Resource: "*" }]),
      setAsDefault: true,
    });
    expect(add.posture).toBe("adds policy version and activates it");
    expect(add.reading).toContain("all actions on all resources");
    expect(add.severityFloor).toBe("High");
  });
  it("DeletePolicyVersion claims 'non-default' only on success", () => {
    const ok = iam("DeletePolicyVersion", {
      policyArn: "arn:aws:iam::111122223333:policy/p",
      versionId: "v2",
    });
    expect(ok.summary).toContain("current access unchanged");
    const denied = iam(
      "DeletePolicyVersion",
      { policyArn: "arn:aws:iam::111122223333:policy/p", versionId: "v2" },
      {},
      "AccessDenied",
    );
    expect(denied.posture).toBe("attempted to delete policy version v2");
    expect(denied.summary).not.toContain("non-default");
    expect(denied.summary).not.toContain("current access unchanged");
  });
  it("removing a permissions boundary is High on success — AWS's own words: it may increase permissions", () => {
    const d = iam("DeleteRolePermissionsBoundary", { roleName: "r" });
    expect(d.severityFloor).toBe("High");
    expect(d.mitre).toContain("T1098.003");
    expect(d.summary).toContain("may increase permissions");
  });
  it("a managed policy is named and nothing about its content is claimed — AdministratorAccess included", () => {
    const d = iam("AttachUserPolicy", {
      userName: "u",
      policyArn: "arn:aws-cn:iam::aws:policy/AdministratorAccess",
    });
    expect(d.object).toContain("policy=AdministratorAccess");
    expect(d.reading).toBe("");
    expect(d.summary).toContain("its document and version are not in this record");
    expect(d.summary).not.toMatch(/grants all/);
  });
  it("Put* carries the 'previous document not in this record' qualifier; Attach does not", () => {
    const put = iam("PutUserPolicy", { userName: "u", policyName: "p", policyDocument: doc([]) });
    expect(put.qualifiers).toContain("previous document not in this record");
    const att = iam("AttachUserPolicy", { userName: "u", policyArn: "arn:aws:iam::111122223333:policy/p" });
    expect(att.qualifiers).not.toContain("previous document not in this record");
  });
});

describe("decodeIamChange — a denied call is an attempt", () => {
  it("renders 'attempted to …', says denied with the code, floors Medium, and makes no success claim", () => {
    const d = iam(
      "PutRolePolicy",
      {
        roleName: "r",
        policyName: "p",
        policyDocument: doc([{ Effect: "Allow", Action: "*", Resource: "*" }]),
      },
      {},
      "AccessDenied",
    );
    expect(d.attempted).toBe(true);
    expect(d.posture).toBe("attempted to replace inline policy");
    expect(d.summary).toContain("denied (AccessDenied)");
    expect(d.reading).toMatch(/^requested document: /);
    expect(d.reading).toContain("all actions on all resources");
    expect(d.severityFloor).toBe("Medium");
    expect(d.keySegment).toContain("|denied|");
  });
  it("a denied boundary removal and a denied public trust stay Medium — the High floors are success-only", () => {
    expect(iam("DeleteUserPermissionsBoundary", { userName: "u" }, {}, "AccessDenied").severityFloor).toBe(
      "Medium",
    );
    const t = iam(
      "UpdateAssumeRolePolicy",
      { roleName: "r", policyDocument: trust("*") },
      {},
      "AccessDenied",
    );
    expect(t.severityFloor).toBe("Medium");
    expect(t.trust).toMatch(/^requested trust: /);
  });
});

describe("decodeIamChange — trust is literal", () => {
  it("an assumption action to any principal with no Condition is unrestricted public assumption (High)", () => {
    const d = iam("UpdateAssumeRolePolicy", { roleName: "r", policyDocument: trust("*") });
    expect(d.trust).toContain("allows sts:AssumeRole to any principal");
    expect(d.trust).toContain("unrestricted public assumption");
    expect(d.severityFloor).toBe("High");
  });
  it("the same with a Condition is conditional, not unrestricted (Medium)", () => {
    const d = iam("UpdateAssumeRolePolicy", {
      roleName: "r",
      policyDocument: trust("*", { Condition: { StringEquals: { "aws:PrincipalOrgID": "o-abc" } } }),
    });
    expect(d.trust).not.toContain("unrestricted");
    expect(d.qualifiers).toContain(CONDITIONAL_NOTE);
    expect(d.severityFloor).toBe("Medium");
  });
  it("external accounts are read from a bare id, a root ARN, a role ARN and an STS assumed-role ARN (High unconditioned)", () => {
    for (const p of [
      OTHER,
      `arn:aws:iam::${OTHER}:root`,
      `arn:aws:iam::${OTHER}:role/x`,
      `arn:aws:sts::${OTHER}:assumed-role/x/session`,
      `arn:aws-us-gov:iam::${OTHER}:user/u`,
    ]) {
      const d = iam("CreateRole", { roleName: "r", assumeRolePolicyDocument: trust({ AWS: p }) });
      expect(d.trust).toContain(`external account ${OTHER}`);
      expect(d.severityFloor).toBe("High");
    }
  });
  it("an external account with an ExternalId condition is Medium and says conditional", () => {
    const d = iam("CreateRole", {
      roleName: "r",
      assumeRolePolicyDocument: trust(
        { AWS: `arn:aws:iam::${OTHER}:root` },
        { Condition: { StringEquals: { "sts:ExternalId": "x" } } },
      ),
    });
    expect(d.severityFloor).toBe("Medium");
    expect(d.qualifiers).toContain(CONDITIONAL_NOTE);
  });
  it("same-account, service and federated principals are named and carry no trust floor", () => {
    const d = iam("CreateRole", {
      roleName: "r",
      assumeRolePolicyDocument: doc([
        { Effect: "Allow", Principal: { AWS: `arn:aws:iam::${ACCT}:root` }, Action: "sts:AssumeRole" },
        { Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" },
        {
          Effect: "Allow",
          Principal: { Federated: "arn:aws:iam::111122223333:saml-provider/idp" },
          Action: "sts:AssumeRoleWithSAML",
        },
      ]),
    });
    expect(d.trust).toContain("same-account");
    expect(d.trust).toContain("service lambda.amazonaws.com");
    expect(d.trust).toContain("federated arn:aws:iam::111122223333:saml-provider/idp");
    expect(d.severityFloor).toBeNull();
  });
  it("without recipientAccountId the account is named but not compared", () => {
    const d = decodeIamChange(
      IAM,
      "CreateRole",
      { roleName: "r", assumeRolePolicyDocument: trust({ AWS: OTHER }) },
      {},
      "",
      "",
      "",
    )!;
    expect(d.trust).toContain(`account ${OTHER} — not compared: recipient account not in this record`);
    expect(d.severityFloor).toBeNull();
  });
  it("a principal of unknown form is kept, and a TagSession-only statement is not a trust", () => {
    const d = iam("CreateRole", {
      roleName: "r",
      assumeRolePolicyDocument: doc([
        { Effect: "Allow", Principal: { AWS: "not-an-arn" }, Action: "sts:AssumeRole" },
        { Effect: "Allow", Principal: "*", Action: "sts:TagSession" },
      ]),
    });
    expect(d.trust).toContain("principal of unknown form: not-an-arn");
    expect(d.trust).not.toContain("any principal");
    expect(d.severityFloor).toBeNull();
  });
  it("a Deny statement's principal is not a trust", () => {
    const d = iam("CreateRole", {
      roleName: "r",
      assumeRolePolicyDocument: doc([{ Effect: "Deny", Principal: "*", Action: "sts:AssumeRole" }]),
    });
    expect(d.trust).toBe("");
    expect(d.severityFloor).toBeNull();
  });
});

describe("decodeIamChange — role bindings in the call that passes them", () => {
  it("RunInstances passes an INSTANCE PROFILE (never called a role) to the launched instances (Medium)", () => {
    const d = decodeIamChange(
      "ec2.amazonaws.com",
      "RunInstances",
      { iamInstanceProfile: { arn: "arn:aws:iam::111122223333:instance-profile/web" } },
      { instancesSet: { items: [{ instanceId: "i-1" }, { instanceId: "i-2" }] } },
      "",
      "",
      ACCT,
    )!;
    expect(d.bindings).toEqual([
      {
        label: "instance profile",
        role: "arn:aws:iam::111122223333:instance-profile/web",
        destination: "i-1,i-2",
      },
    ]);
    expect(d.bindingsText).toContain(
      "passing instance profile arn:aws:iam::111122223333:instance-profile/web → i-1,i-2",
    );
    expect(d.bindingsText).not.toMatch(/passing role/);
    expect(d.severityFloor).toBe("Medium");
    expect(d.mitre).toContain("T1078.004");
    const byName = decodeIamChange(
      "ec2.amazonaws.com",
      "RunInstances",
      { iamInstanceProfile: { name: "web" }, clientToken: "tok" },
      {},
      "",
      "",
      ACCT,
    )!;
    expect(byName.bindings[0]).toEqual({ label: "instance profile", role: "web", destination: "tok" });
  });
  it("Lambda, ECS (both roles) and CloudFormation name the role and its destination", () => {
    const fn = decodeIamChange(
      "lambda.amazonaws.com",
      "CreateFunction20150331",
      { functionName: "f", role: "arn:aws:iam::111122223333:role/lr" },
      {},
      "",
      "",
      ACCT,
    )!;
    expect(fn.bindings).toEqual([
      { label: "role", role: "arn:aws:iam::111122223333:role/lr", destination: "f" },
    ]);
    const ecs = decodeIamChange(
      "ecs.amazonaws.com",
      "RegisterTaskDefinition",
      {
        family: "fam",
        taskRoleArn: "arn:aws:iam::111122223333:role/t",
        executionRoleArn: "arn:aws:iam::111122223333:role/e",
      },
      { taskDefinition: { revision: 7 } },
      "",
      "",
      ACCT,
    )!;
    expect(ecs.bindings).toEqual([
      { label: "task role", role: "arn:aws:iam::111122223333:role/t", destination: "fam:7" },
      { label: "execution role", role: "arn:aws:iam::111122223333:role/e", destination: "fam:7" },
    ]);
    const cfn = decodeIamChange(
      "cloudformation.amazonaws.com",
      "CreateStack",
      { stackName: "s", roleARN: "arn:aws:iam::111122223333:role/cfn" },
      { stackId: "arn:aws:cloudformation:us-east-1:111122223333:stack/s/uuid" },
      "",
      "",
      ACCT,
    )!;
    expect(cfn.bindings[0]).toEqual({
      label: "role",
      role: "arn:aws:iam::111122223333:role/cfn",
      destination: "arn:aws:cloudformation:us-east-1:111122223333:stack/s/uuid",
    });
  });
  it("a RunInstances without a profile, and CreateInstanceProfile, are not IAM changes", () => {
    expect(
      decodeIamChange("ec2.amazonaws.com", "RunInstances", { instanceType: "t3.micro" }, {}, "", "", ACCT),
    ).toBeNull();
    expect(
      decodeIamChange(IAM, "CreateInstanceProfile", { instanceProfileName: "p" }, {}, "", "", ACCT),
    ).toBeNull();
  });
  it("a PassRole denial on any call is 'role passing denied' (Medium) — never 'passed'", () => {
    const d = decodeIamChange(
      "lambda.amazonaws.com",
      "CreateFunction20150331",
      { functionName: "f", role: "arn:aws:iam::111122223333:role/admin" },
      {},
      "AccessDenied",
      "User: arn:aws:iam::111122223333:user/dev is not authorized to perform: iam:PassRole on resource: arn:aws:iam::111122223333:role/admin",
      ACCT,
    )!;
    expect(d.bindingsText).toContain("role passing denied: arn:aws:iam::111122223333:role/admin");
    expect(d.bindingsText).not.toMatch(/\bpassing role\b/);
    expect(d.severityFloor).toBe("Medium");
    expect(d.attempted).toBe(true);
  });
});

describe("decodeIamChange — the key carries every identity", () => {
  const key = (name: string, req: Record<string, unknown>, res: Record<string, unknown> = {}, src = IAM) =>
    decodeIamChange(src, name, req, res, "", "", ACCT)!.keySegment;
  it("distinct objects are distinct keys; the same call twice is one", () => {
    expect(key("AttachGroupPolicy", { groupName: "a", policyArn: "arn:aws:iam::aws:policy/X" })).not.toBe(
      key("AttachGroupPolicy", { groupName: "b", policyArn: "arn:aws:iam::aws:policy/X" }),
    );
    expect(key("AttachRolePolicy", { roleName: "r", policyArn: "arn:aws:iam::aws:policy/X" })).not.toBe(
      key("AttachRolePolicy", { roleName: "r", policyArn: "arn:aws:iam::aws:policy/Y" }),
    );
    expect(
      key("SetDefaultPolicyVersion", { policyArn: "arn:aws:iam::111122223333:policy/p", versionId: "v1" }),
    ).not.toBe(
      key("SetDefaultPolicyVersion", { policyArn: "arn:aws:iam::111122223333:policy/p", versionId: "v2" }),
    );
    expect(key("DeleteUser", { userName: "a" })).not.toBe(key("DeleteUser", { userName: "b" }));
    expect(key("DeactivateMFADevice", { userName: "u", serialNumber: "s1" })).not.toBe(
      key("DeactivateMFADevice", { userName: "u", serialNumber: "s2" }),
    );
    expect(key("AttachGroupPolicy", { groupName: "a", policyArn: "arn:aws:iam::aws:policy/X" })).toBe(
      key("AttachGroupPolicy", { groupName: "a", policyArn: "arn:aws:iam::aws:policy/X" }),
    );
  });
  it("identities the RESPONSE creates are in the key: two new keys for one user, two new versions", () => {
    expect(
      key("CreateAccessKey", { userName: "u" }, { accessKey: { accessKeyId: "AKID-EXAMPLE-0001" } }),
    ).not.toBe(
      key("CreateAccessKey", { userName: "u" }, { accessKey: { accessKeyId: "AKID-EXAMPLE-0002" } }),
    );
    const v = (id: string) =>
      key(
        "CreatePolicyVersion",
        { policyArn: "arn:aws:iam::111122223333:policy/p", policyDocument: doc([]) },
        { policyVersion: { versionId: id } },
      );
    expect(v("v4")).not.toBe(v("v5"));
  });
  it("two different documents, readable or not, are two keys; the same document reordered is one", () => {
    const put = (d: string) => key("PutRolePolicy", { roleName: "r", policyName: "p", policyDocument: d });
    expect(put("garbage-one")).not.toBe(put("garbage-two"));
    expect(put('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')).toBe(
      put('{"Statement":[{"Resource":"*","Action":"s3:*","Effect":"Allow"}]}'),
    );
  });
  it("bindings key on the role AND its destination: two functions on one role, two profiles on one launch", () => {
    const fn = (f: string) =>
      key(
        "CreateFunction20150331",
        { functionName: f, role: "arn:aws:iam::111122223333:role/lr" },
        {},
        "lambda.amazonaws.com",
      );
    expect(fn("a")).not.toBe(fn("b"));
    const run = (p: string) =>
      key("RunInstances", { iamInstanceProfile: { name: p }, clientToken: "t" }, {}, "ec2.amazonaws.com");
    expect(run("web")).not.toBe(run("db"));
  });
});

describe("decodeIamChange — table invariants", () => {
  const IAM_API = new Set(
    Object.keys(AWS_ACTIONS).filter((k) =>
      /^(create|delete|update|attach|detach|put|add|remove|set|deactivate|enable|resync|tag|untag|change|get|list)(user|role|group|policy|accesskey|loginprofile|mfa|virtualmfa|assumerole|default|instanceprofile|permissionsboundary|servicespecific|saml|openid|account|virtual|useraccess|accountpassword)/i.test(
        k,
      ),
    ),
  );
  it("every IAM entry of AWS_ACTIONS has a posture (a new table entry without one fails here)", () => {
    expect(IAM_API.size).toBeGreaterThan(10);
    for (const name of IAM_API) {
      expect(decodeIamChange(IAM, name, {}, {}, "", "", ACCT), name).not.toBeNull();
    }
  });
  it("every High-graded IAM entry of AWS_ACTIONS is an escalation primitive", () => {
    const lower = new Set(ESCALATION_PRIMITIVES.map((p) => p.toLowerCase()));
    for (const name of IAM_API) {
      if (AWS_ACTIONS[name].severity !== "High") continue;
      expect(lower.has(`iam:${name}`), name).toBe(true);
    }
  });
  it("is safe on malformed shapes", () => {
    for (const [req, res] of [
      [null, null],
      ["str", 1],
      [[], []],
      [{ policyDocument: 5 }, { accessKey: "x" }],
    ] as Array<[unknown, unknown]>) {
      expect(() => decodeIamChange(IAM, "PutRolePolicy", req, res, "", "", ACCT)).not.toThrow();
      expect(() =>
        decodeIamChange("ec2.amazonaws.com", "RunInstances", req, res, "", "", ACCT),
      ).not.toThrow();
    }
  });
});

describe("renderAwsDescription — reserved budgets", () => {
  const parts = (over: Partial<Parameters<typeof renderAwsDescription>[0]> = {}) => ({
    head: `AWS PutRolePolicy (iam) by ${"p".repeat(500)} from 203.0.113.9 in us-east-1`,
    posture: "attempted to replace inline policy",
    outcome: "denied (AccessDenied)",
    object: `role=${"r".repeat(400)} policyName=${"n".repeat(400)}`,
    optional: [
      `requested document: ${"x".repeat(1000)}`,
      `requested trust: ${"t".repeat(500)}`,
      `passing role ${"a".repeat(300)} → ${"d".repeat(300)}`,
    ],
    tail: `[ua: ${"u".repeat(30)}] [root] [AccessDenied]`,
    qualifiers: ["previous document not in this record", CONDITIONAL_NOTE, POLICY_CAVEAT],
    ...over,
  });
  it("the maximal row keeps the head, the outcome, the object and all three qualifiers inside 600", () => {
    const s = renderAwsDescription(parts());
    expect(s.length).toBeLessThanOrEqual(600);
    expect(s).toMatch(/^AWS PutRolePolicy \(iam\) by p+/);
    expect(s).toContain("attempted to replace inline policy");
    expect(s).toContain("denied (AccessDenied)");
    expect(s).toContain("role=rrrr");
    expect(s).toContain("previous document not in this record");
    expect(s).toContain(CONDITIONAL_NOTE);
    expect(s).toContain(POLICY_CAVEAT);
    expect(s).toContain("[root]");
  });
  it("a short row is composed whole, in slot order, with no clipping marks", () => {
    const s = renderAwsDescription({
      head: "AWS AttachRolePolicy (iam) by alice",
      posture: "attaches managed policy",
      outcome: "",
      object: "role=r policy=ReadOnlyAccess",
      optional: ["— its document and version are not in this record"],
      tail: "",
      qualifiers: [],
    });
    expect(s).toBe(
      "AWS AttachRolePolicy (iam) by alice attaches managed policy role=r policy=ReadOnlyAccess — its document and version are not in this record",
    );
  });
});
