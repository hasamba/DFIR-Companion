// #2604 items 8–9 — CloudTrail calls graded by a parameter the record carries: a console sign-in by
// an IAM user without MFA, and Systems Manager parameters read WITH decryption by an IAM user or an
// assumed-role session that no AWS service or workload issued. Synthetic records: account
// 111111111111, documentation IPs, invented ids.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";

const iamUser = {
  type: "IAMUser",
  principalId: "AIDAEXAMPLE000000001",
  arn: "arn:aws:iam::111111111111:user/alice",
  accountId: "111111111111",
  userName: "alice",
};
const assumed = (extra: Record<string, unknown> = {}, sc: Record<string, unknown> = {}) => ({
  type: "AssumedRole",
  principalId: "AROAEXAMPLE000000002:alice-session",
  arn: "arn:aws:sts::111111111111:assumed-role/Ops/alice-session",
  accountId: "111111111111",
  accessKeyId: "ASIAEXAMPLE000000003",
  sessionContext: {
    sessionIssuer: {
      type: "Role",
      principalId: "AROAEXAMPLE000000002",
      arn: "arn:aws:iam::111111111111:role/Ops",
      accountId: "111111111111",
      userName: "Ops",
    },
    attributes: { creationDate: "2026-04-01T09:00:00Z", mfaAuthenticated: "false" },
    ...sc,
  },
  ...extra,
});

const base = (o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: "2026-04-01T10:00:00Z",
  awsRegion: "us-east-1",
  sourceIPAddress: "203.0.113.50",
  userAgent: "aws-cli/2.15.0",
  userIdentity: iamUser,
  recipientAccountId: "111111111111",
  eventID: "00000000-0000-4000-8000-0000000000e1",
  ...o,
});

const login = (mfa: string, result = "Success", identity: unknown = iamUser) =>
  base({
    eventSource: "signin.amazonaws.com",
    eventName: "ConsoleLogin",
    eventType: "AwsConsoleSignIn",
    readOnly: false,
    userIdentity: identity,
    responseElements: { ConsoleLogin: result },
    additionalEventData: {
      LoginTo: "https://console.aws.amazon.com/console/home",
      MobileVersion: "No",
      MFAUsed: mfa,
    },
  });

const getParams = (o: Record<string, unknown> = {}, name = "GetParameters") =>
  base({
    eventSource: "ssm.amazonaws.com",
    eventName: name,
    readOnly: true,
    requestParameters: { names: ["/credentials/db-password", "/credentials/api-key"], withDecryption: true },
    responseElements: null,
    ...o,
  });

const rows = (records: Record<string, unknown>[]) =>
  parseCloudTrail(JSON.stringify({ Records: records })).events;

describe("ConsoleLogin without MFA (#2604 item 8)", () => {
  it("an IAM user's successful sign-in without MFA is Medium + T1078.004 and says so", () => {
    const [e] = rows([login("No")]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1078.004");
    expect(e.description).toContain("without MFA");
  });

  it("with MFA, failed, or by an assumed-role (SSO) session it is unchanged", () => {
    expect(rows([login("Yes")])[0].severity).toBe("Info");
    expect(rows([login("No", "Success", assumed())])[0].severity).toBe("Info");
    const failed = rows([login("No", "Failure")])[0];
    expect(failed.description).not.toContain("without MFA");
    expect((failed.mitreTechniques ?? []).includes("T1110")).toBe(true);
  });

  it("root stays High", () => {
    const root = {
      type: "Root",
      principalId: "111111111111",
      arn: "arn:aws:iam::111111111111:root",
      accountId: "111111111111",
    };
    expect(rows([login("No", "Success", root)])[0].severity).toBe("High");
  });

  it("with and without MFA never fold into one row, in either order", () => {
    for (const order of [
      [login("No"), login("Yes")],
      [login("Yes"), login("No")],
    ]) {
      expect(
        rows(order)
          .map((e) => e.severity)
          .sort(),
      ).toEqual(["Info", "Medium"]);
    }
  });
});

describe("SSM parameters read with decryption (#2604 item 9)", () => {
  it("GetParameters / GetParameter / GetParametersByPath by an IAM user is Medium + T1552", () => {
    for (const name of ["GetParameters", "GetParameter", "GetParametersByPath"]) {
      const req =
        name === "GetParameter"
          ? { name: "/credentials/db-password", withDecryption: true }
          : name === "GetParametersByPath"
            ? { path: "/credentials", withDecryption: true }
            : undefined;
      const [e] = rows([getParams(req ? { requestParameters: req } : {}, name)]);
      expect(e.severity).toBe("Medium");
      expect(e.mitreTechniques).toContain("T1552");
      expect(e.description).toContain("with decryption");
      expect(e.description).toContain("IAMUser");
      expect(e.description).not.toMatch(/human/i);
    }
  });

  it("an assumed-role session a person holds is graded too", () => {
    const [e] = rows([getParams({ userIdentity: assumed() })]);
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("AssumedRole");
  });

  it("without decryption it is unchanged", () => {
    const [e] = rows([getParams({ requestParameters: { names: ["/app/flag"], withDecryption: false } })]);
    expect(e.severity).toBe("Info");
    expect(e.description).not.toContain("with decryption");
  });

  it("AWS-service, workload and instance-role callers are not graded", () => {
    const callers = [
      getParams({ userIdentity: { ...iamUser, invokedBy: "cloudformation.amazonaws.com" } }),
      getParams({ userIdentity: { ...iamUser, invokedByDelegate: { accountId: "222222222222" } } }),
      getParams({
        userIdentity: assumed({
          inScopeOf: {
            issuerType: "AWS::Lambda::Function",
            credentialsIssuedTo: "arn:aws:lambda:us-east-1:111111111111:function:f",
          },
        }),
      }),
      getParams({ userIdentity: assumed({}, { ec2RoleDelivery: "2.0" }) }),
      getParams({
        userIdentity: assumed(
          {},
          {
            sessionIssuer: {
              type: "Role",
              principalId: "AROAEXAMPLE000000009",
              arn: "arn:aws:iam::111111111111:role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM",
              accountId: "111111111111",
              userName: "AWSServiceRoleForAmazonSSM",
            },
          },
        ),
      }),
      getParams({
        userIdentity: { type: "AWSService", invokedBy: "ssm.amazonaws.com" },
        sourceIPAddress: "ssm.amazonaws.com",
      }),
    ];
    for (const r of callers) expect(rows([r])[0].severity).toBe("Info");
  });

  it("a denied read is not the completed signal", () => {
    const [e] = rows([getParams({ errorCode: "AccessDenied", errorMessage: "not authorized" })]);
    expect(e.description).not.toContain("with decryption");
    expect(e.mitreTechniques ?? []).not.toContain("T1552");
  });

  it("with and without decryption never fold into one row, in either order", () => {
    const plain = getParams({
      requestParameters: {
        names: ["/credentials/db-password", "/credentials/api-key"],
        withDecryption: false,
      },
    });
    for (const order of [
      [plain, getParams()],
      [getParams(), plain],
    ]) {
      expect(
        rows(order)
          .map((e) => e.severity)
          .sort(),
      ).toEqual(["Info", "Medium"]);
    }
  });
});
