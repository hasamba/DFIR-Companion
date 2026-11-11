// #2542 (user decision Q1): a bucket-recovery check — GetBucketVersioning,
// GetBucketObjectLockConfiguration, PutBucketVersioning (Suspended) — is raised to High only when the
// same access key made a successful privileged change earlier in the same upload.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";

const ACCT = "111122223333";
const KEY = "AKIAEXAMPLEPRECURS01";
const OTHER_KEY = "AKIAEXAMPLEPRECURS02";
const user = (key = KEY) => ({
  type: "IAMUser",
  principalId: "AIDAEXAMPLE",
  arn: `arn:aws:iam::${ACCT}:user/dev-user`,
  accountId: ACCT,
  accessKeyId: key,
  userName: "dev-user",
});
let n = 0;
const rec = (time: string, eventSource: string, eventName: string, over: Record<string, unknown> = {}) => ({
  eventVersion: "1.08",
  eventTime: `2024-05-01T${time}Z`,
  eventSource: `${eventSource}.amazonaws.com`,
  eventName,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.9",
  userAgent: "aws-cli/2.15",
  readOnly: true,
  recipientAccountId: ACCT,
  eventID: `evt-precursor-${++n}`,
  userIdentity: user(),
  ...over,
});
const selfGrant = (time: string, over: Record<string, unknown> = {}) =>
  rec(time, "iam", "PutUserPolicy", {
    readOnly: false,
    requestParameters: {
      userName: "dev-user",
      policyName: "p",
      policyDocument:
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
    },
    ...over,
  });
const newKey = (time: string) =>
  rec(time, "iam", "CreateAccessKey", {
    readOnly: false,
    requestParameters: { userName: "dev-user" },
    responseElements: { accessKey: { userName: "dev-user", accessKeyId: OTHER_KEY, status: "Active" } },
  });
const check = (time: string, name = "GetBucketVersioning", over: Record<string, unknown> = {}) =>
  rec(time, "s3", name, { requestParameters: { bucketName: "example-eng" }, ...over });
const suspend = (time: string, status: string) =>
  rec(time, "s3", "PutBucketVersioning", {
    readOnly: false,
    requestParameters: { bucketName: "example-eng", VersioningConfiguration: { Status: status } },
  });

const graded = (...records: object[]) =>
  parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false }).events.filter(
    (e) => e.canonical?.event.type === "api" && /Bucket/.test(e.canonical.event.action ?? ""),
  );

describe("S3 ransomware precursors (#2542, Q1)", () => {
  it("raises the two recovery checks after the same key granted itself a policy", () => {
    const rows = graded(
      selfGrant("10:00:00"),
      check("11:00:00"),
      check("11:00:01", "GetBucketObjectLockConfiguration"),
    );
    expect(rows).toHaveLength(2);
    for (const r of rows) {
      expect(r.severity).toBe("High");
      expect(r.description).toContain("ransomware precursor");
      expect(r.description).toContain("granted to the caller itself");
    }
  });
  it("raises a check after the same key created an access key", () => {
    expect(graded(newKey("10:00:00"), check("10:30:00"))[0].severity).toBe("High");
  });
  it("leaves a check alone with no change, a change after it, another key's change, or a failed change", () => {
    expect(graded(check("11:00:00"))[0].severity).toBe("Info");
    // File order says the change came first; eventTime says it came after — eventTime wins.
    expect(graded(selfGrant("12:00:00"), check("11:00:00"))[0].severity).toBe("Info");
    expect(
      graded(
        selfGrant("10:00:00", {
          userIdentity: user(OTHER_KEY),
          requestParameters: {
            userName: "dev-user",
            policyName: "p",
            policyDocument: '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
          },
        }),
        check("11:00:00"),
      )[0].severity,
    ).toBe("Info");
    expect(graded(selfGrant("10:00:00", { errorCode: "AccessDenied" }), check("11:00:00"))[0].severity).toBe(
      "Info",
    );
  });
  it("does not count a policy put on another user as a self grant", () => {
    const other = selfGrant("10:00:00", {
      requestParameters: { userName: "someone-else", policyName: "p", policyDocument: '{"Statement":[]}' },
    });
    expect(graded(other, check("11:00:00"))[0].severity).toBe("Info");
  });
  it("raises versioning being suspended, never enabled", () => {
    const [suspended] = graded(selfGrant("10:00:00"), suspend("11:00:00", "Suspended"));
    expect(suspended.severity).toBe("High");
    const [enabled] = graded(selfGrant("10:00:00"), suspend("11:00:00", "Enabled"));
    expect(enabled.description).not.toContain("ransomware precursor");
  });
  it("keeps a raised check apart from the same call made before the change when aggregating", () => {
    const records = [check("09:00:00"), selfGrant("10:00:00"), check("11:00:00")];
    const rows = parseCloudTrail(JSON.stringify({ Records: records })).events.filter(
      (e) => e.canonical?.event.action === "GetBucketVersioning",
    );
    expect(rows.map((r) => r.severity).sort()).toEqual(["High", "Info"]);
  });
});
