// #2338 — ModifySnapshotAttribute is graded on what the request does, not on the event name alone:
// a request whose ONLY effect is removing sharing drops to Low; every share, an unreadable or
// missing request, and anything the reader cannot positively establish stays High. PutBucketAcl is
// unchanged; PutBucketPolicy is graded by its principals since #2542 (below).
import { describe, it, expect } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { awsExposureGrade } from "../../src/analysis/awsExposure.js";

const base = {
  eventTime: "2026-01-01T00:00:00Z",
  eventSource: "ec2.amazonaws.com",
  eventName: "ModifySnapshotAttribute",
  readOnly: false,
  userIdentity: { type: "IAMUser", userName: "alice", accountId: "111122223333" },
  sourceIPAddress: "198.51.100.7",
  awsRegion: "us-east-1",
  recipientAccountId: "111122223333",
};
const snapReq = (perm: unknown) => ({
  snapshotId: "snap-0123456789abcdef0",
  attributeType: "CREATE_VOLUME_PERMISSION",
  createVolumePermission: perm,
});
const grade = (over: Record<string, unknown>): string =>
  parseCloudTrail(JSON.stringify({ Records: [{ ...base, ...over }] })).events[0].severity;

describe("ModifySnapshotAttribute grading (#2338)", () => {
  it("grades a removal-only request Low", () => {
    expect(grade({ requestParameters: snapReq({ remove: { items: [{ userId: "444455556666" }] } }) })).toBe(
      "Low",
    );
    expect(grade({ requestParameters: snapReq({ remove: { items: [{ group: "all" }] } }) })).toBe("Low");
  });

  it("keeps High for a share with an account or the world", () => {
    expect(grade({ requestParameters: snapReq({ add: { items: [{ userId: "444455556666" }] } }) })).toBe(
      "High",
    );
    expect(grade({ requestParameters: snapReq({ add: { items: [{ group: "all" }] } }) })).toBe("High");
  });

  it("keeps High when a request both adds and removes", () => {
    const perm = { add: { items: [{ userId: "444455556666" }] }, remove: { items: [{ group: "all" }] } };
    expect(grade({ requestParameters: snapReq(perm) })).toBe("High");
  });

  it("keeps High for missing, empty or unreadable request parameters", () => {
    expect(grade({})).toBe("High");
    expect(grade({ requestParameters: null })).toBe("High");
    expect(grade({ requestParameters: snapReq(undefined) })).toBe("High");
    expect(grade({ requestParameters: snapReq({ remove: { items: [] } }) })).toBe("High");
    // an add side present in a shape the reader does not understand is unknown, not "no add"
    expect(
      grade({
        requestParameters: snapReq({ add: { items: [{ odd: "x" }] }, remove: { items: [{ userId: "1" }] } }),
      }),
    ).toBe("High");
    expect(
      grade({ requestParameters: snapReq({ add: "weird", remove: { items: [{ userId: "1" }] } }) }),
    ).toBe("High");
    // a removal item the reader cannot read is unknown too
    expect(grade({ requestParameters: snapReq({ remove: { items: [{ odd: "x" }] } }) })).toBe("High");
  });

  it("keeps the failed-call floor: a failed removal is Medium", () => {
    const r = grade({
      requestParameters: snapReq({ remove: { items: [{ userId: "444455556666" }] } }),
      errorCode: "UnauthorizedOperation",
    });
    expect(r).toBe("Medium");
  });

  it("keeps the root floor: a root removal is Medium", () => {
    const r = grade({
      requestParameters: snapReq({ remove: { items: [{ userId: "444455556666" }] } }),
      userIdentity: { type: "Root", arn: "arn:aws:iam::111122223333:root", accountId: "111122223333" },
    });
    expect(r).toBe("Medium");
  });

  it("leaves PutBucketAcl alone, and keeps an empty bucket policy High", () => {
    expect(awsExposureGrade("PutBucketPolicy", { bucketName: "b", bucketPolicy: { Statement: [] } })).toBe(
      undefined,
    );
    expect(awsExposureGrade("PutBucketAcl", { bucketName: "b", "x-amz-acl": "private" })).toBe(undefined);
    const policy = grade({
      eventName: "PutBucketPolicy",
      eventSource: "s3.amazonaws.com",
      requestParameters: { bucketName: "b", bucketPolicy: { Statement: [] } },
    });
    expect(policy).toBe("High");
  });
});

// #2542 (user decision Q3), reversing the #2345 deferral: a bucket policy is graded on who it lets in.
// Medium only when every Allow principal is an AWS service or the bucket's own account; an outside
// account, `*` or a policy the reader cannot positively read stays High.
describe("PutBucketPolicy grading by content (#2542)", () => {
  const policyGrade = (bucketPolicy: unknown, over: Record<string, unknown> = {}): string =>
    grade({
      eventName: "PutBucketPolicy",
      eventSource: "s3.amazonaws.com",
      requestParameters: { bucketName: "example-log", bucketPolicy },
      ...over,
    });
  const allow = (principal: unknown, extra: Record<string, unknown> = {}) => ({
    Statement: [{ Effect: "Allow", Principal: principal, Action: "s3:PutObject", ...extra }],
  });

  it("grades a policy for AWS service principals or this account Medium", () => {
    expect(policyGrade(allow({ Service: "cloudtrail.amazonaws.com" }))).toBe("Medium");
    expect(policyGrade(allow({ AWS: "arn:aws:iam::111122223333:role/Backup" }))).toBe("Medium");
    expect(
      policyGrade(JSON.stringify(allow({ Service: ["logs.amazonaws.com", "cloudtrail.amazonaws.com"] }))),
    ).toBe("Medium");
  });

  it("keeps High for an outside account, `*`, a federated principal or NotPrincipal", () => {
    expect(policyGrade(allow({ AWS: "444455556666" }))).toBe("High");
    expect(policyGrade(allow("*"))).toBe("High");
    expect(
      policyGrade(
        allow({ AWS: "*" }, { Condition: { StringEquals: { "aws:SourceAccount": "111122223333" } } }),
      ),
    ).toBe("High");
    expect(policyGrade(allow({ Federated: "cognito-identity.amazonaws.com" }))).toBe("High");
    expect(policyGrade({ Statement: [{ Effect: "Allow", NotPrincipal: { AWS: "111122223333" } }] })).toBe(
      "High",
    );
    // one trusted statement does not excuse an outside one
    expect(
      policyGrade({
        Statement: [
          { Effect: "Allow", Principal: { Service: "cloudtrail.amazonaws.com" } },
          { Effect: "Allow", Principal: { AWS: "444455556666" } },
        ],
      }),
    ).toBe("High");
  });

  it("keeps High for an unreadable or truncated policy, or with no recipient account", () => {
    expect(
      policyGrade('{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"'),
    ).toBe("High");
    expect(policyGrade(undefined)).toBe("High");
    expect(
      policyGrade(allow({ Service: "cloudtrail.amazonaws.com" }), { recipientAccountId: undefined }),
    ).toBe("High");
  });

  it("keeps the failed-call and root floors on a trusted policy", () => {
    expect(policyGrade(allow({ Service: "cloudtrail.amazonaws.com" }), { errorCode: "AccessDenied" })).toBe(
      "Medium",
    );
    const root = { type: "Root", arn: "arn:aws:iam::111122223333:root", accountId: "111122223333" };
    expect(policyGrade(allow({ Service: "cloudtrail.amazonaws.com" }), { userIdentity: root })).toBe(
      "Medium",
    );
  });

  it("says what the policy grants on the row", () => {
    const [row] = parseCloudTrail(
      JSON.stringify({
        Records: [
          {
            ...base,
            eventName: "PutBucketPolicy",
            eventSource: "s3.amazonaws.com",
            requestParameters: {
              bucketName: "example-log",
              bucketPolicy: allow({ Service: "cloudtrail.amazonaws.com" }),
            },
          },
        ],
      }),
    ).events;
    expect(row.description).toMatch(
      /bucket example-log policy grants only AWS services \(cloudtrail\.amazonaws\.com\)/,
    );
  });
});

// #2611 — the EBS snapshot share and S3 bucket exposure readings join the CloudTrail row key the way
// the #2605 readings do: different recipients or grants by the same caller stay on separate rows,
// while repeated identical calls still fold into one counted row.
describe("EBS snapshot and S3 exposure rows do not fold different recipients (#2611)", () => {
  const ACCT_A = "111111111111";
  const ACCT_B = "222222222222";
  const parse = (records: Record<string, unknown>[]) =>
    parseCloudTrail(JSON.stringify({ Records: records.map((r) => ({ ...base, ...r })) })).events;
  const share = (acct: string, minute: number) => ({
    eventTime: `2026-01-01T00:0${minute}:00Z`,
    requestParameters: snapReq({ add: { items: [{ userId: acct }] } }),
  });

  it("keeps two snapshot shares to different accounts on two rows, each naming its recipient", () => {
    const events = parse([share(ACCT_A, 0), share(ACCT_B, 1)]);
    expect(events).toHaveLength(2);
    expect(events.some((e) => e.description.includes(ACCT_A))).toBe(true);
    expect(events.some((e) => e.description.includes(ACCT_B))).toBe(true);
  });

  it("still folds a repeated identical snapshot share into one counted row", () => {
    const events = parse([share(ACCT_A, 0), share(ACCT_A, 1)]);
    expect(events).toHaveLength(1);
    expect(events[0].count).toBe(2);
  });

  const s3 = { eventSource: "s3.amazonaws.com" };
  const policyTo = (principal: unknown, minute: number) => ({
    ...s3,
    eventName: "PutBucketPolicy",
    eventTime: `2026-01-01T00:0${minute}:00Z`,
    requestParameters: {
      bucketName: "loot",
      bucketPolicy: { Statement: [{ Effect: "Allow", Principal: principal, Action: "s3:GetObject" }] },
    },
  });
  const aclGrant = (header: string, minute: number) => ({
    ...s3,
    eventName: "PutBucketAcl",
    eventTime: `2026-01-01T00:0${minute}:00Z`,
    requestParameters: {
      bucketName: "loot",
      [header]: 'uri="http://acs.amazonaws.com/groups/global/AllUsers"',
    },
  });

  it("keeps two bucket policies granting different principals on separate rows", () => {
    const events = parse([
      policyTo({ AWS: `arn:aws:iam::${ACCT_A}:root` }, 0),
      policyTo({ AWS: `arn:aws:iam::${ACCT_B}:root` }, 1),
    ]);
    expect(events).toHaveLength(2);
  });

  it("keeps two bucket ACLs with different grants on separate rows", () => {
    const events = parse([aclGrant("x-amz-grant-read", 0), aclGrant("x-amz-grant-full-control", 1)]);
    expect(events).toHaveLength(2);
  });

  it("still folds a repeated identical bucket policy into one counted row", () => {
    const events = parse([policyTo("*", 0), policyTo("*", 1)]);
    expect(events).toHaveLength(1);
    expect(events[0].count).toBe(2);
  });
});
