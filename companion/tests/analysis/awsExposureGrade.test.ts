// #2338 — ModifySnapshotAttribute is graded on what the request does, not on the event name alone:
// a request whose ONLY effect is removing sharing drops to Low; every share, an unreadable or
// missing request, and anything the reader cannot positively establish stays High. PutBucketAcl /
// PutBucketPolicy are unchanged here (deferred to #2345).
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

  it("leaves PutBucketAcl / PutBucketPolicy alone (deferred to #2345)", () => {
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
