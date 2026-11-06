import { describe, expect, it } from "vitest";
import { runAwsReadCheck } from "../../../src/integrations/cloudCheck/awsReadCheck.js";
import { checkSummary } from "../../../src/integrations/cloudCheck/readCheckWording.js";
import { ALLOWED_AWS_COMMANDS, AWS_ALL_OK, awsDenied, mockAws } from "./readCheckMocks.js";

// #2309: the AWS check signs in with GetCallerIdentity, then makes one read per selected source.

const BOTH = ["cloudtrail-lookup", "s3-trail"] as const;
const input = (extra: Record<string, unknown> = {}) => ({
  sources: [...BOTH],
  s3Bucket: "trail-bucket",
  secrets: [],
  ...extra,
});

describe("runAwsReadCheck", () => {
  it("#2363: tests ec2:DescribeRegions with one read and says what a failure costs", async () => {
    const ok = mockAws(AWS_ALL_OK);
    const out = await runAwsReadCheck(ok.clients, { sources: ["ec2-regions"], secrets: [] });
    expect(ok.sent).toEqual(["GetCallerIdentityCommand", "DescribeRegionsCommand"]);
    expect(out.results).toEqual([
      {
        id: "ec2-regions",
        label: "Enabled regions (ec2:DescribeRegions)",
        status: "succeeded",
        detail: "2 region(s) enabled on the account",
      },
    ]);
    const denied = mockAws({
      ...AWS_ALL_OK,
      DescribeRegionsCommand: awsDenied(
        "UnauthorizedOperation",
        "You are not authorized to perform this operation.",
      ),
    });
    const failed = await runAwsReadCheck(denied.clients, { sources: ["ec2-regions"], secrets: [] });
    expect(failed.results[0].status).toBe("failed");
    expect(failed.results[0].detail).toMatch(/UnauthorizedOperation/);
    expect(failed.results[0].detail).toMatch(/default region list and says so/);
  });

  it("reports both sources read when every call succeeds", async () => {
    const { clients, sent } = mockAws(AWS_ALL_OK);
    const out = await runAwsReadCheck(clients, input());
    expect(out.results.map((r) => r.status)).toEqual(["succeeded", "succeeded"]);
    expect(out.signedInAs).toBe("arn:aws:sts::123456789012:assumed-role/dfir-collector/check");
    expect(sent).toEqual([
      "GetCallerIdentityCommand",
      "LookupEventsCommand",
      "ListObjectsV2Command",
      "GetObjectCommand",
    ]);
    expect(checkSummary(out.results)).toBe(
      "Tested reads succeeded for: CloudTrail event history, CloudTrail S3 bucket. Failed: none. " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("reports a partial result when the trail file read is denied, with the KMS hint", async () => {
    const { clients } = mockAws({
      ...AWS_ALL_OK,
      GetObjectCommand: awsDenied("AccessDenied", "Access Denied"),
    });
    const out = await runAwsReadCheck(clients, input());
    expect(out.results[0].status).toBe("succeeded");
    expect(out.results[1].status).toBe("failed");
    expect(checkSummary(out.results)).toBe(
      "Tested reads succeeded for: CloudTrail event history. Failed: CloudTrail S3 bucket (listing worked, " +
        "reading a trail file failed: HTTP 403 AccessDenied: Access Denied; if the trail is KMS-encrypted, the " +
        "identity also needs kms:Decrypt on the trail key). " +
        "The companion did not test whether this identity can also write. Use the minimum policy.",
    );
  });

  it("fails every selected source when sign-in fails, and calls nothing else", async () => {
    const { clients, sent } = mockAws({
      GetCallerIdentityCommand: awsDenied("InvalidClientTokenId", "bad token"),
    });
    const out = await runAwsReadCheck(clients, input());
    expect(out.results.every((r) => r.status === "failed")).toBe(true);
    expect(out.results[0].detail).toBe("sign-in failed: HTTP 403 InvalidClientTokenId: bad token");
    expect(sent).toEqual(["GetCallerIdentityCommand"]);
    expect(checkSummary(out.results)).toMatch(
      /^Tested reads succeeded for: none\. Failed: CloudTrail event history/,
    );
  });

  it("does not count a sign-in alone as a success", async () => {
    const { clients } = mockAws({ GetCallerIdentityCommand: AWS_ALL_OK.GetCallerIdentityCommand });
    const out = await runAwsReadCheck(clients, input());
    expect(out.results.map((r) => r.status)).toEqual(["failed", "failed"]);
  });

  it("tests only the selected source", async () => {
    const { clients, sent } = mockAws(AWS_ALL_OK);
    const out = await runAwsReadCheck(clients, input({ sources: ["cloudtrail-lookup"] }));
    expect(out.results.map((r) => r.id)).toEqual(["cloudtrail-lookup"]);
    expect(sent).not.toContain("ListObjectsV2Command");
  });

  it("does not test S3 without a bucket, and lists under the default prefix with one", async () => {
    const { clients, sent } = mockAws(AWS_ALL_OK);
    const none = await runAwsReadCheck(clients, input({ s3Bucket: undefined, sources: ["s3-trail"] }));
    expect(none.results[0]).toMatchObject({
      status: "not-tested",
      detail: "name the trail bucket to test it",
    });
    expect(sent).toEqual(["GetCallerIdentityCommand"]);

    let listed: Record<string, unknown> = {};
    const rec = mockAws({
      ...AWS_ALL_OK,
      ListObjectsV2Command: (i) => ((listed = i), AWS_ALL_OK.ListObjectsV2Command(i)),
    });
    await runAwsReadCheck(rec.clients, input({ sources: ["s3-trail"] }));
    expect(listed).toEqual({ Bucket: "trail-bucket", Prefix: "AWSLogs/", MaxKeys: 1 });
  });

  it("reports an empty prefix as not tested, not as a failure", async () => {
    const { clients, sent } = mockAws({ ...AWS_ALL_OK, ListObjectsV2Command: () => ({ KeyCount: 0 }) });
    const out = await runAwsReadCheck(clients, input({ sources: ["s3-trail"], s3Prefix: "org/AWSLogs/" }));
    expect(out.results[0]).toMatchObject({
      status: "not-tested",
      detail: "listing org/AWSLogs/ worked, but it holds no file to test reading one",
    });
    expect(sent).not.toContain("GetObjectCommand");
  });

  it("cuts the account's secrets out of an error", async () => {
    const secret = "aws-secret-sentinel-41c7";
    const { clients } = mockAws({ ...AWS_ALL_OK, LookupEventsCommand: awsDenied("Boom", `echo ${secret}`) });
    const out = await runAwsReadCheck(clients, input({ secrets: [secret], sources: ["cloudtrail-lookup"] }));
    expect(JSON.stringify(out)).not.toContain(secret);
  });

  it("never sends a write or simulate command, whatever the answers", async () => {
    for (const answers of [
      AWS_ALL_OK,
      {},
      { GetCallerIdentityCommand: AWS_ALL_OK.GetCallerIdentityCommand },
    ]) {
      const { clients, sent } = mockAws(answers);
      await runAwsReadCheck(clients, input());
      for (const name of sent) expect(ALLOWED_AWS_COMMANDS.has(name), name).toBe(true);
    }
  });
});
