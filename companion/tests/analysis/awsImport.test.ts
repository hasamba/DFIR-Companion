import { describe, it, expect } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";

function record(over: object): object {
  return {
    eventTime: "2023-06-01T10:00:00Z",
    eventSource: "iam.amazonaws.com",
    eventName: "GetUser",
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.10",
    userAgent: "aws-cli/2.0",
    readOnly: true,
    eventType: "AwsApiCall",
    userIdentity: { type: "IAMUser", userName: "bob", arn: "arn:aws:iam::123:user/bob", accountId: "123" },
    ...over,
  };
}
function envelope(...recs: object[]): string {
  return JSON.stringify({ Records: recs });
}

describe("parseCloudTrail — action-derived severity", () => {
  it("reads the { Records: [...] } envelope and derives High for CreateAccessKey", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "CreateAccessKey", readOnly: false })));
    expect(r.format).toBe("cloudtrail");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("AWS CreateAccessKey (iam)");
    expect(e.description).toContain("by bob");
    expect(e.description).toContain("from 203.0.113.10");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.001");
    expect(e.sources).toEqual(["AWS CloudTrail"]);
    expect(e.timestamp).toBe("2023-06-01T10:00:00Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.10");
  });

  it("High for disabling CloudTrail logging (defense evasion)", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "StopLogging", eventSource: "cloudtrail.amazonaws.com", readOnly: false })));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1562.008");
  });

  it("read-only Describe/Get with no verdict stays Info", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com" })));
    expect(r.events[0].severity).toBe("Info");
  });

  it("a denied call (errorCode) is bumped to at least Medium", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com", errorCode: "Client.UnauthorizedOperation" })));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[Client.UnauthorizedOperation]");
  });

  it("grades iam:PassRole and Lambda CreateFunction (priv-esc primitives) as Medium", () => {
    const pass = parseCloudTrail(envelope(record({ eventName: "PassRole", readOnly: false })));
    expect(pass.events[0].severity).toBe("Medium");
    expect(pass.events[0].mitreTechniques).toContain("T1098");
    const fn = parseCloudTrail(envelope(record({ eventName: "CreateFunction", eventSource: "lambda.amazonaws.com", readOnly: false })));
    expect(fn.events[0].severity).toBe("Medium");
    expect(fn.events[0].mitreTechniques).toContain("T1648");
  });

  it("grades STS GetSessionToken as Low with T1078.004", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "GetSessionToken", eventSource: "sts.amazonaws.com", readOnly: false })));
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].mitreTechniques).toContain("T1078.004");
  });
});

describe("parseCloudTrail — console login & root", () => {
  it("a failed ConsoleLogin is Medium (brute force)", () => {
    const r = parseCloudTrail(envelope(record({
      eventName: "ConsoleLogin", eventSource: "signin.amazonaws.com", readOnly: false,
      responseElements: { ConsoleLogin: "Failure" }, errorMessage: "Failed authentication",
      userIdentity: { type: "IAMUser", userName: "bob" },
    })));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });

  it("a root console login is High and flagged [root]", () => {
    const r = parseCloudTrail(envelope(record({
      eventName: "ConsoleLogin", eventSource: "signin.amazonaws.com", readOnly: false,
      responseElements: { ConsoleLogin: "Success" }, userIdentity: { type: "Root", arn: "arn:aws:iam::123:root" },
    })));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toContain("[root]");
  });

  it("uses the assumed-role issuer as the principal", () => {
    const r = parseCloudTrail(envelope(record({
      eventName: "PutBucketPolicy", eventSource: "s3.amazonaws.com", readOnly: false,
      userIdentity: { type: "AssumedRole", sessionContext: { sessionIssuer: { userName: "AdminRole" } } },
    })));
    expect(r.events[0].description).toContain("by AdminRole");
    expect(r.events[0].severity).toBe("High");
  });
});

describe("parseCloudTrail — inputs, floor & edges", () => {
  it("reads NDJSON (CloudTrail Lake / Athena)", () => {
    const text = [record({ eventName: "CreateAccessKey", readOnly: false }), record({ eventName: "GetCallerIdentity" })]
      .map((o) => JSON.stringify(o)).join("\n");
    const r = parseCloudTrail(text);
    expect(r.format).toBe("cloudtrail");
    expect(r.events).toHaveLength(2);
  });

  it("does not turn an AWS-service caller into an IP IOC", () => {
    const r = parseCloudTrail(envelope(record({ eventName: "RunInstances", eventSource: "ec2.amazonaws.com", sourceIPAddress: "ec2.amazonaws.com", readOnly: false })));
    expect(r.iocs.filter((i) => i.type === "ip")).toHaveLength(0);
  });

  it("applies a severity floor", () => {
    const text = envelope(
      record({ eventName: "CreateAccessKey", readOnly: false }),       // High
      record({ eventName: "DescribeInstances", eventSource: "ec2.amazonaws.com" }), // Info
    );
    const r = parseCloudTrail(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });

  it("reports empty for a non-CloudTrail file", () => {
    const r = parseCloudTrail(JSON.stringify({ foo: "bar" }));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});
