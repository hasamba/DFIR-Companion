// CloudTrail grading matches the event SOURCE together with the name (#2358). The action table used
// to key on the eventName alone, so a Transfer Family / WorkMail `CreateUser` was graded as IAM user
// creation, and the real Lambda name `CreateFunction20150331` (API-version suffix) never matched.
import { describe, it, expect } from "vitest";
import { AWS_ACTIONS, lookupAwsAction, parseCloudTrail } from "../../src/analysis/awsImport.js";

function record(eventSource: string, eventName: string, over: object = {}): object {
  return {
    eventTime: "2023-06-01T10:00:00Z",
    eventSource,
    eventName,
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.10",
    userAgent: "aws-cli/2.0",
    readOnly: false,
    eventType: "AwsApiCall",
    eventID: `${eventSource}-${eventName}`,
    recipientAccountId: "123456789012",
    userIdentity: {
      type: "IAMUser",
      userName: "bob",
      arn: "arn:aws:iam::123456789012:user/bob",
      accountId: "123456789012",
    },
    ...over,
  };
}

function grade(eventSource: string, eventName: string, over: object = {}) {
  const r = parseCloudTrail(JSON.stringify({ Records: [record(eventSource, eventName, over)] }));
  expect(r.events).toHaveLength(1);
  return r.events[0];
}

describe("lookupAwsAction — service + name (#2358)", () => {
  it("returns the entry for the service that owns the call", () => {
    expect(lookupAwsAction("iam.amazonaws.com", "CreateUser")).toBe(AWS_ACTIONS.createuser);
    expect(lookupAwsAction("IAM.amazonaws.com", "createuser")).toBe(AWS_ACTIONS.createuser);
    expect(lookupAwsAction("lambda.amazonaws.com", "CreateFunction")).toBe(AWS_ACTIONS.createfunction);
  });

  it("accepts the Lambda API-version suffixes CloudTrail records", () => {
    expect(lookupAwsAction("lambda.amazonaws.com", "CreateFunction20150331")).toBe(
      AWS_ACTIONS.createfunction,
    );
    expect(lookupAwsAction("lambda.amazonaws.com", "CreateFunction20150331v2")).toBe(
      AWS_ACTIONS.createfunction,
    );
  });

  it("does not strip a version suffix for any other service, or trailing junk on Lambda", () => {
    expect(lookupAwsAction("iam.amazonaws.com", "CreateUser20150331")).toBeUndefined();
    expect(lookupAwsAction("lambda.amazonaws.com", "CreateFunctionX")).toBeUndefined();
    expect(lookupAwsAction("lambda.amazonaws.com", "CreateFunction2015")).toBeUndefined();
  });

  it("returns nothing for the same name from another service", () => {
    for (const [source, name] of [
      ["transfer.amazonaws.com", "CreateUser"],
      ["workmail.amazonaws.com", "CreateUser"],
      ["identitystore.amazonaws.com", "CreateUser"],
      ["cloudfront.amazonaws.com", "CreateFunction"],
      ["appsync.amazonaws.com", "CreateFunction"],
      ["iot.amazonaws.com", "CreatePolicyVersion"],
      ["iot.amazonaws.com", "SetDefaultPolicyVersion"],
      ["frauddetector.amazonaws.com", "DeleteDetector"],
      ["lightsail.amazonaws.com", "ImportKeyPair"],
    ]) {
      expect(lookupAwsAction(source, name), `${source} ${name}`).toBeUndefined();
    }
  });

  it("every table entry names the services it is graded for", () => {
    for (const [name, def] of Object.entries(AWS_ACTIONS)) {
      expect(def.sources.length, name).toBeGreaterThan(0);
      for (const s of def.sources) expect(s, name).toMatch(/^[a-z0-9-]+$/);
    }
  });
});

describe("parseCloudTrail — graded by service + name (#2358)", () => {
  it("grades the real Lambda CreateFunction20150331 Medium with T1648", () => {
    for (const name of ["CreateFunction20150331", "CreateFunction20150331v2"]) {
      const e = grade("lambda.amazonaws.com", name, { requestParameters: { functionName: "f" } });
      expect(e.severity, name).toBe("Medium");
      expect(e.mitreTechniques, name).toContain("T1648");
    }
  });

  it("CloudFront / AppSync CreateFunction is a generic write, not Lambda execution", () => {
    for (const source of ["cloudfront.amazonaws.com", "appsync.amazonaws.com"]) {
      const e = grade(source, "CreateFunction");
      expect(e.severity, source).toBe("Low");
      expect(e.mitreTechniques ?? [], source).not.toContain("T1648");
    }
  });

  it("grades IAM CreateUser Medium with T1136.003 and leaves look-alike services at the write floor", () => {
    const iam = grade("iam.amazonaws.com", "CreateUser", { requestParameters: { userName: "u" } });
    expect(iam.severity).toBe("Medium");
    expect(iam.mitreTechniques).toContain("T1136.003");
    for (const source of [
      "transfer.amazonaws.com",
      "workmail.amazonaws.com",
      "identitystore.amazonaws.com",
    ]) {
      const e = grade(source, "CreateUser");
      expect(e.severity, source).toBe("Low");
      expect(e.mitreTechniques ?? [], source).not.toContain("T1136.003");
    }
  });

  it("a read-only look-alike stays Info, and a denied look-alike keeps only the generic failure grade", () => {
    expect(grade("workmail.amazonaws.com", "CreateUser", { readOnly: true }).severity).toBe("Info");
    const denied = grade("transfer.amazonaws.com", "CreateUser", { errorCode: "AccessDenied" });
    const deniedProbe = grade("transfer.amazonaws.com", "DetectionProbe", { errorCode: "AccessDenied" });
    expect(denied.severity).toBe(deniedProbe.severity);
    expect(denied.mitreTechniques ?? []).not.toContain("T1136.003");
  });

  it("other name collisions are not graded as the IAM / GuardDuty / EC2 call", () => {
    expect(grade("iot.amazonaws.com", "CreatePolicyVersion").severity).toBe("Low");
    expect(grade("iot.amazonaws.com", "SetDefaultPolicyVersion").severity).toBe("Low");
    expect(grade("frauddetector.amazonaws.com", "DeleteDetector").severity).toBe("Low");
    expect(grade("lightsail.amazonaws.com", "ImportKeyPair").severity).toBe("Low");
    // …while the owning service keeps its grade.
    expect(grade("guardduty.amazonaws.com", "DeleteDetector").severity).toBe("High");
    expect(grade("ec2.amazonaws.com", "ImportKeyPair").severity).toBe("Medium");
  });
});
