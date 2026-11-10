// #2542 (user decision Q2): CloudTrail withholds a bundled rule's ATT&CK technique only where its own
// reading proves the technique does not apply — and keeps it everywhere else. The grade never moves.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import {
  cloudTrailTagVeto,
  loneFailedSignIns,
  withholdTechniques,
} from "../../src/analysis/cloudTrailTagVeto.js";
import { trustedOnlyGrant } from "../../src/analysis/awsPolicyPrincipals.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

const OWN = "111122223333";
const OUTSIDE = "444455556666";
const sigma = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();

type Rec = Record<string, unknown>;
const user: Rec = {
  type: "IAMUser",
  arn: `arn:aws:iam::${OWN}:user/alice`,
  accountId: OWN,
  userName: "alice",
  accessKeyId: "AKIAEXAMPLEALICE0001",
};
const rec = (over: Rec): Rec => ({
  eventVersion: "1.08",
  eventTime: "2026-01-01T00:00:00Z",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.0",
  userIdentity: user,
  readOnly: false,
  recipientAccountId: OWN,
  eventID: `id-${Math.random().toString(36).slice(2)}`,
  ...over,
});
const parse = (...records: Rec[]) =>
  parseCloudTrail(JSON.stringify({ Records: records }), { sigma, aggregate: false }).events;
const has = (techniques: string[], t: string): boolean =>
  techniques.some((m) => m === t || m.startsWith(`${t}.`));

const bucketPolicy = (principal: unknown, extra: Rec = {}): Rec =>
  rec({
    eventSource: "s3.amazonaws.com",
    eventName: "PutBucketPolicy",
    requestParameters: {
      bucketName: "example-log",
      bucketPolicy: { Statement: [{ Effect: "Allow", Principal: principal, Action: "s3:*", ...extra }] },
    },
  });
const putObject = (who: Rec): Rec =>
  rec({
    eventSource: "s3.amazonaws.com",
    eventName: "PutObject",
    userIdentity: who,
    requestParameters: { bucketName: "example-log", key: "AWSLogs/x.json.gz" },
    eventCategory: "Data",
  });
const keyPolicy = (statements: Rec[]): string => JSON.stringify({ Statement: statements });
const trailStatement: Rec = {
  Effect: "Allow",
  Principal: { Service: "cloudtrail.amazonaws.com" },
  Action: "kms:GenerateDataKey*",
};
const createKey = (policy: string | undefined, origin = "AWS_KMS"): Rec =>
  rec({
    eventSource: "kms.amazonaws.com",
    eventName: "CreateKey",
    requestParameters: { origin, keyUsage: "ENCRYPT_DECRYPT", ...(policy ? { policy } : {}) },
  });
const login = (time: string, ok: boolean, ip = "198.51.100.7", who: Rec = user): Rec =>
  rec({
    eventTime: time,
    eventSource: "signin.amazonaws.com",
    eventName: "ConsoleLogin",
    eventType: "AwsConsoleSignIn",
    sourceIPAddress: ip,
    userIdentity: { ...who, accessKeyId: "" },
    responseElements: { ConsoleLogin: ok ? "Success" : "Failure" },
    ...(ok ? {} : { errorMessage: "Failed authentication" }),
  });

describe("trustedOnlyGrant", () => {
  const doc = (...statements: Rec[]) => ({ Statement: statements });
  it("accepts service principals and the owner account, by id or ARN", () => {
    expect(
      trustedOnlyGrant(doc({ Effect: "Allow", Principal: { Service: "cloudtrail.amazonaws.com" } }), OWN),
    ).toEqual({
      services: ["cloudtrail.amazonaws.com"],
      ownAccount: false,
    });
    expect(
      trustedOnlyGrant(
        doc({ Effect: "Allow", Principal: { AWS: [OWN, `arn:aws:iam::${OWN}:role/r`] } }),
        OWN,
      ),
    ).toEqual({ services: [], ownAccount: true });
  });

  it("ignores Deny statements but needs at least one Allow", () => {
    expect(trustedOnlyGrant(doc({ Effect: "Deny", Principal: "*" }), OWN)).toBeNull();
    expect(
      trustedOnlyGrant(
        doc(
          { Effect: "Deny", Principal: "*" },
          { Effect: "Allow", Principal: { Service: "logs.amazonaws.com" } },
        ),
        OWN,
      ),
    ).not.toBeNull();
  });

  it("refuses anything it cannot positively read", () => {
    for (const principal of [
      "*",
      { AWS: "*" },
      { AWS: OUTSIDE },
      { AWS: `arn:aws:iam::${OUTSIDE}:root` },
      { Federated: "cognito-identity.amazonaws.com" },
      { CanonicalUser: "abc" },
      { Service: "evil.example.com" },
      {},
    ])
      expect(
        trustedOnlyGrant(doc({ Effect: "Allow", Principal: principal }), OWN),
        JSON.stringify(principal),
      ).toBeNull();
    expect(trustedOnlyGrant(doc({ Effect: "Allow", NotPrincipal: { AWS: OWN } }), OWN)).toBeNull();
    expect(trustedOnlyGrant("{not json", OWN)).toBeNull();
    expect(trustedOnlyGrant(doc({ Effect: "Allow", Principal: { AWS: OWN } }), "")).toBeNull();
  });

  it("counts a `*` held to the owner account only when asked to", () => {
    const held = doc({
      Effect: "Allow",
      Principal: { AWS: "*" },
      Condition: { StringEquals: { "kms:CallerAccount": OWN } },
    });
    expect(trustedOnlyGrant(held, OWN)).toBeNull();
    expect(trustedOnlyGrant(held, OWN, { starHeldToAccount: true })).toEqual({
      services: [],
      ownAccount: true,
    });
    const elsewhere = doc({
      Effect: "Allow",
      Principal: "*",
      Condition: { StringEquals: { "kms:CallerAccount": OUTSIDE } },
    });
    expect(trustedOnlyGrant(elsewhere, OWN, { starHeldToAccount: true })).toBeNull();
  });
});

describe("loneFailedSignIns", () => {
  it("marks a single failure followed by a same-source success", () => {
    expect([
      ...loneFailedSignIns([login("2026-01-01T00:00:00Z", false), login("2026-01-01T00:00:43Z", true)]),
    ]).toEqual([0]);
  });

  it("does not mark repeated failures, a failure with no success, or a success from elsewhere", () => {
    const three = [0, 10, 20].map((s) => login(`2026-01-01T00:00:${String(s).padStart(2, "0")}Z`, false));
    expect(loneFailedSignIns([...three, login("2026-01-01T00:00:40Z", true)]).size).toBe(0);
    expect(loneFailedSignIns([login("2026-01-01T00:00:00Z", false)]).size).toBe(0);
    expect(
      loneFailedSignIns([
        login("2026-01-01T00:00:00Z", false),
        login("2026-01-01T00:00:43Z", true, "203.0.113.9"),
      ]).size,
    ).toBe(0);
    expect(
      loneFailedSignIns([login("2026-01-01T00:00:00Z", false), login("2026-01-01T00:30:00Z", true)]).size,
    ).toBe(0);
  });

  it("counts a failure for another user from the same source (spraying keeps T1110)", () => {
    const bob = { ...user, arn: `arn:aws:iam::${OWN}:user/bob`, userName: "bob" };
    const records = [
      login("2026-01-01T00:00:00Z", false, undefined, bob),
      login("2026-01-01T00:00:10Z", false),
      login("2026-01-01T00:00:43Z", true),
    ];
    expect(loneFailedSignIns(records).size).toBe(0);
  });
});

describe("withholdTechniques", () => {
  const event = {
    mitre: ["T1530", "T1565.001", "T1565"],
    message: "m",
    aggKey: "k",
  } as unknown as MappedEvent;
  it("removes the technique and its sub-techniques, adds a note and keeps the grade fields", () => {
    const out = withholdTechniques(
      { ...event, severity: "Low" },
      {
        techniques: ["T1565"],
        reason: "r",
      },
    );
    expect(out.mitre).toEqual(["T1530"]);
    expect(out.severity).toBe("Low");
    expect(out.message).toMatch(/ATT&CK T1565\.001 withheld — r/);
    expect(out.aggKey).not.toBe("k");
  });

  it("leaves a row without the technique untouched", () => {
    expect(withholdTechniques(event, { techniques: ["T1110"], reason: "r" })).toBe(event);
    expect(withholdTechniques(event, undefined)).toBe(event);
  });

  it("vetoes nothing for a record no rule covers", () => {
    expect(
      cloudTrailTagVeto(rec({ eventSource: "s3.amazonaws.com", eventName: "GetObject" }), false),
    ).toBeUndefined();
    expect(cloudTrailTagVeto(undefined, true)).toBeUndefined();
  });
});

describe("through the importer with the bundled rules", () => {
  it("T1565: an AWS service's object write loses it; a user's object write keeps it", () => {
    const [service] = parse(putObject({ type: "AWSService", invokedBy: "cloudtrail.amazonaws.com" }));
    expect(has(service.mitreTechniques, "T1565")).toBe(false);
    const [person] = parse(putObject(user));
    expect(has(person.mitreTechniques, "T1565")).toBe(true);
  });

  it("T1486: the CloudTrail log key loses it; an outside principal, EXTERNAL origin or no policy keeps it", () => {
    const own = { Effect: "Allow", Principal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: "kms:*" };
    const [logKey] = parse(createKey(keyPolicy([own, trailStatement])));
    expect(has(logKey.mitreTechniques, "T1486")).toBe(false);
    const outside = { ...own, Principal: { AWS: `arn:aws:iam::${OUTSIDE}:root` } };
    const kept = [
      createKey(keyPolicy([outside, trailStatement])),
      createKey(keyPolicy([own, trailStatement]), "EXTERNAL"),
      createKey(undefined),
      createKey(keyPolicy([own])), // no CloudTrail grant: not the trail's log key
    ];
    for (const r of kept) expect(has(parse(r)[0].mitreTechniques, "T1486"), JSON.stringify(r)).toBe(true);
  });

  it("T1048: a service-only bucket policy loses it and is Medium; an outside account keeps it and High", () => {
    const [trusted] = parse(bucketPolicy({ Service: "delivery.logs.amazonaws.com" }));
    expect(trusted.severity).toBe("Medium");
    expect(has(trusted.mitreTechniques, "T1048")).toBe(false);
    const [outside] = parse(bucketPolicy({ AWS: `arn:aws:iam::${OUTSIDE}:root` }));
    expect(outside.severity).toBe("High");
    expect(has(outside.mitreTechniques, "T1048")).toBe(true);
    expect(outside.mitreTechniques).toContain("T1530");
  });

  it("T1110: a lone failure before a success loses it at the same grade; three failures keep it", () => {
    const lone = parse(login("2026-01-01T00:00:00Z", false), login("2026-01-01T00:00:43Z", true));
    const failed = lone.find((e) => e.canonical?.event.outcome === "failed")!;
    expect(failed.mitreTechniques).not.toContain("T1110");
    expect(failed.severity).toBe("Medium");
    const burst = parse(
      login("2026-01-01T00:00:00Z", false),
      login("2026-01-01T00:00:10Z", false),
      login("2026-01-01T00:00:20Z", false),
      login("2026-01-01T00:00:43Z", true),
    );
    for (const e of burst.filter((r) => r.canonical?.event.outcome === "failed"))
      expect(e.mitreTechniques).toContain("T1110");
  });
});
