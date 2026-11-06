import { describe, it, expect } from "vitest";
import { cloudTrailSummaries, parseCloudTrail } from "../../src/analysis/awsImport.js";

// #2362 — the streamed import's summary rows come from cloudTrailSummaries, which skips mapping the
// summary window. It must return exactly what the full parse of that window returned after its
// source rows — `parseCloudTrail("", { records }).events.slice(kept)` — at every boundary.

type Rec = Record<string, unknown>;
const ACCT = "123456789012";

const rec = (i: number, over: Rec = {}): Rec => ({
  eventVersion: "1.09",
  eventTime: `2026-11-01T00:${String(i % 60).padStart(2, "0")}:00Z`,
  eventSource: "ec2.amazonaws.com",
  eventName: "DescribeInstances",
  awsRegion: "us-east-1",
  sourceIPAddress: `198.51.100.${(i % 9) + 1}`,
  recipientAccountId: ACCT,
  eventID: `evt-${i}`,
  readOnly: true,
  userIdentity: {
    type: "IAMUser",
    arn: `arn:aws:iam::${ACCT}:user/svc${i % 3}`,
    accountId: ACCT,
    accessKeyId: `AKIASUMMARY00000000${i % 3}`,
    userName: `svc${i % 3}`,
  },
  ...over,
});
const launch = (i: number, id: string): Rec =>
  rec(i, {
    eventName: "RunInstances",
    readOnly: false,
    requestParameters: { instanceType: "t3.micro" },
    responseElements: {
      ownerId: ACCT,
      instancesSet: { items: [{ instanceId: id, instanceType: "t3.micro" }] },
    },
  });
const terminate = (i: number, id: string): Rec =>
  rec(i, {
    eventName: "TerminateInstances",
    readOnly: false,
    requestParameters: { instancesSet: { items: [{ instanceId: id }] } },
  });
const assumeRole = (i: number): Rec =>
  rec(i, {
    eventSource: "sts.amazonaws.com",
    eventName: "AssumeRole",
    requestParameters: { roleArn: `arn:aws:iam::${ACCT}:role/deploy`, roleSessionName: "s1" },
    responseElements: {
      credentials: { accessKeyId: "ASIASUMMARY000000001", expiration: "2026-11-01T12:00:00Z" },
      assumedRoleUser: { arn: `arn:aws:sts::${ACCT}:assumed-role/deploy/s1` },
    },
  });
const usedSession = (i: number): Rec =>
  rec(i, {
    userIdentity: {
      type: "AssumedRole",
      arn: `arn:aws:sts::${ACCT}:assumed-role/deploy/s1`,
      accountId: ACCT,
      accessKeyId: "ASIASUMMARY000000001",
      sessionContext: { sessionIssuer: { type: "Role", arn: `arn:aws:iam::${ACCT}:role/deploy` } },
    },
    eventSource: "s3.amazonaws.com",
    eventName: "GetObject",
  });

function wholeFile(records: Rec[]) {
  const r = parseCloudTrail("", { records });
  return r.events.slice(r.kept);
}

const WINDOWS: Record<string, Rec[]> = {
  empty: [],
  "all blanked (duplicates)": [{}, {}, {}],
  "nothing maps (no eventName or no eventSource)": [
    { eventSource: "ec2.amazonaws.com" },
    { eventName: "RunInstances" },
    { eventName: "", eventSource: "ec2.amazonaws.com" },
    { eventName: {}, eventSource: "ec2.amazonaws.com" },
  ],
  "only an unmappable launch record (summaries need one mapping record)": [
    { ...launch(1, "i-0aaaaaaaaaaaaaaa1"), eventName: undefined },
  ],
  "case-insensitive keys": [
    { eventname: "RunInstances", EVENTSOURCE: "ec2.amazonaws.com", ...launch(2, "i-0aaaaaaaaaaaaaaa2") },
  ],
  "non-string scalar action": [
    { ...rec(3), eventName: 42, eventSource: true },
    launch(4, "i-0aaaaaaaaaaaaaaa4"),
  ],
  "mixed: lineages, compute, blanked and unmappable records": [
    rec(5),
    {},
    assumeRole(6),
    usedSession(7),
    launch(8, "i-0aaaaaaaaaaaaaaa8"),
    { eventName: "Orphan" },
    terminate(9, "i-0aaaaaaaaaaaaaaa8"),
    ...Array.from({ length: 40 }, (_, i) => rec(10 + i)),
    usedSession(60),
  ],
};

describe("cloudTrailSummaries (#2362)", () => {
  for (const [name, window] of Object.entries(WINDOWS)) {
    it(`equals the whole-file parse's summary rows: ${name}`, () => {
      expect(cloudTrailSummaries(window)).toEqual(wholeFile(window));
    });
  }

  it("the mixed window really exercises both summary kinds, in order", () => {
    const rows = cloudTrailSummaries(WINDOWS["mixed: lineages, compute, blanked and unmappable records"]);
    const kinds = rows.map((e) =>
      e.description.startsWith("AWS compute lifecycle") ? "compute" : "lineage",
    );
    expect(kinds).toContain("lineage");
    expect(kinds).toContain("compute");
    expect(kinds.indexOf("compute")).toBeGreaterThan(kinds.lastIndexOf("lineage"));
  });
});
