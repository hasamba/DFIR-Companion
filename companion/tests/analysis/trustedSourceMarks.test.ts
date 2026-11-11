// #2561: an analyst-marked friendly source (ours / responder) tags its routine rows
// `trusted-activity`; grades never move; high-impact actions are never tagged (fail closed).
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import type { IocAttributionLabel, IocAttributionMap } from "../../src/analysis/iocAttribution.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  TRUSTED_AUTHOR_PREFIX,
  TRUSTED_LABEL,
  honouredTrustedRows,
  parseTrustedAuthor,
  parseTrustedMarks,
  trustedActivityTags,
  trustedAuthor,
  trustedMarkFor,
} from "../../src/analysis/trustedSourceMarks.js";
import {
  ATTACK,
  ATTACKER_IP,
  ATTACKER_KEY,
  COMPANY_IP,
  LAB_ACCOUNT,
  sans504Records,
} from "./fixtures/sans504Lab.js";

type Rec = Record<string, unknown>;
const sigma = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();

let seq = 0;
function rowsOf(records: Rec[]): ForensicEvent[] {
  const parsed = parseCloudTrail(JSON.stringify({ Records: records }), { sigma, aggregate: false });
  return parsed.events.map((e) => ({ ...e, id: `ev${++seq}` }) as unknown as ForensicEvent);
}
const labRows = rowsOf(sans504Records());

function marks(entries: Record<string, IocAttributionLabel>): IocAttributionMap {
  return Object.fromEntries(
    Object.entries(entries).map(([value, label]) => [
      value.toLowerCase(),
      { value, label, setAt: "2026-11-11T00:00:00Z", setBy: "analyst" },
    ]),
  );
}

const ROOT_ARN = `arn:aws:iam::${LAB_ACCOUNT}:root`;
const rootWho = (): Rec => ({
  type: "Root",
  principalId: LAB_ACCOUNT,
  arn: ROOT_ARN,
  accountId: LAB_ACCOUNT,
  accessKeyId: "ASIAEXAMPLEROOTSES09",
});
let evt = 0;
function trustedRec(name: string, source: string, extra: Rec = {}): Rec {
  return {
    eventVersion: "1.08",
    userIdentity: rootWho(),
    eventTime: "2021-07-30T09:00:00Z",
    eventSource: `${source}.amazonaws.com`,
    eventName: name,
    awsRegion: "us-west-1",
    sourceIPAddress: COMPANY_IP,
    userAgent: "aws-cli/2.2.23",
    requestParameters: null,
    responseElements: null,
    eventID: `00000000-0000-4000-8000-${String(++evt).padStart(12, "0")}`,
    readOnly: false,
    eventType: "AwsApiCall",
    recipientAccountId: LAB_ACCOUNT,
    ...extra,
  };
}

const ipMark = parseTrustedMarks(marks({ [COMPANY_IP]: "responder" }));
const byAction = (rows: ForensicEvent[], action: string) =>
  rows.filter((e) => e.canonical?.event.action === action);
const tagged = (rows: ForensicEvent[], m = ipMark) =>
  new Set(trustedActivityTags(rows, m).map((t) => t.targetId));

describe("parseTrustedMarks", () => {
  it("keeps ours/responder values it can read and ignores the rest", () => {
    const m = parseTrustedMarks(
      marks({
        [COMPANY_IP]: "ours",
        ASIAEXAMPLEROOTSES09: "responder",
        [ROOT_ARN]: "ours",
        [`arn:aws:iam::${LAB_ACCOUNT}:user/ops/admin-user`]: "ours",
        [`arn:aws:sts::${LAB_ACCOUNT}:assumed-role/Ops/alice`]: "responder",
        [`arn:aws:iam::${LAB_ACCOUNT}:role/Ops`]: "responder",
        "evil.example.com": "ours",
        [ATTACKER_IP]: "attacker",
        "10.0.0.1": "unknown",
      }),
    );
    expect(m.friendly.map((x) => x.kind).sort()).toEqual(
      ["access-key", "aws-assumed-role", "aws-role", "aws-root", "aws-user", "ip"].sort(),
    );
    expect(m.attacker.map((x) => x.kind)).toEqual(["ip"]);
  });

  it("is empty when no friendly label exists", () => {
    expect(parseTrustedMarks(marks({ [ATTACKER_IP]: "attacker" })).friendly).toEqual([]);
  });
});

describe("tagging the lab's admin IP (acceptance)", () => {
  const ids = tagged(labRows);

  it("tags the trusted source's routine rows", () => {
    const login = labRows.find(
      (e) => e.canonical?.event.action === "ConsoleLogin" && e.canonical?.event.outcome === "success",
    );
    expect(login).toBeDefined();
    expect(ids.has(login!.id)).toBe(true);
    for (const a of ["CreateTrail", "StartLogging"]) {
      const rows = byAction(labRows, a).filter((e) => e.canonical?.event.outcome === "success");
      expect(rows.length, a).toBeGreaterThan(0);
      for (const r of rows) expect(ids.has(r.id), a).toBe(true);
    }
  });

  it("leaves the attacker's *:* grant Critical and untagged", () => {
    const grant = byAction(labRows, "PutUserPolicy")[0];
    expect(grant.severity).toBe("Critical");
    expect(ids.has(grant.id)).toBe(false);
    for (const e of labRows.filter((r) => r.canonical?.network?.source?.address === ATTACKER_IP))
      expect(ids.has(e.id), e.description).toBe(false);
  });

  it("never tags the trusted source's IAM writes, failed sign-in or the trail reconfiguration", () => {
    for (const a of ["CreateRole", "CreatePolicy", "AttachRolePolicy", "UpdateTrail", "PutEventSelectors"])
      for (const r of byAction(labRows, a)) expect(ids.has(r.id), a).toBe(false);
    const failed = labRows.find(
      (e) => e.canonical?.event.action === "ConsoleLogin" && e.canonical?.event.outcome === "failed",
    );
    expect(failed && ids.has(failed.id)).toBe(false);
  });

  it("writes one tag per row with the label and a provenance author, and never moves a grade", () => {
    const before = labRows.map((e) => [e.id, e.severity, [...(e.mitreTechniques ?? [])]]);
    const tags = trustedActivityTags(labRows, ipMark);
    expect(tags.length).toBeGreaterThan(0);
    for (const t of tags) {
      expect(t.label).toBe(TRUSTED_LABEL);
      expect(t.targetType).toBe("event");
      expect(t.author).toBe(`${TRUSTED_AUTHOR_PREFIX}responder:${COMPANY_IP}`);
    }
    expect(new Set(tags.map((t) => t.targetId)).size).toBe(tags.length);
    expect(labRows.map((e) => [e.id, e.severity, [...(e.mitreTechniques ?? [])]])).toEqual(before);
  });
});

describe("never-tag gate: a trusted source's high-impact actions stay untagged", () => {
  const grant = ATTACK.find((r) => r.eventName === "PutUserPolicy") ?? {};
  const dangerous = rowsOf([
    {
      ...grant,
      userIdentity: rootWho(),
      sourceIPAddress: COMPANY_IP,
      eventID: "00000000-0000-4000-8000-0000000000a1",
    },
    trustedRec("StopLogging", "cloudtrail", { requestParameters: { name: "management-events" } }),
    trustedRec("DeleteTrail", "cloudtrail", { requestParameters: { name: "management-events" } }),
    trustedRec("CreateAccessKey", "iam", {
      requestParameters: { userName: "someone-else" },
      responseElements: { accessKey: { accessKeyId: "AKIAEXAMPLEOTHERKEY1", userName: "someone-else" } },
    }),
    trustedRec("UpdateAssumeRolePolicy", "iam", {
      requestParameters: {
        roleName: "Ops",
        policyDocument: JSON.stringify({
          Statement: [
            {
              Effect: "Allow",
              Principal: { AWS: "arn:aws:iam::210987654321:root" },
              Action: "sts:AssumeRole",
            },
          ],
        }),
      },
    }),
    trustedRec("PutBucketPolicy", "s3", {
      requestParameters: {
        bucketName: "example-eng",
        bucketPolicy: {
          Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "*" }],
        },
      },
    }),
    trustedRec("SendCommand", "ssm", { requestParameters: { documentName: "AWS-RunShellScript" } }),
  ]);

  it.each([
    "PutUserPolicy",
    "StopLogging",
    "DeleteTrail",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "PutBucketPolicy",
    "SendCommand",
  ])("%s by the marked source is not tagged", (action) => {
    const rows = byAction(dangerous, action);
    expect(rows.length, action).toBeGreaterThan(0);
    for (const r of rows) expect(trustedMarkFor(r, ipMark), action).toBeNull();
  });

  it("never tags a Critical row, even a read", () => {
    const read = rowsOf([trustedRec("ListBuckets", "s3", { readOnly: true })])[0];
    expect(trustedMarkFor(read, ipMark)).not.toBeNull();
    expect(trustedMarkFor({ ...read, severity: "Critical" }, ipMark)).toBeNull();
    expect(trustedMarkFor({ ...read, severity: "High" }, ipMark)).toBeNull();
  });

  it("never tags a failed call from the marked source", () => {
    const denied = rowsOf([
      trustedRec("ListBuckets", "s3", {
        readOnly: true,
        errorCode: "AccessDenied",
        errorMessage: "Access Denied",
      }),
    ])[0];
    expect(trustedMarkFor(denied, ipMark)).toBeNull();
  });

  it("never tags secret-bearing reads", () => {
    for (const [name, src] of [
      ["GetSecretValue", "secretsmanager"],
      ["GetPasswordData", "ec2"],
      ["GetSessionToken", "sts"],
    ] as const) {
      const r = rowsOf([trustedRec(name, src, { readOnly: true })])[0];
      expect(trustedMarkFor(r, ipMark), name).toBeNull();
    }
  });
});

describe("content-bearing reads are not routine (Codex code review)", () => {
  it.each([
    ["GetFunction20150331v2", "lambda"],
    ["GetQueryResults", "logs"],
    ["GetLogEvents", "logs"],
    ["GetObject", "s3"],
    ["GetRecords", "kinesis"],
    ["LookupEvents", "cloudtrail"],
    ["TestInvokeMethod", "apigateway"],
    ["SearchResources", "resource-groups"],
  ])("%s by the marked source is not tagged", (name, src) => {
    const r = rowsOf([trustedRec(name, src, { readOnly: true })])[0];
    expect(trustedMarkFor(r, ipMark), name).toBeNull();
  });

  it.each([
    ["GetBucketVersioning", "s3"],
    ["GetCallerIdentity", "sts"],
    ["ListFunctions20150331", "lambda"],
    ["DescribeInstances", "ec2"],
  ])("the metadata read %s by the marked source is tagged", (name, src) => {
    const r = rowsOf([trustedRec(name, src, { readOnly: true })])[0];
    expect(trustedMarkFor(r, ipMark), name).not.toBeNull();
  });
});

describe("matching by key and principal", () => {
  const read = rowsOf([trustedRec("ListBuckets", "s3", { readOnly: true })])[0];

  it("matches the account root, the access key, and not another account's root", () => {
    expect(trustedMarkFor(read, parseTrustedMarks(marks({ [ROOT_ARN]: "ours" })))?.kind).toBe("aws-root");
    expect(trustedMarkFor(read, parseTrustedMarks(marks({ ASIAEXAMPLEROOTSES09: "ours" })))?.kind).toBe(
      "access-key",
    );
    expect(
      trustedMarkFor(read, parseTrustedMarks(marks({ "arn:aws:iam::210987654321:root": "ours" }))),
    ).toBeNull();
  });

  it("an attacker label on the same row's key vetoes a friendly IP", () => {
    const m = parseTrustedMarks(marks({ [COMPANY_IP]: "ours", ASIAEXAMPLEROOTSES09: "attacker" }));
    expect(trustedMarkFor(read, m)).toBeNull();
  });

  it("does not tag the attacker's rows when the attacker IP is wrongly marked ours but its key is attacker", () => {
    const m = parseTrustedMarks(marks({ [ATTACKER_IP]: "ours", [ATTACKER_KEY]: "attacker" }));
    const signed = labRows.filter(
      (r) =>
        r.canonical?.network?.source?.address === ATTACKER_IP &&
        r.canonical?.authentication?.credentialId === ATTACKER_KEY,
    );
    expect(signed.length).toBeGreaterThan(0);
    for (const e of signed) expect(trustedMarkFor(e, m), e.description).toBeNull();
  });

  it("a source IP that is not edge-observed confers no trust", () => {
    const c = read.canonical!;
    const claimed = { ...read, canonical: { ...c, network: { source: { address: COMPANY_IP } } } };
    expect(trustedMarkFor(claimed as ForensicEvent, ipMark)).toBeNull();
    expect(c.network?.source?.provenance).toBe("edge-observed");
    expect(trustedMarkFor(read, ipMark)).not.toBeNull();
  });

  it("does not match a single-call row from another provider in v1", () => {
    const other = {
      ...read,
      canonical: { ...read.canonical!, cloud: { ...read.canonical!.cloud, provider: "azure" } },
    };
    expect(trustedMarkFor(other as ForensicEvent, ipMark)).toBeNull();
  });
});

describe("credential-lineage rows", () => {
  const lineages = labRows.filter((e) => e.canonical?.event.type === "credential-lineage");

  it("tags a lineage row only when every source is marked, none beyond, no shape, not High", () => {
    for (const l of lineages) {
      const block = l.canonical!.awsLineage!;
      const eligible =
        block.shapes.length === 0 &&
        block.sources.length > 0 &&
        block.sourcesBeyond === 0 &&
        block.sources.every((s) => s.address === COMPANY_IP) &&
        (l.severity === "Low" || l.severity === "Medium" || l.severity === "Info");
      expect(trustedMarkFor(l, ipMark) !== null, l.description).toBe(eligible);
    }
  });

  it("never tags the attacker key's lineage", () => {
    const attacker = lineages.filter((l) => l.canonical!.awsLineage!.credentialId === ATTACKER_KEY);
    expect(attacker.length).toBeGreaterThan(0);
    for (const l of attacker) expect(trustedMarkFor(l, ipMark)).toBeNull();
  });

  it("a lineage row with a shape stays untagged even when the key itself is marked", () => {
    const withShape = lineages.find((l) => l.canonical!.awsLineage!.shapes.length > 0);
    expect(withShape).toBeDefined();
    const key = withShape!.canonical!.awsLineage!.credentialId;
    expect(trustedMarkFor(withShape!, parseTrustedMarks(marks({ [key]: "ours" })))).toBeNull();
  });
});

describe("author round trip and the consumer guard", () => {
  it("round-trips an ARN value with colons", () => {
    const author = trustedAuthor({ label: "ours", value: ROOT_ARN });
    expect(parseTrustedAuthor(author)).toEqual({ label: "ours", value: ROOT_ARN });
    expect(parseTrustedAuthor("tagger:dfir-collector:x")).toBeNull();
  });

  it("honours a tag only while its mark is still friendly and the row still eligible", () => {
    const tags = trustedActivityTags(labRows, ipMark).map((t, i) => ({ ...t, id: `t${i}`, createdAt: "" }));
    const live = honouredTrustedRows(labRows, tags, marks({ [COMPANY_IP]: "responder" }));
    expect(live.size).toBe(tags.length);
    expect(honouredTrustedRows(labRows, tags, marks({})).size).toBe(0);
    expect(honouredTrustedRows(labRows, tags, marks({ [COMPANY_IP]: "attacker" })).size).toBe(0);
    const raised = labRows.map((e) =>
      e.id === tags[0].targetId ? { ...e, severity: "Critical" as const } : e,
    );
    expect(
      honouredTrustedRows(raised, tags, marks({ [COMPANY_IP]: "responder" })).has(tags[0].targetId),
    ).toBe(false);
  });

  it("ignores an analyst-authored trusted-activity tag", () => {
    const row = [...tagged(labRows)][0];
    const forged = [
      { id: "x", targetType: "event", targetId: row, label: TRUSTED_LABEL, author: "mallory", createdAt: "" },
    ];
    expect(honouredTrustedRows(labRows, forged, marks({ [COMPANY_IP]: "ours" })).size).toBe(0);
  });
});
