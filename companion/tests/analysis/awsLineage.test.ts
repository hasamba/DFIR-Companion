// #931 item 5, chain half (#979): the credential lineage built over one CloudTrail upload — an
// issuance joined to its uses by the access key id alone, every source named with its first use,
// the shapes beside them from exact successful calls, and nothing the records do not say.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { awsLineages, AWS_LINEAGE_MAX, SOURCES_PER_KEY_MAX } from "../../src/analysis/awsLineage.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ACCT = "111122223333";
const OTHER = "444455556666";
const ROLE = `arn:aws:iam::${ACCT}:role/Deploy`;
const KEY = "ASIAEXAMPLEKEY000001";
const USER_KEY = "AKIAEXAMPLEKEY000009";
const IP = "203.0.113.5";
const IP2 = "198.51.100.7";
const T = "2024-05-01T09:00:00Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
let n = 0;
const alice = {
  type: "IAMUser",
  principalId: "AIDAEXAMPLE",
  arn: `arn:aws:iam::${ACCT}:user/alice`,
  accountId: ACCT,
  accessKeyId: USER_KEY,
  userName: "alice",
};
const session = (key = KEY, over: Record<string, unknown> = {}, sc: Record<string, unknown> = {}) => ({
  type: "AssumedRole",
  principalId: `AROAEXAMPLEID:ci-42`,
  arn: `arn:aws:sts::${ACCT}:assumed-role/Deploy/ci-42`,
  accountId: ACCT,
  accessKeyId: key,
  sessionContext: {
    sessionIssuer: {
      type: "Role",
      principalId: "AROAEXAMPLEID",
      arn: ROLE,
      accountId: ACCT,
      userName: "Deploy",
    },
    attributes: { creationDate: T, mfaAuthenticated: "false" },
    ...sc,
  },
  ...over,
});
const rec = (over: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: T,
  eventSource: "s3.amazonaws.com",
  eventName: "GetObject",
  awsRegion: "us-east-1",
  sourceIPAddress: IP,
  userAgent: "aws-cli/2.15",
  recipientAccountId: ACCT,
  eventID: `evt-${++n}`,
  userIdentity: session(),
  ...over,
});
const issuance = (over: Record<string, unknown> = {}, issued = KEY, role = ROLE) =>
  rec({
    eventSource: "sts.amazonaws.com",
    eventName: "AssumeRole",
    userIdentity: alice,
    requestParameters: { roleArn: role, roleSessionName: "ci-42" },
    responseElements: {
      credentials: { accessKeyId: issued, expiration: "May 1, 2024, 10:00:00 PM" },
      assumedRoleUser: {
        arn: `arn:aws:sts::${ACCT}:assumed-role/Deploy/ci-42`,
        assumedRoleId: "AROAEXAMPLEID:ci-42",
      },
    },
    ...over,
  });
const use = (over: Record<string, unknown> = {}, key = KEY) =>
  rec({ eventTime: at(12), userIdentity: session(key), ...over });
const lineages = (records: Record<string, unknown>[]) => awsLineages(records);
const importLineages = (records: Record<string, unknown>[], opts: Record<string, unknown> = {}) =>
  parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false, ...opts });

describe("issuance → use by key id", () => {
  it("an issuance and its uses form one row: the issuance named with its record, every source's first use, the counts cited", () => {
    const rows = lineages([
      issuance(),
      use(),
      use({ eventTime: at(60), eventName: "ListObjects" }),
      use({ eventTime: at(3720), sourceIPAddress: IP2, userAgent: "python-requests/2.31" }),
    ]);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.severity).toBe("Medium");
    expect(r.description).toContain(
      `AWS credential lineage: ${KEY} (account ${ACCT}) [issued ${T.replace("Z", ".000Z")} by AssumeRole of ${ROLE} as session ci-42 by IAMUser arn:aws:iam::${ACCT}:user/alice (MFA not recorded on the issuance) — record:0`,
    );
    expect(r.description).toContain(
      "uses: 3 records 2024-05-01T09:00:12.000Z (record:1) → 2024-05-01T10:02:00.000Z (record:3)",
    );
    expect(r.description).toContain(
      `first use from each source: ${IP} aws-cli/2.15 at 2024-05-01T09:00:12.000Z (record:1, 2 records); ${IP2} python-requests/2.31 at 2024-05-01T10:02:00.000Z (record:3, 1 record)`,
    );
    expect(r.description).toContain(
      "second source 62 min after the issuance; the workload's own addresses are not in this evidence",
    );
    expect(r.description).toContain("record retention and the trails' selectors are not in this evidence");
    expect(r.description).toMatch(/issuance and 3 uses in this upload\]$/);
    expect(r.description).not.toMatch(/stolen|compromised|exfiltrat|attacker|new source/);
    expect(canonicalEventEnvelopeSchema.safeParse(r.canonical).success).toBe(true);
    expect(r.canonical?.awsLineage).toMatchObject({
      credentialId: KEY,
      account: ACCT,
      issuance: { action: "AssumeRole", locator: "record:0", role: ROLE, sessionName: "ci-42" },
      uses: { records: 3 },
      sourcesBeyond: 0,
      notCited: 0,
    });
    expect(r.canonical?.awsLineage?.sources.map((s) => s.address)).toEqual([IP, IP2]);
    expect(r.canonical?.evidence.rawRecords.map((x) => x.locator).sort()).toEqual([
      "record:0",
      "record:1",
      "record:2",
      "record:3",
    ]);
    expect(r.canonical?.authentication?.credentialId).toBe(KEY);
  });

  it("two sessions of one name under two keys are two rows; a session name or role name never joins", () => {
    const K2 = "ASIAEXAMPLEKEY000002";
    const rows = lineages([
      issuance(),
      use(),
      issuance({ eventTime: at(5) }, K2),
      use({ eventTime: at(30) }, K2),
    ]);
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.canonical?.awsLineage?.credentialId).sort()).toEqual([KEY, K2].sort());
    expect(new Set(rows.map((r) => r.aggKey)).size).toBe(2);
    for (const r of rows) expect(r.canonical?.awsLineage?.uses.records).toBe(1);
  });

  it("a single-source key with an issuance is a Low lineage; an issuance alone or a single-source use alone is no row", () => {
    expect(lineages([issuance(), use()])[0].severity).toBe("Low");
    expect(lineages([issuance(), use()])[0].mitre).toEqual([]);
    expect(lineages([issuance()])).toHaveLength(0);
    expect(lineages([use(), use({ eventTime: at(20) })])).toHaveLength(0);
  });
});

describe("what is never claimed", () => {
  it("a use whose key no issuance record exposes says so with the upload's counts; a request with no response is listed, not joined", () => {
    const rows = lineages([
      issuance({ responseElements: null }),
      use(),
      use({ eventTime: at(600), sourceIPAddress: IP2 }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain(
      "no issuance record in this upload exposes this credential id (3 records, 2024-05-01T09:00:00 → 2024-05-01T09:10:00)",
    );
    expect(rows[0].description).toContain(
      "1 issuance request for this role and session at 2024-05-01T09:00:00.000Z (record:0) has no response in the record — not joined",
    );
    expect(rows[0].description).not.toContain("issued 2024");
    expect(rows[0].canonical?.awsLineage?.issuance).toBeUndefined();
  });

  it("a workload key says the service delivered it and names the addresses and the gap — never 'new source'", () => {
    const ec2 = (over: Record<string, unknown> = {}) =>
      use({ ...over, userIdentity: session(KEY, {}, { ec2RoleDelivery: "2.0" }) });
    const rows = lineages([ec2(), ec2({ eventTime: at(900), sourceIPAddress: IP2, userAgent: "curl/8.0" })]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain(
      "delivered by the service to the EC2 instance role; no STS record is expected",
    );
    expect(rows[0].description).toContain("the workload's own addresses are not in this evidence");
    expect(rows[0].description).toMatch(/workload key \(EC2 instance role\)\]$/);
    expect(rows[0].description).not.toMatch(/new source|missing/);
    expect(rows[0].canonical?.awsLineage?.workload).toBe("EC2 instance role");
    const lambda = lineages([
      use({
        userIdentity: session(KEY, {
          inScopeOf: {
            issuerType: "AWS::Lambda::Function",
            credentialsIssuedTo: "arn:aws:lambda:us-east-1:111122223333:function:f",
          },
        }),
      }),
      use({
        eventTime: at(900),
        sourceIPAddress: IP2,
        userIdentity: session(KEY, { inScopeOf: { issuerType: "AWS::Lambda::Function" } }),
      }),
    ]);
    expect(lambda[0].canonical?.awsLineage?.workload).toBe("Lambda function");
    // An AWSService identity is not a workload credential.
    const svc = lineages([use({ userIdentity: { type: "AWSService", invokedBy: "ec2.amazonaws.com" } })]);
    expect(svc).toHaveLength(0);
  });

  it("shapes are exact successful calls: a privileged change or remote execution after the second source is High; denied calls are attempts; s3 GetObject across services is not enumeration", () => {
    const high = lineages([
      issuance(),
      use(),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
      use({
        eventTime: at(3660),
        sourceIPAddress: IP2,
        eventSource: "iam.amazonaws.com",
        eventName: "CreateAccessKey",
      }),
    ]);
    expect(high[0].severity).toBe("High");
    expect(high[0].description).toContain(
      "privileged change: iam CreateAccessKey at 2024-05-01T10:01:00.000Z (record:3) — after the second source",
    );
    expect(high[0].mitre).toEqual(["T1098"]);
    const denied = lineages([
      issuance(),
      use(),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
      use({
        eventTime: at(3660),
        sourceIPAddress: IP2,
        eventSource: "ssm.amazonaws.com",
        eventName: "SendCommand",
        errorCode: "AccessDenied",
      }),
    ]);
    expect(denied[0].severity).toBe("Medium");
    expect(denied[0].description).toContain("attempts: 1 denied call of these shapes — not counted");
    expect(denied[0].description).not.toContain("remote execution:");
    const before = lineages([
      issuance(),
      use(),
      use({ eventTime: at(30), eventSource: "ssm.amazonaws.com", eventName: "SendCommand" }),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
    ]);
    expect(before[0].severity).toBe("Medium");
    expect(before[0].description).toContain(
      "remote execution: ssm SendCommand at 2024-05-01T09:00:30.000Z (record:2)",
    );
    expect(before[0].description).not.toContain("after the second source");
    const reads = lineages([
      issuance(),
      use({ eventSource: "s3.amazonaws.com", eventName: "GetObject" }),
      use({ eventTime: at(20), eventSource: "secretsmanager.amazonaws.com", eventName: "GetSecretValue" }),
      use({ eventTime: at(40), eventSource: "kms.amazonaws.com", eventName: "GetKeyPolicy" }),
      use({ eventTime: at(60), eventSource: "bedrock-runtime.amazonaws.com", eventName: "InvokeModel" }),
    ]);
    expect(reads[0].severity).toBe("Low");
    expect(reads[0].description).not.toMatch(/enumeration|remote execution/);
  });

  it("enumeration is ≥ 3 services inside 10 minutes; two services, or three spread over an hour, are not", () => {
    const enumAt = (s: number, source: string, name: string) =>
      use({ eventTime: at(s), eventSource: source, eventName: name });
    const yes = lineages([
      issuance(),
      enumAt(10, "sts.amazonaws.com", "GetCallerIdentity"),
      enumAt(20, "iam.amazonaws.com", "ListUsers"),
      enumAt(30, "s3.amazonaws.com", "ListBuckets"),
    ]);
    expect(yes[0].severity).toBe("Medium");
    expect(yes[0].description).toContain(
      "enumeration: sts, iam, s3 within 10 min (sts GetCallerIdentity first) at 2024-05-01T09:00:10.000Z (record:1)",
    );
    expect(yes[0].mitre).toEqual(["T1580"]);
    const two = lineages([
      issuance(),
      enumAt(10, "sts.amazonaws.com", "GetCallerIdentity"),
      enumAt(20, "iam.amazonaws.com", "ListUsers"),
    ]);
    expect(two[0].severity).toBe("Low");
    const spread = lineages([
      issuance(),
      enumAt(10, "sts.amazonaws.com", "GetCallerIdentity"),
      enumAt(1800, "iam.amazonaws.com", "ListUsers"),
      enumAt(3600, "s3.amazonaws.com", "ListBuckets"),
    ]);
    expect(spread[0].severity).toBe("Low");
  });
});

describe("lanes, accounts, chaining", () => {
  it("a cross-account assumption's issuance and its uses meet on the role's account", () => {
    const otherRole = `arn:aws:iam::${OTHER}:role/Admin`;
    const rows = lineages([
      issuance({}, KEY, otherRole),
      use({
        userIdentity: session(KEY, {
          accountId: OTHER,
          arn: `arn:aws:sts::${OTHER}:assumed-role/Admin/ci-42`,
        }),
        recipientAccountId: OTHER,
      }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].canonical?.awsLineage).toMatchObject({ account: OTHER, issuance: { role: otherRole } });
    expect(rows[0].description).not.toContain("no issuance record");
  });

  it("a cross-account replica counts once", () => {
    const shared = { sharedEventID: "shared-1" };
    const rows = lineages([
      issuance(),
      use(shared),
      use({ ...shared, eventID: "evt-x", recipientAccountId: OTHER }),
    ]);
    expect(rows[0].canonical?.awsLineage?.uses.records).toBe(1);
    expect(rows[0].canonical?.awsLineage?.coverage.records).toBe(2);
  });

  it("the issuance kind labels the row; the stated human identity and a service-invoked use are carried", () => {
    const saml = lineages([
      issuance({
        eventName: "AssumeRoleWithSAML",
        userIdentity: { type: "SAMLUser", userName: "alice@example.invalid" },
        requestParameters: { roleArn: ROLE, sourceIdentity: "alice@example.invalid" },
      }),
      use({ userIdentity: session(KEY, {}, { sourceIdentity: "alice@example.invalid" }) }),
      use({ eventTime: at(30), userIdentity: session(KEY, { invokedBy: "cloudformation.amazonaws.com" }) }),
    ]);
    expect(saml[0].description).toContain("by AssumeRoleWithSAML");
    expect(saml[0].description).toContain("stated human identity alice@example.invalid");
    expect(saml[0].description).toContain("1 record made by an AWS service on the caller's behalf");
    const root = lineages([
      issuance({
        eventName: "AssumeRoot",
        requestParameters: {
          targetPrincipal: OTHER,
          taskPolicyArn: { arn: "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials" },
        },
      }),
      use({ userIdentity: session(KEY, { accountId: OTHER }) }),
    ]);
    expect(root[0].description).toContain("by AssumeRoot");
    expect(root[0].canonical?.awsLineage?.account).toBe(OTHER);
  });

  it("role chaining links the signer's row and the issued key's row, bounded", () => {
    const K2 = "ASIAEXAMPLEKEY000002";
    const adminRole = `arn:aws:iam::${ACCT}:role/Admin`;
    const rows = lineages([
      issuance(),
      use(),
      rec({
        eventTime: at(120),
        eventSource: "sts.amazonaws.com",
        eventName: "AssumeRole",
        userIdentity: session(),
        requestParameters: { roleArn: adminRole, roleSessionName: "hop" },
        responseElements: { credentials: { accessKeyId: K2 } },
      }),
      use({
        eventTime: at(180),
        userIdentity: session(K2, { arn: `arn:aws:sts::${ACCT}:assumed-role/Admin/hop` }),
      }),
    ]);
    const a = rows.find((r) => r.canonical?.awsLineage?.credentialId === KEY)!;
    const b = rows.find((r) => r.canonical?.awsLineage?.credentialId === K2)!;
    expect(a.description).toContain(`chained: issued ${K2} (record:2)`);
    expect(b.description).toContain(`issued from a session of ${KEY} (record:2)`);
    expect(b.canonical?.awsLineage?.chained).toEqual([
      { credentialId: KEY, direction: "issued-from", locator: "record:2" },
    ]);
  });
});

describe("identity, bounds, the importer", () => {
  it("the row's identity is (account, key id); a re-import folds at merge; the importer appends after the cap and counts source rows alone", () => {
    const records = [issuance(), use(), use({ eventTime: at(3600), sourceIPAddress: IP2 })];
    const a = importLineages(records);
    const b = importLineages(records);
    const rowsA = a.events.filter((e) => e.description.startsWith("AWS credential lineage:"));
    expect(rowsA).toHaveLength(1);
    expect(rowsA[0].aggKey).toBe(
      b.events.find((e) => e.description.startsWith("AWS credential lineage:"))!.aggKey,
    );
    expect(rowsA[0].aggKey).toMatch(/^aws-credential-lineage\|[0-9a-f]{32}$/);
    const asEvents = (tag: string): ForensicEvent[] =>
      importLineages(records)
        .events.filter((e) => e.description.startsWith("AWS credential lineage:"))
        .map((e, i) => ({
          ...e,
          id: `${tag}-${i}`,
          relatedFindingIds: [],
          sourceScreenshots: [],
          sources: ["AWS CloudTrail"],
        }));
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(1);
    const capped = importLineages(records, { maxEvents: 1 });
    expect(capped.events.filter((e) => e.description.startsWith("AWS credential lineage:"))).toHaveLength(1);
    expect(capped.kept).toBe(1);
    expect(capped.summaries).toBe(1);
    expect(capped.dropped).toBe(2);
  });

  it("hostile names are neutralised; 257 keys → the rest counted with the omitted grade; sources and citations bounded; every record scanned", () => {
    const evil = lineages([
      issuance({ requestParameters: { roleArn: ROLE, roleSessionName: "ci] [fake: x" } }),
      use(),
    ]);
    expect(evil[0].description).not.toContain("] [fake");
    const many = Array.from({ length: AWS_LINEAGE_MAX + 2 }, (_, i) => {
      const k = `ASIAEXAMPLE${String(i).padStart(9, "0")}`;
      return [issuance({}, k), use({ eventTime: at(10) }, k)];
    }).flat();
    const rows = lineages(many);
    expect(rows).toHaveLength(AWS_LINEAGE_MAX + 1);
    const omitted = rows.find((r) => r.description.includes("further credentials"))!;
    expect(omitted.description).toContain(
      `2 further credentials with a lineage in this upload beyond the ${AWS_LINEAGE_MAX} reported — not shown`,
    );
    expect(omitted.severity).toBe("Low");
    const flood = [
      issuance(),
      ...Array.from({ length: 5000 }, (_, i) => use({ eventTime: at(10 + i) })),
      ...Array.from({ length: SOURCES_PER_KEY_MAX + 3 }, (_, i) =>
        use({
          eventTime: at(6000 + i),
          sourceIPAddress: `198.51.100.${(i % 200) + 1}`,
          userAgent: `agent-${i}`,
        }),
      ),
      use({
        eventTime: at(9000),
        sourceIPAddress: IP2,
        eventSource: "ssm.amazonaws.com",
        eventName: "SendCommand",
      }),
    ];
    const started = Date.now();
    const r = lineages(flood)[0];
    expect(Date.now() - started).toBeLessThan(5000);
    // The decisive record past every bound still decides the grade: every record is scanned.
    expect(r.severity).toBe("High");
    expect(r.canonical?.awsLineage?.sourcesBeyond).toBe(5);
    expect(r.description).toContain("further records not individually cited");
    expect(r.canonical?.evidence.rawRecords.length).toBeLessThanOrEqual(256);
    expect(r.description.length).toBeLessThanOrEqual(1400);
    expect(r.description).toMatch(/issuance and 5068 uses in this upload\]$/);
  });
});

// Code round 1 (Codex): the cases the review named.
describe("code round 1", () => {
  it("replicas are grouped first: the informative identity is read whichever replica the file lists first", () => {
    const shared = { sharedEventID: "shared-9" };
    const accountView = use({
      ...shared,
      userIdentity: { type: "AWSAccount", principalId: "AIDA", accountId: ACCT },
      recipientAccountId: OTHER,
    });
    const roleView = use({ ...shared, eventID: "evt-r" });
    const a = lineages([
      issuance(),
      accountView,
      roleView,
      use({ eventTime: at(600), sourceIPAddress: IP2 }),
    ]);
    const b = lineages([
      issuance(),
      roleView,
      accountView,
      use({ eventTime: at(600), sourceIPAddress: IP2 }),
    ]);
    expect(a[0].canonical?.awsLineage?.uses.records).toBe(2);
    expect(b[0].canonical?.awsLineage?.uses.records).toBe(2);
    expect(a[0].description.replace(/record:\d+/g, "")).toBe(b[0].description.replace(/record:\d+/g, ""));
  });

  it("an AssumeRoot target given as a root ARN owns the key the same as the 12-digit form", () => {
    for (const target of [OTHER, `arn:aws:iam::${OTHER}:root`]) {
      const rows = lineages([
        issuance({
          eventName: "AssumeRoot",
          requestParameters: {
            targetPrincipal: target,
            taskPolicyArn: { arn: "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials" },
          },
        }),
        use({ userIdentity: session(KEY, { accountId: OTHER }) }),
      ]);
      expect(rows).toHaveLength(1);
      expect(rows[0].canonical?.awsLineage?.account).toBe(OTHER);
      expect(rows[0].description).not.toContain("no issuance record");
    }
  });

  it("deploying Lambda code is not remote execution; only Invoke is", () => {
    const deploy = lineages([
      issuance(),
      use(),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
      use({
        eventTime: at(3700),
        sourceIPAddress: IP2,
        eventSource: "lambda.amazonaws.com",
        eventName: "UpdateFunctionCode",
      }),
    ]);
    expect(deploy[0].severity).toBe("Medium");
    expect(deploy[0].description).not.toContain("remote execution");
    const invoke = lineages([
      issuance(),
      use(),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
      use({
        eventTime: at(3700),
        sourceIPAddress: IP2,
        eventSource: "lambda.amazonaws.com",
        eventName: "Invoke",
      }),
    ]);
    expect(invoke[0].severity).toBe("High");
    expect(invoke[0].mitre).toEqual(["T1651"]);
  });

  it("the decisive shape is always in the words and the evidence, whatever precedes it; the state stays bounded", () => {
    const many = [
      issuance(),
      use(),
      ...Array.from({ length: 40 }, (_, i) =>
        use({ eventTime: at(20 + i), eventSource: "iam.amazonaws.com", eventName: "CreateAccessKey" }),
      ),
      use({ eventTime: at(3600), sourceIPAddress: IP2 }),
      use({
        eventTime: at(3700),
        sourceIPAddress: IP2,
        eventSource: "ssm.amazonaws.com",
        eventName: "SendCommand",
      }),
      ...Array.from({ length: 3000 }, (_, i) =>
        use({ eventTime: at(4000 + i), eventSource: "iam.amazonaws.com", eventName: "ListUsers" }),
      ),
    ];
    const r = lineages(many)[0];
    expect(r.severity).toBe("High");
    expect(r.description).toContain(
      "remote execution: ssm SendCommand at 2024-05-01T10:01:40.000Z (record:43) — after the second source",
    );
    expect(r.canonical?.evidence.rawRecords.map((x) => x.locator)).toContain("record:43");
    expect(r.canonical?.awsLineage?.shapes.length).toBeLessThanOrEqual(6);
    expect(r.canonical?.awsLineage?.shapes[0]).toMatchObject({
      kind: "remote-execution",
      locator: "record:43",
      afterSecondSource: true,
    });
    expect(r.description).toContain("+35 more shape records");
    expect(r.description).toContain("enumeration calls beyond the scanned buffer");
    expect(JSON.stringify(r.canonical).length).toBeLessThan(60_000);
  });

  it("sources past the tracked bound are counted as distinct sources, not as records; the second source is exact whatever the order", () => {
    const flood = [
      issuance(),
      ...Array.from({ length: SOURCES_PER_KEY_MAX + 1 }, (_, i) =>
        use({
          eventTime: at(100 + i),
          sourceIPAddress: `198.51.100.${(i % 200) + 1}`,
          userAgent: `agent-${i}`,
        }),
      ),
      ...Array.from({ length: 500 }, (_, i) =>
        use({ eventTime: at(5000 + i), sourceIPAddress: "192.0.2.77", userAgent: "one-more" }),
      ),
    ];
    const r = lineages(flood)[0];
    expect(r.canonical?.awsLineage?.sourcesBeyond).toBe(2);
    expect(r.description).toContain("+58 more sources");
    // The earliest source arrives LAST in the file: it still becomes the first source.
    const reversed = lineages([
      issuance(),
      ...Array.from({ length: SOURCES_PER_KEY_MAX + 5 }, (_, i) =>
        use({ eventTime: at(100 + i), sourceIPAddress: `198.51.100.${i + 1}` }),
      ).reverse(),
    ])[0];
    expect(reversed.canonical?.awsLineage?.sources[0].address).toBe("198.51.100.1");
    expect(reversed.canonical?.awsLineage?.sources[1].address).toBe("198.51.100.2");
  });

  it("citations are one deduplicated list: an issuance plus exactly 256 uses cites 256 and says one is not", () => {
    const r = lineages([
      issuance(),
      ...Array.from({ length: 256 }, (_, i) => use({ eventTime: at(10 + i) })),
    ])[0];
    expect(r.canonical?.evidence.rawRecords).toHaveLength(256);
    expect(r.canonical?.evidence.rawRecords.map((x) => x.locator)).toEqual(
      expect.arrayContaining(["record:0", "record:1", "record:256"]),
    );
    expect(r.canonical?.awsLineage?.notCited).toBe(1);
    expect(r.description).toContain("1 further record not individually cited");
  });
});
