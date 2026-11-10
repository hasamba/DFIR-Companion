// #2543 part 1a: CloudTrail principals, long-term keys, issued keys and created names as `other`
// IOCs with a context note — only from High+ rows or a successful CreateAccessKey, never from the
// account root or an AWS service, keyed on the full ARN.
import { describe, expect, it } from "vitest";
import { addAwsIdentityIocs, awsIocCandidates } from "../../src/analysis/awsIocCandidates.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { iocHasBehavioralEvent } from "../../src/analysis/iocAnchors.js";
import { iocKind } from "../../src/enrichment/provider.js";
import type { MappedEvent, SiemIoc } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import {
  ATTACKER_IP,
  ATTACKER_KEY,
  COMPANY_IP,
  CREATED_KEY,
  LAB_ACCOUNT,
  sans504Upload,
} from "./fixtures/sans504Lab.js";

type Rec = Record<string, unknown>;
const USER_ARN = `arn:aws:iam::${LAB_ACCOUNT}:user/dev-user`;
const user = (key = ATTACKER_KEY): Rec => ({
  type: "IAMUser",
  principalId: "AIDAEXAMPLE",
  arn: USER_ARN,
  accountId: LAB_ACCOUNT,
  accessKeyId: key,
  userName: "dev-user",
});
const rec = (name: string, who: Rec, extra: Rec = {}): Rec => ({
  eventTime: "2021-07-29T13:04:00Z",
  eventSource: "iam.amazonaws.com",
  eventName: name,
  userIdentity: who,
  sourceIPAddress: ATTACKER_IP,
  requestParameters: null,
  responseElements: null,
  ...extra,
});
const putPolicy = (policyName: string, who = user()): Rec =>
  rec("PutUserPolicy", who, { requestParameters: { userName: "dev-user", policyName } });
const createKey = (extra: Rec = {}): Rec =>
  rec("CreateAccessKey", user(), {
    requestParameters: { userName: "dev-user" },
    responseElements: { accessKey: { userName: "dev-user", accessKeyId: CREATED_KEY } },
    ...extra,
  });

describe("awsIocCandidates (#2543)", () => {
  it("a High self PutUserPolicy yields the user ARN, its AKIA key and the policy name, with notes", () => {
    const c = awsIocCandidates(putPolicy("examplepolicy1"), "High");
    expect(c.map((x) => x.value)).toEqual([USER_ARN, ATTACKER_KEY, "examplepolicy1"]);
    expect(c.every((x) => x.type === "other")).toBe(true);
    expect(c[0].note).toMatch(/AWS IAM principal — acted in PutUserPolicy at 2021-07-29T13:04:00Z/);
    expect(c[1].note).toMatch(/AWS access key — used for PutUserPolicy/);
    expect(c[2].note).toBe("AWS IAM policy — created by PutUserPolicy at 2021-07-29T13:04:00Z");
  });

  it("a successful CreateAccessKey yields the issued key, even below High; a failed one does not", () => {
    const ok = awsIocCandidates(createKey(), "Low");
    const issued = ok.find((x) => x.value === CREATED_KEY);
    expect(issued?.note).toBe(
      "AWS access key — issued by CreateAccessKey for dev-user at 2021-07-29T13:04:00Z",
    );
    const failed = awsIocCandidates(createKey({ errorCode: "AccessDenied" }), "Medium");
    expect(failed).toEqual([]);
  });

  it("a denied High PutUserPolicy records the caller but no created name", () => {
    const c = awsIocCandidates({ ...putPolicy("p1"), errorCode: "AccessDenied" }, "High");
    expect(c.map((x) => x.value)).toEqual([USER_ARN, ATTACKER_KEY]);
  });

  it("root, AWS-service and Info callers yield nothing; a session ASIA key is never an IOC", () => {
    const root = {
      type: "Root",
      arn: `arn:aws:iam::${LAB_ACCOUNT}:root`,
      accessKeyId: "ASIAEXAMPLEROOTSES01",
    };
    expect(awsIocCandidates(rec("ConsoleLogin", root), "High")).toEqual([]);
    expect(
      awsIocCandidates(rec("CreateRole", { type: "AWSService", invokedBy: "x.amazonaws.com" }), "High"),
    ).toEqual([]);
    expect(awsIocCandidates(putPolicy("p"), "Info")).toEqual([]);
    expect(awsIocCandidates(putPolicy("p"), "Medium")).toEqual([]);
    const session = awsIocCandidates(putPolicy("p", user("ASIAEXAMPLESESSION01")), "High");
    expect(session.map((x) => x.value)).toEqual([USER_ARN, "p"]);
  });

  it("an assumed role is keyed on its role ARN, never the per-session ARN; a service-linked role is skipped", () => {
    const role = (arn: string): Rec => ({
      type: "AssumedRole",
      arn: `arn:aws:sts::${LAB_ACCOUNT}:assumed-role/Ops/session-1`,
      sessionContext: { sessionIssuer: { type: "Role", arn } },
    });
    const ops = `arn:aws:iam::${LAB_ACCOUNT}:role/Ops`;
    expect(awsIocCandidates(rec("DeleteTrail", role(ops)), "High").map((x) => x.value)).toEqual([ops]);
    const linked = `arn:aws:iam::${LAB_ACCOUNT}:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX`;
    expect(awsIocCandidates(rec("DeleteTrail", role(linked)), "High")).toEqual([]);
  });

  it("an attacker-chosen policy name stays verbatim as the value and keeps the note on one line", () => {
    const c = awsIocCandidates(putPolicy('=HYPERLINK("http://x")'), "Critical");
    expect(c.map((x) => x.value)).toContain('=HYPERLINK("http://x")');
    const nl = awsIocCandidates(
      createKey({ responseElements: { accessKey: { userName: "a\nb|c", accessKeyId: CREATED_KEY } } }),
      "High",
    );
    expect(nl.find((x) => x.value === CREATED_KEY)?.note).not.toMatch(/\n/);
  });

  it("every value is a type the enrichment layer never sends to a threat-intel service", () => {
    expect(iocKind("other")).toBeUndefined();
  });

  it("links each row's IOCs to that row's aggKey and keeps the first note", () => {
    const sink = new Map<string, SiemIoc>();
    const rows = [
      { severity: "High", aggKey: "k1" },
      { severity: "Critical", aggKey: "k2" },
    ] as unknown as MappedEvent[];
    addAwsIdentityIocs(sink, rows, [putPolicy("p1"), putPolicy("p2")]);
    const arn = [...sink.values()].find((x) => x.value === USER_ARN);
    expect(arn?.sourceAggKeys).toEqual(["k1", "k2"]);
    expect(arn?.note).toMatch(/PutUserPolicy/);
  });

  it("the full-ARN key does not corroborate itself on a row that only says `by dev-user`", () => {
    const ev = {
      id: "e1",
      severity: "High",
      description: "AWS ListUsers (iam) by dev-user",
    } as ForensicEvent;
    expect(iocHasBehavioralEvent(USER_ARN, [ev])).toBe(false);
  });
});

describe("SANS 504 lab: identity IOCs (#2543)", () => {
  const result = parseCloudTrail(sans504Upload(), { aggregate: false });
  const iocs = result.iocs;
  const values = new Set(iocs.map((i) => i.value));

  it("adds the IAM user ARN, both example keys and the self-attached policy name, each with context", () => {
    const want = [
      `arn:aws:iam::${LAB_ACCOUNT}:user/example-user`,
      ATTACKER_KEY,
      CREATED_KEY,
      "examplepolicy1",
    ];
    for (const v of want) {
      const ioc = iocs.find((i) => i.value === v);
      expect(ioc, v).toBeDefined();
      expect(ioc?.type).toBe("other");
      expect(ioc?.note, v).toBeTruthy();
      expect(ioc?.sourceAggKeys?.length, v).toBeGreaterThan(0);
    }
  });

  it("adds nothing for the root responder, the CloudTrail wizard role or the next-day admin", () => {
    expect([...values].filter((v) => /:root$/.test(v))).toEqual([]);
    expect(values.has("ExampleTrailRoleForCloudWatchLogs")).toBe(false);
    expect(values.has("AKIAEXAMPLEADMINKEY1")).toBe(false);
    expect([...values].some((v) => /example-admin/.test(v))).toBe(false);
  });

  it("the case IOC set is the two addresses plus the four identity values", () => {
    expect(values).toEqual(
      new Set([
        ATTACKER_IP,
        COMPANY_IP,
        `arn:aws:iam::${LAB_ACCOUNT}:user/example-user`,
        ATTACKER_KEY,
        CREATED_KEY,
        "examplepolicy1",
      ]),
    );
  });
});

describe("SANS 504 lab through the import pipeline (#2543)", () => {
  it("the case IOCs carry the note and link to real event ids, at default aggregation", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-awsioc-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore: new StateStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const state = await pipeline.importAws("c1", sans504Upload(), {
      label: "trail.json",
      idPrefix: "a1",
      importedAt: "2026-11-10T00:00:00Z",
    });
    const eventIds = new Set(state.forensicTimeline.map((e) => e.id));
    const want = [
      `arn:aws:iam::${LAB_ACCOUNT}:user/example-user`,
      ATTACKER_KEY,
      CREATED_KEY,
      "examplepolicy1",
    ];
    for (const v of want) {
      const ioc = state.iocs.find((i) => i.value === v);
      expect(ioc, v).toBeDefined();
      expect(ioc?.type).toBe("other");
      expect(ioc?.note, v).toMatch(/^AWS /);
      expect(ioc?.extractedFrom?.length, v).toBeGreaterThan(0);
      for (const id of ioc?.extractedFrom ?? []) expect(eventIds.has(id), `${v} → ${id}`).toBe(true);
    }
  }, 60_000);
});
