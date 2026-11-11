// #2560: AWS account weaknesses from the CloudTrail parse — the rules, the fold, and the SANS 504 lab.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { ACCOUNTS_MAX, ROOT_IDS_MAX, type WeaknessFile } from "../../src/analysis/awsAccountWeakness.js";
import { foldWeaknesses } from "../../src/analysis/awsAccountWeaknessFold.js";
import { summarizeWeaknesses, type WeaknessItem } from "../../src/analysis/awsAccountWeaknessSummary.js";
import { LAB_ACCOUNT, SELECTORS_AT, TARGET_BUCKET, sans504Records } from "./fixtures/sans504Lab.js";

type Rec = Record<string, unknown>;

const draftOf = (records: Rec[]): WeaknessFile =>
  parseCloudTrail(JSON.stringify({ Records: records }), { aggregate: false }).weaknesses!;
const itemsOf = (records: Rec[]): WeaknessItem[] => summarizeWeaknesses(draftOf(records)).items;
const idOf = (r: Rec): string => String(r.eventID);

let n = 0;
function rec(name: string, source: string, extra: Rec = {}): Rec {
  n += 1;
  return {
    eventVersion: "1.08",
    eventTime: `2026-03-01T10:${String(Math.floor(n / 60) % 60).padStart(2, "0")}:${String(n % 60).padStart(2, "0")}Z`,
    eventSource: `${source}.amazonaws.com`,
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.5",
    userAgent: "aws-cli/2",
    eventID: `id-${n}`,
    eventType: "AwsApiCall",
    eventCategory: "Management",
    readOnly: true,
    recipientAccountId: "111122223333",
    userIdentity: { type: "IAMUser", accountId: "111122223333", arn: "arn:aws:iam::111122223333:user/u" },
    ...extra,
  };
}
const ROOT = { type: "Root", accountId: "111122223333", arn: "arn:aws:iam::111122223333:root" };
const rootLogin = (outcome: "Success" | "Failure", mfa = "No"): Rec =>
  rec("ConsoleLogin", "signin", {
    userIdentity: ROOT,
    eventType: "AwsConsoleSignIn",
    responseElements: { ConsoleLogin: outcome },
    additionalEventData: { MFAUsed: mfa },
    ...(outcome === "Failure" ? { errorMessage: "Failed authentication" } : {}),
  });

describe("SANS 504 lab acceptance (#2560)", () => {
  const records = sans504Records();
  const items = itemsOf(records);
  const byId = new Map(records.map((r) => [idOf(r), r]));
  const kinds = items.map((i) => i.kind);

  it("yields the four weaknesses and no versioning item (the lab's versioning checks carry no response)", () => {
    expect(kinds).toEqual([
      "root-no-mfa-login",
      "root-routine-use",
      "object-lock-missing",
      "object-logging-window",
    ]);
  });

  it("links every item to a record of the upload, by eventID and time", () => {
    for (const item of items)
      for (const c of item.cites) {
        const r = byId.get(c.eventId);
        expect(r, `${item.kind} ${c.eventId}`).toBeDefined();
        expect(Date.parse(c.time)).toBe(Date.parse(String(r!.eventTime)));
      }
  });

  it("cites the successful root sign-in (not the failed one), the bucket check, and the selector change", () => {
    const login = items.find((i) => i.kind === "root-no-mfa-login")!;
    expect(byId.get(login.cites[0].eventId)).toMatchObject({ responseElements: { ConsoleLogin: "Success" } });
    const lock = items.find((i) => i.kind === "object-lock-missing")!;
    expect(lock.bucket).toBe(TARGET_BUCKET);
    expect(byId.get(lock.cites[0].eventId)?.eventName).toBe("GetBucketObjectLockConfiguration");
    const window = items.find((i) => i.kind === "object-logging-window")!;
    expect(window.account).toBe(LAB_ACCOUNT);
    expect(byId.get(window.cites[0].eventId)?.eventName).toBe("PutEventSelectors");
    expect(Date.parse(window.cites[0].time)).toBe(Date.parse(SELECTORS_AT));
    expect(window.detail).toMatch(
      /No S3 object-level \(data\) records were observed before 2021-07-29T23:53:36Z/,
    );
    expect(window.detail).toMatch(/Other trails' selectors are not in this evidence/);
  });

  it("counts root management calls without the sign-ins", () => {
    const use = items.find((i) => i.kind === "root-routine-use")!;
    const rootCalls = records.filter(
      (r) =>
        (r.userIdentity as Rec)?.type === "Root" &&
        r.eventSource !== "signin.amazonaws.com" &&
        (!r.eventCategory || r.eventCategory === "Management"),
    );
    expect(use.detail).toMatch(new RegExp(`^${rootCalls.length} root management call`));
  });

  it("batch by batch folds to the same file as the whole upload, in any order", () => {
    const whole = draftOf(records);
    const halves = [records.slice(0, 17), records.slice(17)].map(draftOf);
    expect(foldWeaknesses(halves[0], halves[1])).toEqual(whole);
    expect(foldWeaknesses(halves[1], halves[0])).toEqual(whole);
  });

  it("is idempotent: the same upload folded twice changes nothing", () => {
    const whole = draftOf(records);
    expect(foldWeaknesses(whole, whole)).toEqual(whole);
  });
});

describe("weakness rules (#2560)", () => {
  it("a failed root sign-in with MFAUsed No proves nothing; a successful one with MFA is fine", () => {
    expect(itemsOf([rootLogin("Failure"), rootLogin("Success", "Yes")])).toEqual([]);
    expect(itemsOf([rootLogin("Success")]).map((i) => i.kind)).toEqual(["root-no-mfa-login"]);
  });

  it("root routine use counts management calls only (Data / Insight excluded) and mutating ones apart", () => {
    const items = itemsOf([
      rec("ListBuckets", "s3", { userIdentity: ROOT }),
      rec("CreateUser", "iam", { userIdentity: ROOT, readOnly: false }),
      rec("GetObject", "s3", { userIdentity: ROOT, eventCategory: "Data" }),
      rec("x", "cloudtrail", { userIdentity: ROOT, eventCategory: "Insight" }),
    ]);
    expect(items).toHaveLength(1);
    expect(items[0].detail).toMatch(/^2 root management call\(s\), 1 of them changing something/);
  });

  it("root facts key on the caller's account, bucket facts on the recipient's", () => {
    const file = draftOf([
      rec("ListUsers", "iam", { userIdentity: { ...ROOT, accountId: "444455556666" } }),
      rec("GetBucketObjectLockConfiguration", "s3", {
        userIdentity: { type: "IAMUser", accountId: "444455556666" },
        errorCode: "ObjectLockConfigurationNotFoundError",
        requestParameters: { bucketName: "b1" },
      }),
    ]);
    const accounts = Object.fromEntries(file.accounts.map((a) => [a.account, a]));
    expect(accounts["444455556666"].rootUse).toBeDefined();
    expect(accounts["111122223333"].objectLock?.buckets.map((b) => b.bucket)).toEqual(["b1"]);
  });

  it("versioning: a null or empty response proves nothing; a stated Suspended / MFADelete Disabled does", () => {
    expect(
      itemsOf([
        rec("GetBucketVersioning", "s3", { requestParameters: { bucketName: "b" }, responseElements: null }),
        rec("GetBucketVersioning", "s3", { requestParameters: { bucketName: "b" }, responseElements: {} }),
        rec("GetBucketVersioning", "s3", {
          requestParameters: { bucketName: "b" },
          responseElements: { Status: "Suspended" },
          errorCode: "AccessDenied",
        }),
      ]),
    ).toEqual([]);
    const kinds = itemsOf([
      rec("GetBucketVersioning", "s3", {
        requestParameters: { bucketName: "b1" },
        responseElements: { VersioningConfiguration: { Status: "Suspended", MFADelete: "Disabled" } },
      }),
      rec("PutBucketVersioning", "s3", {
        readOnly: false,
        requestParameters: {
          bucketName: "b2",
          VersioningConfiguration: { Status: "Suspended", MfaDelete: "Disabled" },
        },
      }),
    ]).map((i) => `${i.kind}:${i.bucket}`);
    expect(kinds).toEqual([
      "mfa-delete-disabled:b1",
      "versioning-suspended:b1",
      "mfa-delete-disabled:b2",
      "versioning-suspended:b2",
    ]);
  });

  it("an earlier object-level record withdraws the logging-window item, even from another upload", () => {
    const selector = rec("PutEventSelectors", "cloudtrail", {
      userIdentity: ROOT,
      readOnly: false,
      requestParameters: {
        trailName: "t",
        eventSelectors: [{ dataResources: [{ type: "AWS::S3::Object", values: ["arn:aws:s3"] }] }],
      },
    });
    const later = summarizeWeaknesses(draftOf([selector])).items.filter(
      (i) => i.kind === "object-logging-window",
    );
    expect(later).toHaveLength(1);
    const earlier = rec("GetObject", "s3", {
      eventTime: "2026-02-01T00:00:00Z",
      eventCategory: "Data",
      requestParameters: { bucketName: "b", key: "k.txt" },
    });
    const folded = foldWeaknesses(draftOf([selector]), draftOf([earlier]));
    expect(summarizeWeaknesses(folded).items.some((i) => i.kind === "object-logging-window")).toBe(false);
  });

  it("a record with no account never joins the logging window; a bucket name over 255 chars is dropped, not cut", () => {
    const file = draftOf([
      rec("GetBucketObjectLockConfiguration", "s3", {
        errorCode: "ObjectLockConfigurationNotFoundError",
        requestParameters: { bucketName: "x".repeat(256) },
      }),
      rec("ListBuckets", "s3", { recipientAccountId: undefined, userIdentity: { type: "IAMUser" } }),
    ]);
    expect(file.accounts.some((a) => a.objectLock)).toBe(false);
    expect(file.accounts.some((a) => a.account === "")).toBe(false);
  });

  it("a root set past its cap keeps the smallest keys whatever the order and says 'at least'", () => {
    const calls = Array.from({ length: ROOT_IDS_MAX + 5 }, () =>
      rec("ListUsers", "iam", { userIdentity: ROOT }),
    );
    const a = draftOf(calls);
    const b = foldWeaknesses(draftOf(calls.slice(300)), draftOf(calls.slice(0, 300)));
    expect(b).toEqual(a);
    const use = summarizeWeaknesses(a).items.find((i) => i.kind === "root-routine-use")!;
    expect(use.detail).toMatch(
      new RegExp(`^at least ${ROOT_IDS_MAX.toLocaleString("en-US")} root management`),
    );
  });

  it("past the account cap the kept accounts depend on their ids alone, so an evicted account cannot claim a false gap", () => {
    const acct = (id: string): Rec => ({
      recipientAccountId: id,
      userIdentity: { type: "IAMUser", accountId: id },
    });
    const object = rec("GetObject", "s3", {
      ...acct("999999999999"),
      eventTime: "2026-02-01T00:00:00Z",
      eventCategory: "Data",
      requestParameters: { bucketName: "b", key: "k.txt" },
    });
    const others = Array.from({ length: ACCOUNTS_MAX }, (_, i) =>
      rec("ListBuckets", "s3", acct(String(100000000000 + i))),
    );
    const selector = rec("PutEventSelectors", "cloudtrail", {
      ...acct("999999999999"),
      readOnly: false,
      requestParameters: {
        trailName: "t",
        eventSelectors: [{ dataResources: [{ type: "AWS::S3::Object", values: ["arn:aws:s3"] }] }],
      },
    });
    const stepwise = foldWeaknesses(foldWeaknesses(draftOf([object]), draftOf(others)), draftOf([selector]));
    const whole = draftOf([object, ...others, selector]);
    expect(stepwise).toEqual(whole);
    expect(whole.accountsOverflow).toBe(true);
    expect(summarizeWeaknesses(stepwise).items.some((i) => i.kind === "object-logging-window")).toBe(false);
  });
});
