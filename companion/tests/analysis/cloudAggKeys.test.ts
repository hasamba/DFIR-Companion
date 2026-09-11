import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";

// #931 prerequisite: the three cloud aggregation keys discarded the discriminators every later
// correlation needs, and used a raw slice that deletes one row's evidence when two keys share a
// 400-character prefix. Each key now names stable IDENTITIES (never display labels), bounded
// fields first, the unbounded one last, through boundedAggKey.

describe("Entra directory audit key", () => {
  const audit = (over: Record<string, unknown>) => ({
    activityDateTime: "2023-05-02T08:00:00Z",
    activityDisplayName: "Add member to role",
    result: "success",
    initiatedBy: { user: { id: "u-1", userPrincipalName: "admin@victim.com", ipAddress: "198.51.100.9" } },
    targetResources: [
      { id: "t-1", type: "User", userPrincipalName: "alice@victim.com", displayName: "Alice" },
    ],
    ...over,
  });
  const rows = (...recs: object[]) => parseM365Audit(JSON.stringify(recs)).events;

  it("keeps a success and a failure of the same change as two rows", () => {
    expect(rows(audit({}), audit({ result: "failure" }))).toHaveLength(2);
  });

  it("treats every spelling of success as one outcome", () => {
    expect(
      rows(audit({ result: "success" }), audit({ result: "Success" }), audit({ result: "succeeded" })),
    ).toHaveLength(1);
  });

  // The old key took targetResources[0] only: a change naming two users was "the first user".
  it("keys on EVERY target, order-independent, and shows the overflow in the description", () => {
    const two = [
      { id: "t-1", type: "User", userPrincipalName: "alice@victim.com" },
      { id: "t-2", type: "User", userPrincipalName: "bob@victim.com" },
    ];
    const a = audit({ targetResources: two });
    const b = audit({ targetResources: [...two].reverse() });
    const c = audit({
      targetResources: [two[0], { id: "t-3", type: "User", userPrincipalName: "carol@victim.com" }],
    });
    const out = rows(a, b, c);
    expect(out).toHaveLength(2); // a and b are one change; c is another
    expect(out.some((e) => e.description.includes("+1 more"))).toBe(true);
  });

  // Two applications, groups or roles can share a display name and differ only by id.
  it("distinguishes two targets that share a display name but not an id", () => {
    const a = audit({ targetResources: [{ id: "app-1", type: "Application", displayName: "Backup Agent" }] });
    const b = audit({ targetResources: [{ id: "app-2", type: "Application", displayName: "Backup Agent" }] });
    expect(rows(a, b)).toHaveLength(2);
  });

  it("distinguishes two app initiators that share a display name but not an id", () => {
    const a = audit({ initiatedBy: { app: { appId: "a-1", displayName: "Sync" } } });
    const b = audit({ initiatedBy: { app: { appId: "a-2", displayName: "Sync" } } });
    expect(rows(a, b)).toHaveLength(2);
  });

  // Graph's result is four-valued; a timeout is not a failure and unknownFutureValue is not either.
  it("keeps failure, timeout and unknownFutureValue as three outcomes, and absent as a fourth", () => {
    expect(
      rows(
        audit({ result: "failure" }),
        audit({ result: "timeout" }),
        audit({ result: "unknownFutureValue" }),
        audit({ result: "" }),
      ),
    ).toHaveLength(4);
  });

  it("keeps two changes whose keys share a 400-character prefix as two rows", () => {
    const long = (n: number) => ({
      id: `t-${n}`,
      type: "User",
      userPrincipalName: `${"x".repeat(420)}${n}@victim.com`,
    });
    expect(rows(audit({ targetResources: [long(1)] }), audit({ targetResources: [long(2)] }))).toHaveLength(
      2,
    );
  });
});

describe("Google Workspace key", () => {
  const gws = (
    params: Array<{ name: string; value?: string; multiValue?: string[] }>,
    over: Record<string, unknown> = {},
  ) => ({
    id: { time: "2023-05-02T08:00:00Z", applicationName: "drive" },
    actor: { email: "alice@victim.com" },
    ipAddress: "198.51.100.9",
    events: [{ name: "change_user_access", parameters: params }],
    ...over,
  });
  const rows = (...recs: object[]) => parseGoogleWorkspaceReport(JSON.stringify({ items: recs })).events;

  // doc_title is not identity: two different documents can share a title.
  it("keys on the document id, so two documents with one title are two rows", () => {
    const a = gws([
      { name: "doc_id", value: "1AAA" },
      { name: "doc_title", value: "Q3 Plan" },
    ]);
    const b = gws([
      { name: "doc_id", value: "2BBB" },
      { name: "doc_title", value: "Q3 Plan" },
    ]);
    expect(rows(a, b)).toHaveLength(2);
  });

  it("never keys on a configuration value — OLD_VALUE/NEW_VALUE are description-only", () => {
    const a = gws(
      [
        { name: "SETTING_NAME", value: "2sv" },
        { name: "OLD_VALUE", value: "on" },
        { name: "NEW_VALUE", value: "off" },
      ],
      { id: { time: "2023-05-02T08:00:00Z", applicationName: "admin" } },
    );
    const b = gws(
      [
        { name: "SETTING_NAME", value: "2sv" },
        { name: "OLD_VALUE", value: "off" },
        { name: "NEW_VALUE", value: "on" },
      ],
      { id: { time: "2023-05-02T08:00:00Z", applicationName: "admin" } },
    );
    expect(rows(a, b)).toHaveLength(1);
  });

  // Drive emits one access-change event per sharee: same doc_id, different target_user.
  it("keeps one document shared with three people as three rows", () => {
    const share = (who: string) =>
      gws([
        { name: "doc_id", value: "1AAA" },
        { name: "doc_title", value: "Q3 Plan" },
        { name: "target_user", value: who },
      ]);
    expect(rows(share("bob@x"), share("carol@x"), share("dave@x"))).toHaveLength(3);
  });

  it("keys an event with no identity parameter exactly as before (one row per actor/ip/event)", () => {
    const login = {
      id: { time: "2023-05-02T08:00:00Z", applicationName: "login" },
      actor: { email: "alice@victim.com" },
      ipAddress: "198.51.100.9",
      events: [{ name: "login_success", parameters: [] }],
    };
    expect(rows(login, login)).toHaveLength(1);
  });
});

describe("AWS CloudTrail key", () => {
  const rec = (over: Record<string, unknown>) => ({
    eventVersion: "1.08",
    eventTime: "2023-05-02T08:00:00Z",
    eventSource: "ec2.amazonaws.com",
    eventName: "RunInstances",
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.9",
    userIdentity: {
      type: "AssumedRole",
      principalId: "AROA1:alice",
      arn: "arn:aws:sts::111111111111:assumed-role/Admin/alice",
      accountId: "111111111111",
      userName: "Admin",
    },
    readOnly: false,
    ...over,
  });
  const rows = (...recs: object[]) => parseCloudTrail(JSON.stringify({ Records: recs })).events;

  it("keeps the same call in two regions as two rows", () => {
    expect(rows(rec({}), rec({ awsRegion: "eu-west-3" }))).toHaveLength(2);
  });

  // An organisation trail: identically named roles in two accounts are two principals.
  it("keeps a same-named role from two accounts as two rows", () => {
    const other = rec({
      userIdentity: {
        type: "AssumedRole",
        principalId: "AROA2:alice",
        arn: "arn:aws:sts::222222222222:assumed-role/Admin/alice",
        accountId: "222222222222",
        userName: "Admin",
      },
    });
    expect(rows(rec({}), other)).toHaveLength(2);
  });

  // IAM Identity Center users carry no principalId or userName at the root.
  it("keeps two Identity Center users in one account as two principals", () => {
    const icu = (userId: string) =>
      rec({
        userIdentity: {
          type: "IdentityCenterUser",
          accountId: "111111111111",
          onBehalfOf: { userId, identityStoreArn: "arn:aws:identitystore::111111111111:identitystore/d-1" },
        },
      });
    expect(rows(icu("u-aaaa"), icu("u-bbbb"))).toHaveLength(2);
  });

  it("keeps a same-named API from two services as two rows", () => {
    expect(
      rows(
        rec({ eventName: "Describe", eventSource: "ec2.amazonaws.com" }),
        rec({ eventName: "Describe", eventSource: "rds.amazonaws.com" }),
      ),
    ).toHaveLength(2);
  });

  // ConsoleLogin reports failure in responseElements, with no errorCode at all.
  it("keeps a successful and a failed ConsoleLogin apart even with no errorCode", () => {
    const ok = rec({
      eventSource: "signin.amazonaws.com",
      eventName: "ConsoleLogin",
      responseElements: { ConsoleLogin: "Success" },
    });
    const bad = rec({
      eventSource: "signin.amazonaws.com",
      eventName: "ConsoleLogin",
      responseElements: { ConsoleLogin: "Failure" },
    });
    const out = rows(ok, bad);
    expect(out).toHaveLength(2);
  });

  it("still folds identical calls into one row with a count", () => {
    const out = rows(rec({}), rec({}));
    expect(out).toHaveLength(1);
    expect(out[0].count).toBe(2);
  });
});
