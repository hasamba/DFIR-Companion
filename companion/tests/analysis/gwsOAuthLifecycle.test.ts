// #931 item 10, chain half (#983): the OAuth lifecycle built over one Reports API export — who
// authorized a client, what it called after an authorization and before a revocation, when it
// was revoked, whether calls continued — joined by tenant + client id + profile id, with every
// claim placed in time and nothing a record does not say.
import { describe, expect, it } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import {
  gwsOAuthLifecycles,
  GWS_LIFECYCLES_MAX,
  METHODS_TRACKED_MAX,
  USERS_NAMED_MAX,
} from "../../src/analysis/gwsOAuthLifecycle.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const G = "https://www.googleapis.com/auth/";
const CLIENT = "123456789012-abcdefghijklmnop.apps.googleusercontent.com";
const CLIENT2 = "999999999999-zzzzzzzzzzzzzzzz.apps.googleusercontent.com";
const TENANT = "C01abc";
const ALICE = { email: "alice@example.invalid", profileId: "100000000000000000001" };
const BOB = { email: "bob@example.invalid", profileId: "100000000000000000002" };
const CAROL = { email: "carol@example.invalid", profileId: "100000000000000000003" };
const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
let q = 0;
const clientParams = (id = CLIENT, name = "Mail Backup Pro") => [
  { name: "client_id", value: id },
  { name: "app_name", value: name },
  { name: "client_type", value: "WEB" },
];
const rec = (app: string, events: unknown[], over: Record<string, unknown> = {}) => {
  const { id, ...rest } = over;
  return {
    kind: "admin#reports#activity",
    id: {
      time: T,
      uniqueQualifier: String(--q),
      applicationName: app,
      customerId: TENANT,
      ...((id as Record<string, unknown> | undefined) ?? {}),
    },
    actor: ALICE,
    ipAddress: "203.0.113.10",
    events,
    ...rest,
  };
};
const token = (name: string, params: unknown[], over: Record<string, unknown> = {}) =>
  rec("token", [{ type: "auth", name, parameters: params }], over);
const authorize = (time: string, actor = ALICE, scopes = [G + "gmail.readonly"], client = CLIENT) =>
  token("authorize", [...clientParams(client), { name: "scope", multiValue: scopes }], {
    actor,
    id: { time },
  });
const activity = (
  time: string,
  actor = ALICE,
  method = "gmail.users.messages.get",
  bytes = "1000",
  client = CLIENT,
) =>
  token(
    "activity",
    [
      ...clientParams(client),
      { name: "api_name", value: "gmail" },
      { name: "method_name", value: method },
      { name: "num_response_bytes", intValue: bytes },
    ],
    { actor, id: { time } },
  );
const revoke = (time: string, actor = ALICE, client = CLIENT) =>
  token("revoke", clientParams(client), { actor, id: { time } });
const lifecycles = (records: Record<string, unknown>[]) => gwsOAuthLifecycles(records);
const rowsOf = (records: Record<string, unknown>[], opts: Record<string, unknown> = {}) =>
  parseGoogleWorkspaceReport(JSON.stringify(records), { aggregate: false, ...opts });

describe("the lifecycle of one client", () => {
  it("three users authorize one client: one row, each user's authorization, activity totals, revocation or its absence, graded by the highest tier", () => {
    const rows = lifecycles([
      authorize(at(0)),
      activity(at(60)),
      activity(at(120), ALICE, "gmail.users.messages.list", "500"),
      revoke(at(3600)),
      authorize(at(10), BOB, [G + "drive.file"]),
      activity(at(70), BOB, "drive.files.get", "2048"),
      authorize(at(20), CAROL, [G + "userinfo.email"]),
    ]);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.severity).toBe("High");
    expect(r.mitre).toEqual(["T1528"]);
    expect(r.description).toContain(`Google Workspace OAuth lifecycle: Mail Backup Pro (client ${CLIENT}) [`);
    expect(r.description).toContain(
      `alice@example.invalid: authorized ${T} (High: gmail.readonly) — record:0/event:0; activity: 2 calls, 1,500 bytes returned, 2 methods (gmail.users.messages.get ×1, gmail.users.messages.list ×1) ${at(60)} → ${at(120)}; 2 after an authorization and before a revocation; revoked ${at(3600)} (record:3/event:0)`,
    );
    expect(r.description).toContain("bob@example.invalid: authorized");
    expect(r.description).toContain(
      "no revocation record in this export; the current grant state is not established",
    );
    expect(r.description).toContain("carol@example.invalid: authorized");
    expect(r.description).toContain("no activity record in this export");
    expect(r.description).toContain(
      "3 users authorized this client in the 7 token records of this export (2026-05-02 → 2026-05-02)",
    );
    expect(r.description).toContain(
      "the Reports API retains token events for 6 months; the export's completeness for the period is not established by this evidence",
    );
    expect(r.description).toMatch(/highest authorization covered: High\]$/);
    expect(r.description).not.toMatch(
      /under the grant|live|malicious|exfiltrat|downloaded|bypass|every user/,
    );
    expect(canonicalEventEnvelopeSchema.safeParse(r.canonical).success).toBe(true);
    expect(r.canonical?.gwsLifecycle).toMatchObject({
      clientId: CLIENT,
      tenant: TENANT,
      coveredTier: "High",
      usersBeyond: 0,
      requests: 0,
      denials: 0,
      incomplete: 0,
      coverage: { records: 7 },
    });
    const alice = r.canonical?.gwsLifecycle?.grants.find((g) => g.profileId === ALICE.profileId)!;
    expect(alice.activity).toMatchObject({ calls: 2, bytes: "1500" });
    expect(alice.revocations).toHaveLength(1);
    expect(alice.afterRevocation).toEqual({ calls: 0, reauthorized: 0 });
  });

  it("two clients with one name are two rows; the tenant is part of the identity", () => {
    const rows = lifecycles([authorize(at(0)), authorize(at(0), ALICE, [G + "gmail.readonly"], CLIENT2)]);
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.aggKey)).size).toBe(2);
    const tenants = lifecycles([
      authorize(at(0)),
      { ...authorize(at(0)), id: { time: at(0), applicationName: "token", customerId: "C02xyz" } },
    ]);
    expect(tenants).toHaveLength(2);
  });

  it("a request never opens a lifecycle; request- or deny-only clients get a bounded Low summary", () => {
    const req = lifecycles([
      token("request", [
        ...clientParams(),
        { name: "scope", multiValue: [G + "drive"] },
        { name: "requester_email", value: ALICE.email },
      ]),
    ]);
    expect(req).toHaveLength(1);
    expect(req[0].severity).toBe("Low");
    expect(req[0].description).toContain("1 access request — requested, not granted by those records");
    expect(req[0].description).toContain("0 users authorized this client");
    expect(req[0].canonical?.gwsLifecycle?.grants).toHaveLength(0);
    const deny = lifecycles([
      token("deny", [...clientParams(), { name: "rejection_type", value: "ADMIN_BLOCKED" }]),
    ]);
    expect(deny[0].description).toContain("1 denial");
  });
});

describe("what is never claimed", () => {
  it("activity after a revocation with no re-authorization is 'not established'; with one it is 'a later authorization precedes'", () => {
    const orphan = lifecycles([
      authorize(at(0)),
      activity(at(60)),
      revoke(at(120)),
      activity(at(180)),
      activity(at(240)),
    ]);
    expect(orphan[0].description).toContain(
      "after a revocation with no re-authorization in the export before them: 2 — delayed delivery of earlier calls or a live token; not established",
    );
    expect(orphan[0].canonical?.gwsLifecycle?.grants[0].afterRevocation).toEqual({
      calls: 2,
      reauthorized: 0,
    });
    const reauth = lifecycles([
      authorize(at(0)),
      activity(at(60)),
      revoke(at(120)),
      activity(at(180)),
      authorize(at(200)),
      activity(at(240)),
    ]);
    expect(reauth[0].description).toContain("re-authorized");
    expect(reauth[0].description).toContain(
      "after a revocation with no re-authorization in the export before them: 1",
    );
    expect(reauth[0].description).toContain("1 after a revocation that a later authorization precedes");
    expect(reauth[0].canonical?.gwsLifecycle?.grants[0].afterRevocation).toEqual({
      calls: 1,
      reauthorized: 1,
    });
    expect(reauth[0].description).toContain("2 after an authorization and before a revocation");
  });

  it("activity with no authorization in the export is said so and graded Medium; an equal timestamp establishes no order", () => {
    const rows = lifecycles([activity(at(0)), activity(at(60))]);
    expect(rows[0].severity).toBe("Medium");
    expect(rows[0].mitre).toEqual([]);
    expect(rows[0].description).toContain(
      "2 before any authorization in this export — the grant predates the export or was not exported",
    );
    expect(rows[0].description).toMatch(/no authorization in this export; the scopes are not known\]$/);
    expect(rows[0].canonical?.gwsLifecycle?.coveredTier).toBe("unknown");
    const equal = lifecycles([authorize(at(0)), activity(at(0))]);
    expect(equal[0].description).toContain("1 before any authorization in this export");
    expect(equal[0].description).not.toContain("after an authorization and before a revocation");
  });

  it("a wider re-authorization is said; scopes not in the record read High", () => {
    const rows = lifecycles([
      authorize(at(0), ALICE, [G + "drive.file"]),
      authorize(at(60), ALICE, [G + "drive.file", G + "gmail.readonly"]),
    ]);
    expect(rows[0].description).toContain("re-authorized with wider scopes");
    expect(rows[0].severity).toBe("High");
    const none = lifecycles([token("authorize", clientParams())]);
    expect(none[0].description).toContain("(High: scopes not in this record)");
  });

  it("identity needs a tenant, a client id and a real profile id; an email resolves only through a record stating both; placeholders join nothing", () => {
    const noTenant = { ...authorize(at(0)), id: { time: at(0), applicationName: "token" } };
    const noClient = token("authorize", [{ name: "app_name", value: "Mail Backup Pro" }]);
    const placeholder = authorize(at(0), { email: "", profileId: "105250506097979753968" });
    const rows = lifecycles([authorize(at(0)), noTenant, noClient, placeholder]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain("3 token records without a tenant, client id or user — not joined");
    expect(rows[0].canonical?.gwsLifecycle?.incomplete).toBe(3);
    // Email-only activity joins Alice through the authorization that states both her email and id.
    const emailOnly = lifecycles([authorize(at(0)), activity(at(60), { email: ALICE.email, profileId: "" })]);
    expect(emailOnly[0].canonical?.gwsLifecycle?.grants[0].activity.calls).toBe(1);
    // Two ids for one email: the email teaches nothing.
    const conflict = lifecycles([
      authorize(at(0)),
      authorize(at(0), { email: ALICE.email, profileId: BOB.profileId }),
      activity(at(60), { email: ALICE.email, profileId: "" }),
    ]);
    expect(conflict[0].canonical?.gwsLifecycle?.incomplete).toBe(1);
  });

  it("admin app-control rows join by OAUTH2_APP_ID for web applications only; logins and Drive rows are beside, never attributed", () => {
    const admin = (name: string, type = "WEB_APPLICATION", appId = CLIENT) =>
      rec(
        "admin",
        [
          {
            type: "APPLICATION_SETTINGS",
            name,
            parameters: [
              { name: "OAUTH2_APP_ID", value: appId },
              { name: "OAUTH2_APP_TYPE", value: type },
              { name: "OAUTH2_APP_NAME", value: "x" },
            ],
          },
        ],
        { id: { time: at(300) } },
      );
    const rows = lifecycles([
      authorize(at(0)),
      admin("ADD_TO_BLOCKED_OAUTH2_APPS"),
      admin("ADD_TO_TRUSTED_OAUTH2_APPS", "ANDROID", "com.example.app"),
      rec("login", [{ type: "login", name: "login_success", parameters: [] }], { id: { time: at(-120) } }),
      rec("login", [{ type: "login", name: "login_success", parameters: [] }], { id: { time: at(-3600) } }),
      rec("drive", [{ type: "access", name: "download", parameters: [] }], { id: { time: at(500) } }),
      rec("drive", [{ type: "access", name: "download", parameters: [] }], {
        id: { time: at(500) },
        actor: BOB,
      }),
      revoke(at(1000)),
      rec("drive", [{ type: "access", name: "download", parameters: [] }], { id: { time: at(1500) } }),
    ]);
    const r = rows[0];
    expect(r.description).toContain(
      `admin app control: ADD_TO_BLOCKED_OAUTH2_APPS ${at(300)} (record:1/event:0)`,
    );
    expect(r.description).not.toContain("ADD_TO_TRUSTED_OAUTH2_APPS");
    expect(r.description).toContain(
      "1 login row within 10 min of an authorization — contemporaneous, not established as the same session",
    );
    expect(r.description).toContain(
      "1 Drive event by this user between an authorization and a revocation — not attributed to the app",
    );
    expect(r.canonical?.gwsLifecycle?.grants[0]).toMatchObject({
      contemporaneousLogins: 1,
      driveEventsInWindow: 1,
    });
    expect(r.canonical?.gwsLifecycle?.adminControls).toHaveLength(1);
  });
});

describe("bounds, identity, the importer", () => {
  it("totals cover every activity record: bytes as a big integer, methods beyond the tracked bound counted; 17 users → the rest counted", () => {
    const big = lifecycles([
      authorize(at(0)),
      activity(at(10), ALICE, "gmail.users.messages.get", "9007199254740993"),
      activity(at(20), ALICE, "gmail.users.messages.get", "9007199254740993"),
      ...Array.from({ length: METHODS_TRACKED_MAX + 3 }, (_, i) =>
        activity(at(30 + i), ALICE, `m.${i}`, "1"),
      ),
    ]);
    expect(big[0].canonical?.gwsLifecycle?.grants[0].activity.bytes).toBe("18014398509482053");
    expect(big[0].description).toContain("18,014,398,509,482,053 bytes returned");
    expect(big[0].description).toContain(`4 calls to methods beyond the tracked ${METHODS_TRACKED_MAX}`);
    expect(big[0].canonical?.gwsLifecycle?.grants[0].activity.calls).toBe(METHODS_TRACKED_MAX + 5);
    const many = lifecycles(
      Array.from({ length: USERS_NAMED_MAX + 1 }, (_, i) =>
        authorize(at(i), {
          email: `u${i}@example.invalid`,
          profileId: `1000000000000000${String(i).padStart(5, "0")}`,
        }),
      ),
    );
    expect(many[0].description).toContain("+1 more user");
    expect(many[0].canonical?.gwsLifecycle?.usersBeyond).toBe(1);
    expect(many[0].description).toContain(`${USERS_NAMED_MAX + 1} users authorized this client`);
  });

  it("257 clients → the rest counted with the omitted grade, risk first; hostile names neutralised", () => {
    const many = Array.from({ length: GWS_LIFECYCLES_MAX + 2 }, (_, i) =>
      authorize(
        at(i),
        ALICE,
        [G + "userinfo.email"],
        `${String(i).padStart(12, "0")}-x.apps.googleusercontent.com`,
      ),
    );
    const high = authorize(at(0), ALICE, [G + "gmail.readonly"], CLIENT2);
    const rows = lifecycles([...many, high]);
    expect(rows).toHaveLength(GWS_LIFECYCLES_MAX + 1);
    expect(rows[0].canonical?.gwsLifecycle?.clientId).toBe(CLIENT2);
    const omitted = rows.find((r) => r.description.includes("further clients"))!;
    expect(omitted.description).toContain(
      `3 further clients with a lifecycle in this export beyond the ${GWS_LIFECYCLES_MAX} reported — not shown`,
    );
    expect(omitted.severity).toBe("Low");
    const evil = lifecycles([
      token("authorize", [
        ...clientParams(CLIENT, "Mail] [fake: x"),
        { name: "scope", multiValue: [G + "drive"] },
      ]),
    ]);
    expect(evil[0].description).not.toContain("] [fake");
  });

  it("the row's identity is (tenant, client id); a re-import folds at merge; the importer appends after the cap and counts source rows alone", () => {
    const records = [authorize(at(0)), activity(at(60)), revoke(at(120))];
    const a = rowsOf(records);
    const b = rowsOf(records);
    const rowsA = a.events.filter((e) => e.description.startsWith("Google Workspace OAuth lifecycle:"));
    expect(rowsA).toHaveLength(1);
    expect(rowsA[0].aggKey).toBe(
      b.events.find((e) => e.description.startsWith("Google Workspace OAuth lifecycle:"))!.aggKey,
    );
    expect(rowsA[0].aggKey).toMatch(/^gws-oauth-lifecycle\|[0-9a-f]{32}$/);
    const asEvents = (tag: string): ForensicEvent[] =>
      rowsOf(records)
        .events.filter((e) => e.description.startsWith("Google Workspace OAuth lifecycle:"))
        .map((e, i) => ({
          ...e,
          id: `${tag}-${i}`,
          relatedFindingIds: [],
          sourceScreenshots: [],
          sources: ["Google Workspace"],
        }));
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(1);
    const capped = rowsOf(records, { maxEvents: 1 });
    expect(
      capped.events.filter((e) => e.description.startsWith("Google Workspace OAuth lifecycle:")),
    ).toHaveLength(1);
    expect(capped.kept).toBe(1);
    expect(capped.summaries).toBe(1);
    expect(capped.dropped).toBe(2);
  });
});
