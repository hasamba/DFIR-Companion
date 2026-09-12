import { describe, it, expect } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";
import { canonicalConformanceIssues } from "../../src/analysis/canonicalEvent.js";

function act(over: Record<string, unknown> = {}): Record<string, unknown> {
  const { events, id, ...rest } = over as {
    events?: unknown;
    id?: Record<string, unknown>;
  } & Record<string, unknown>;
  return {
    kind: "admin#reports#activity",
    id: {
      time: "2026-05-02T10:00:00.000Z",
      uniqueQualifier: "-1",
      applicationName: "login",
      customerId: "C01abc",
      ...(id ?? {}),
    },
    actor: { email: "jdoe@example.invalid", profileId: "1234" },
    ipAddress: "203.0.113.10",
    events: events ?? [{ type: "login", name: "login_success", parameters: [] }],
    ...rest,
  };
}

describe("parseGoogleWorkspaceReport", () => {
  it("reports an empty result for empty input", () => {
    const r = parseGoogleWorkspaceReport("");
    expect(r.total).toBe(0);
    expect(r.format).toBe("empty");
  });

  it("unwraps the API's { items: [...] } envelope as well as a bare array", () => {
    const one = act();
    const wrapped = parseGoogleWorkspaceReport(JSON.stringify({ items: [one] }));
    const bare = parseGoogleWorkspaceReport(JSON.stringify([one]));
    expect(wrapped.events).toHaveLength(1);
    expect(bare.events).toHaveLength(1);
    expect(wrapped.events[0].description).toBe(bare.events[0].description);
  });

  it("maps a successful login to Info and records the actor and source IP", () => {
    const r = parseGoogleWorkspaceReport(JSON.stringify([act()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("jdoe@example.invalid");
    expect(r.events[0].description).toContain("203.0.113.10");
    expect(r.iocs.map((i) => i.value)).toContain("203.0.113.10");
    expect(r.events[0].sources).toContain("Google Workspace");
  });

  it("escalates a failed login with the brute-force technique", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([act({ events: [{ type: "login", name: "login_failure" }] })]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });

  it("treats a suspicious login as High", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([act({ events: [{ type: "login", name: "suspicious_login" }] })]),
    );
    expect(r.events[0].severity).toBe("High");
  });

  it("treats turning off 2-step verification as High MFA modification", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          id: { applicationName: "admin" },
          events: [{ type: "security", name: "UNENROLL_USER_FROM_STRONG_AUTH" }],
        }),
      ]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1556.006");
  });

  it("treats an email monitor (mail interception) as High", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          id: { applicationName: "admin" },
          events: [{ type: "EMAIL_MONITOR", name: "CREATE_EMAIL_MONITOR" }],
        }),
      ]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1114");
  });

  it("treats an admin privilege grant as High", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          id: { applicationName: "admin" },
          events: [{ type: "DELEGATED_ADMIN_SETTINGS", name: "GRANT_ADMIN_PRIVILEGE" }],
        }),
      ]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1098.003");
  });

  it("treats an OAuth token authorization as High application-access", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({ id: { applicationName: "token" }, events: [{ type: "auth", name: "authorize" }] }),
      ]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1528");
  });

  it("names the target parameter so the affected user or file is visible", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          id: { applicationName: "admin" },
          events: [
            {
              type: "USER_SETTINGS",
              name: "CHANGE_PASSWORD",
              parameters: [{ name: "USER_EMAIL", value: "victim@example.invalid" }],
            },
          ],
        }),
      ]),
    );
    expect(r.events[0].description).toContain("victim@example.invalid");
  });

  it("fans one record with two events out into two timeline events", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          events: [
            { type: "login", name: "login_success" },
            { type: "login", name: "logout" },
          ],
        }),
      ]),
    );
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(2);
  });

  it("keeps an unknown event name at Info rather than dropping it", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([act({ events: [{ type: "future", name: "SOMETHING_NEW" }] })]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
  });

  it("ignores a record that is not a Workspace activity", () => {
    const r = parseGoogleWorkspaceReport(JSON.stringify([{ hello: "world" }]));
    expect(r.events).toHaveLength(0);
  });

  it("honours a minimum-severity floor", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act(),
        act({ id: { applicationName: "token" }, events: [{ type: "auth", name: "authorize" }] }),
      ]),
      { minSeverity: "High" },
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });
});

// #931 item 10 — the token application's rows say which app, which scopes, what it called.
describe("parseGoogleWorkspaceReport — OAuth token rows", () => {
  const G = "https://www.googleapis.com/auth/";
  const CLIENT = "123456789012-abcdefghijklmnop.apps.googleusercontent.com";
  const clientParams = [
    { name: "client_id", value: CLIENT },
    { name: "app_name", value: "Mail Backup Pro" },
    { name: "client_type", value: "WEB" },
  ];
  const token = (name: string, parameters: unknown[], over: { id?: Record<string, unknown> } = {}) =>
    act({
      ...over,
      id: { applicationName: "token", ...(over.id ?? {}) },
      events: [{ type: "auth", name, parameters }],
    });

  it("an authorize row names the app, client, scopes and the record's limit; the envelope has the user as actor and the client as object", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        token("authorize", [
          ...clientParams,
          { name: "scope", multiValue: [G + "gmail.readonly", "openid"] },
        ]),
      ]),
    );
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1528");
    expect(e.description).toBe(
      `Google Workspace token: authorize by jdoe@example.invalid from 203.0.113.10 authorises Mail Backup Pro (client ${CLIENT}, WEB) for 2 scopes: gmail.readonly, openid — authorization recorded; this record does not evidence API use`,
    );
    expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
    expect(e.canonical?.event).toMatchObject({
      category: "cloud",
      type: "oauth",
      action: "authorize",
      outcome: "success",
    });
    expect(e.canonical?.actor).toEqual({ kind: "account", name: "jdoe@example.invalid", id: "1234" });
    expect(e.canonical?.object).toEqual({ kind: "cloud_principal", id: CLIENT, name: "Mail Backup Pro" });
    expect(e.canonical?.subject).toBeUndefined();
    // The cloud principal follows the actor: the user's profile id, typed as a user; the client is
    // the object, never a "user" principal.
    expect(e.canonical?.cloud).toEqual({
      provider: "google-workspace",
      tenant: "C01abc",
      principalId: "1234",
      principalType: "user",
    });
    expect(e.canonical?.fieldProvenance["cloud.principalId"]).toMatchObject({
      rawFields: ["actor.profileId"],
    });
    expect(e.canonical?.network?.source?.address).toBe("203.0.113.10");
    expect(e.canonical?.evidence.rawRecords).toEqual([
      { source: "google-workspace", locator: "record:0/event:0", recordId: "-1" },
    ]);
    expect(e.canonical?.evidence.sourceArtifactHash).toMatch(/^sha256:/);
    expect(e.canonical?.fieldProvenance["actor.id"]).toMatchObject({
      origin: "raw",
      rawFields: ["actor.profileId"],
    });
    expect(e.canonical?.fieldProvenance["object.id"]).toMatchObject({
      origin: "raw",
      rawFields: ["client_id"],
    });
  });

  it("an activity row has the client as actor, the user as subject, and the API method as the resource", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        token("activity", [
          ...clientParams,
          { name: "api_name", value: "drive" },
          { name: "method_name", value: "drive.files.get" },
          { name: "num_response_bytes", intValue: "4096" },
          { name: "product_bucket", multiValue: ["DRIVE"] },
        ]),
      ]),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("API call drive.drive.files.get by Mail Backup Pro");
    expect(e.description).toContain("4096 bytes returned");
    expect(e.description).toMatch(/bytes returned are not proof that file contents were downloaded$/);
    expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
    expect(e.canonical?.actor).toEqual({ kind: "cloud_principal", id: CLIENT, name: "Mail Backup Pro" });
    expect(e.canonical?.subject).toEqual({ kind: "account", name: "jdoe@example.invalid", id: "1234" });
    expect(e.canonical?.object).toBeUndefined();
    expect(e.canonical?.cloud).toMatchObject({
      principalId: CLIENT,
      principalType: "application",
      resource: "drive.drive.files.get",
    });
    expect(e.canonical?.fieldProvenance["cloud.resource"]).toMatchObject({
      rawFields: ["api_name", "method_name"],
    });
  });

  it("request, deny and revoke rows carry the envelope with the user as actor; no resource is invented", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        token("request", [...clientParams, { name: "scope", multiValue: [G + "drive"] }]),
        token("deny", [...clientParams, { name: "rejection_type", value: "ADMIN_BLOCKED" }]),
        token("revoke", clientParams),
      ]),
      { aggregate: false },
    );
    expect(r.events).toHaveLength(3);
    for (const e of r.events) {
      expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
      expect(e.canonical?.actor?.kind).toBe("account");
      expect(e.canonical?.object?.id).toBe(CLIENT);
      expect(e.canonical?.cloud?.resource).toBeUndefined();
      expect(e.severity).toBe("Low");
    }
    expect(r.events[0].description).toContain("requests access");
    expect(r.events[0].canonical?.subject).toBeUndefined();
    expect(r.events[1].description).toContain("denied access");
    expect(r.events[1].description).toContain("ADMIN_BLOCKED");
    expect(r.events[2].description).toContain("revokes Mail Backup Pro");
  });

  it("two customers' identical rows are two rows — token and Drive alike; one customer's duplicates fold", () => {
    const auth = (customerId: string) =>
      token("authorize", [...clientParams, { name: "scope", multiValue: [G + "drive"] }], {
        id: { customerId },
      });
    const drive = (customerId: string) =>
      act({
        id: { applicationName: "drive", customerId },
        events: [
          {
            type: "access",
            name: "download",
            parameters: [
              { name: "doc_id", value: "doc-1" },
              { name: "doc_title", value: "Q3 plan" },
            ],
          },
        ],
      });
    expect(parseGoogleWorkspaceReport(JSON.stringify([auth("C01abc"), auth("C02xyz")])).events).toHaveLength(
      2,
    );
    expect(parseGoogleWorkspaceReport(JSON.stringify([auth("C01abc"), auth("C01abc")])).events).toHaveLength(
      1,
    );
    expect(
      parseGoogleWorkspaceReport(JSON.stringify([drive("C01abc"), drive("C02xyz")])).events,
    ).toHaveLength(2);
    expect(
      parseGoogleWorkspaceReport(JSON.stringify([drive("C01abc"), drive("C01abc")])).events,
    ).toHaveLength(1);
    // A Drive row reads as before — the tenant is in its key, not its words.
    const d = parseGoogleWorkspaceReport(JSON.stringify([drive("C01abc")])).events[0];
    expect(d.description).toBe(
      "Google Workspace drive: download by jdoe@example.invalid → Q3 plan from 203.0.113.10",
    );
    expect(d.canonical).toBeUndefined();
  });

  it("an authorize row with no scope reads High with 'scopes not in this record'; a per-file grant reads Low", () => {
    const none = parseGoogleWorkspaceReport(JSON.stringify([token("authorize", clientParams)])).events[0];
    expect(none.severity).toBe("High");
    expect(none.description).toContain("scopes not in this record");
    const file = parseGoogleWorkspaceReport(
      JSON.stringify([
        token("authorize", [...clientParams, { name: "scope", multiValue: [G + "drive.file"] }]),
      ]),
    ).events[0];
    expect(file.severity).toBe("Low");
    expect(file.mitreTechniques ?? []).not.toContain("T1528");
  });

  it("a request that names a requester carries that account as the envelope's subject", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        token("request", [
          ...clientParams,
          { name: "scope", multiValue: [G + "gmail.readonly"] },
          { name: "requester_email", value: "bob@example.invalid" },
        ]),
      ]),
    );
    const e = r.events[0];
    expect(e.description).toContain("requester bob@example.invalid");
    expect(e.canonical?.actor).toEqual({ kind: "account", name: "jdoe@example.invalid", id: "1234" });
    expect(e.canonical?.subject).toEqual({ kind: "account", name: "bob@example.invalid" });
    expect(e.canonical?.fieldProvenance["subject.name"]).toMatchObject({ rawFields: ["requester_email"] });
    expect(canonicalConformanceIssues(e.canonical)).toEqual([]);
  });

  it("two authorizations with no client id never fold, even under one display name", () => {
    const noId = (appName: string, uniqueQualifier: string) =>
      token(
        "authorize",
        [
          { name: "app_name", value: appName },
          { name: "scope", multiValue: [G + "drive"] },
        ],
        { id: { uniqueQualifier } },
      );
    const r = parseGoogleWorkspaceReport(JSON.stringify([noId("App A", "q-1"), noId("App B", "q-2")]));
    expect(r.events).toHaveLength(2);
    const same = parseGoogleWorkspaceReport(JSON.stringify([noId("App A", "q-1"), noId("App A", "q-2")]));
    expect(same.events).toHaveLength(2);
    // With the client id present the display name is a label: one client, two names, one row.
    const withId = (appName: string) =>
      token("authorize", [
        { name: "client_id", value: CLIENT },
        { name: "app_name", value: appName },
        { name: "scope", multiValue: [G + "drive"] },
      ]);
    expect(
      parseGoogleWorkspaceReport(JSON.stringify([withId("App A"), withId("App B")])).events,
    ).toHaveLength(1);
  });

  it("a second event in one record gets its own locator", () => {
    const r = parseGoogleWorkspaceReport(
      JSON.stringify([
        act({
          id: { applicationName: "token" },
          events: [
            {
              type: "auth",
              name: "authorize",
              parameters: [...clientParams, { name: "scope", multiValue: [G + "drive"] }],
            },
            { type: "auth", name: "revoke", parameters: clientParams },
          ],
        }),
      ]),
      { aggregate: false },
    );
    expect(r.events.map((e) => e.canonical?.evidence.rawRecords[0].locator)).toEqual([
      "record:0/event:0",
      "record:0/event:1",
    ]);
  });
});
