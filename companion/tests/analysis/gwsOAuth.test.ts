// #931 item 10 — Google Workspace OAuth: the typed parameter reader and the token decoder.
import { describe, expect, it } from "vitest";
import {
  decodeGwsToken,
  GWS_SCOPE_TIERS,
  readGwsParams,
  scopeTier,
  type GwsParam,
} from "../../src/analysis/gwsOAuth.js";

const G = "https://www.googleapis.com/auth/";
const CLIENT = "123456789012-abcdefghijklmnop.apps.googleusercontent.com";

const p = (name: string, over: Record<string, unknown> = {}) => ({ name, ...over });
const value = (name: string, v: string) => p(name, { value: v });
const multi = (name: string, v: string[]) => p(name, { multiValue: v });
const client = (over: Record<string, unknown>[] = []) => [
  value("client_id", CLIENT),
  value("app_name", "Mail Backup Pro"),
  value("client_type", "WEB"),
  ...over,
];
const params = (list: Record<string, unknown>[]): GwsParam[] =>
  readGwsParams({ name: "x", parameters: list });

describe("readGwsParams — every Reports API value kind, by its kind", () => {
  it("reads value, multiValue, intValue (a string of digits or a number), boolValue", () => {
    const out = params([
      value("app_name", "App"),
      multi("scope", [G + "gmail.readonly", G + "drive"]),
      p("num_response_bytes", { intValue: "12345" }),
      p("other_count", { intValue: 7 }),
      p("flag", { boolValue: true }),
    ]);
    expect(out).toEqual([
      { name: "app_name", value: "App" },
      { name: "scope", multiValue: [G + "gmail.readonly", G + "drive"] },
      { name: "num_response_bytes", intValue: 12345 },
      { name: "other_count", intValue: 7 },
      { name: "flag", boolValue: true },
    ]);
    expect(typeof out[2].intValue).toBe("number");
  });
  it("reads a singular messageValue and a multiMessageValue into one list of messages each", () => {
    const single = params([
      p("scope_data", {
        messageValue: {
          parameter: [value("scope_name", G + "gmail.readonly"), multi("product_bucket", ["GMAIL"])],
        },
      }),
    ]);
    expect(single[0].messages).toEqual([
      [
        { name: "scope_name", value: G + "gmail.readonly" },
        { name: "product_bucket", multiValue: ["GMAIL"] },
      ],
    ]);
    const many = params([
      p("scope_data", {
        multiMessageValue: [
          { parameter: [value("scope_name", G + "drive"), multi("product_bucket", ["DRIVE"])] },
          { parameter: [value("scope_name", G + "gmail.readonly"), multi("product_bucket", ["GMAIL"])] },
        ],
      }),
    ]);
    expect(many[0].messages).toHaveLength(2);
    expect(many[0].messages?.[1][0]).toEqual({ name: "scope_name", value: G + "gmail.readonly" });
  });
  it("bounds the entries and the nesting depth", () => {
    const wide = params(Array.from({ length: 100 }, (_, i) => value(`p${i}`, "v")));
    expect(wide).toHaveLength(64);
    // depth: parameters → message → message → message — the fourth level is not read
    const deep = params([
      p("l1", {
        messageValue: {
          parameter: [
            p("l2", {
              messageValue: {
                parameter: [p("l3", { messageValue: { parameter: [value("l4", "gone")] } })],
              },
            }),
          ],
        },
      }),
    ]);
    const l2 = deep[0].messages?.[0][0];
    const l3 = l2?.messages?.[0][0];
    expect(l3?.name).toBe("l3");
    expect(l3?.messages).toBeUndefined();
  });
  it("tolerates malformed shapes: a string, an object, nulls, a nameless entry, a non-object event", () => {
    expect(readGwsParams({ parameters: "scope" })).toEqual([]);
    expect(readGwsParams({ parameters: { name: "scope" } })).toEqual([]);
    expect(readGwsParams({ parameters: [null, 3, { value: "no name" }, value("ok", "v")] })).toEqual([
      { name: "ok", value: "v" },
    ]);
    expect(readGwsParams("not an event")).toEqual([]);
    expect(readGwsParams(null)).toEqual([]);
    // a multiValue with non-strings keeps the strings only; an unreadable intValue is dropped
    expect(params([p("scope", { multiValue: ["a", 1, null] }), p("n", { intValue: "abc" })])).toEqual([
      { name: "scope", multiValue: ["a"] },
      { name: "n" },
    ]);
  });
});

describe("decodeGwsToken — authorize: the grant, graded by its scopes", () => {
  it("names the app, the client id and type, the scope count and classes; High + T1528 for mail read", () => {
    const d = decodeGwsToken(
      "authorize",
      params(client([multi("scope", [G + "gmail.readonly", "openid"])])),
    )!;
    expect(d.kind).toBe("authorize");
    expect(d.severity).toBe("High");
    expect(d.mitre).toEqual(["T1528"]);
    expect(d.posture).toBe("authorises");
    expect(d.object).toBe(`Mail Backup Pro (client ${CLIENT}, WEB)`);
    expect(d.optional).toEqual(["for 2 scopes: gmail.readonly, openid"]);
    expect(d.qualifiers).toEqual(["authorization recorded; this record does not evidence API use"]);
    expect(d.scopes).toEqual([G + "gmail.readonly", "openid"]);
  });
  it("reads scope from a scalar value and from scope_data, unions and sorts them", () => {
    const d = decodeGwsToken(
      "authorize",
      params(
        client([
          value("scope", G + "drive.readonly"),
          p("scope_data", {
            multiMessageValue: [
              { parameter: [value("scope_name", G + "drive.readonly"), multi("product_bucket", ["DRIVE"])] },
              {
                parameter: [
                  value("scope_name", G + "calendar.readonly"),
                  multi("product_bucket", ["CALENDAR"]),
                ],
              },
            ],
          }),
        ]),
      ),
    )!;
    expect(d.scopes).toEqual([G + "calendar.readonly", G + "drive.readonly"]);
    expect(d.productBuckets).toEqual(["CALENDAR", "DRIVE"]);
    expect(d.severity).toBe("High");
  });
  it("grades per-file Drive and identity-only scopes Low, an unknown non-identity scope Medium", () => {
    expect(decodeGwsToken("authorize", params(client([multi("scope", [G + "drive.file"])])))!.severity).toBe(
      "Low",
    );
    expect(
      decodeGwsToken("authorize", params(client([multi("scope", ["openid", "email", "profile"])])))!.severity,
    ).toBe("Low");
    const unknown = decodeGwsToken("authorize", params(client([multi("scope", [G + "future.scope"])])))!;
    expect(unknown.severity).toBe("Medium");
    expect(unknown.mitre).toEqual([]);
  });
  it("with no scope in the record: High, 'scopes not in this record', no count claimed", () => {
    const d = decodeGwsToken("authorize", params(client()))!;
    expect(d.severity).toBe("High");
    expect(d.optional).toEqual(["scopes not in this record"]);
    expect(d.scopes).toEqual([]);
    expect(d.scopeDigest).toBe("");
  });
  it("bounds the class list to four and counts the rest", () => {
    const scopes = Array.from({ length: 10 }, (_, i) => `${G}s${i}.readonly`);
    const d = decodeGwsToken("authorize", params(client([multi("scope", scopes)])))!;
    expect(d.optional[0]).toBe("for 10 scopes: s0.readonly, s1.readonly, s2.readonly, s3.readonly (+6)");
  });
  it("keys on the client id and the scope set: two apps with one name are two, a reordered duplicate is one", () => {
    const a = decodeGwsToken(
      "authorize",
      params(client([multi("scope", [G + "drive", G + "gmail.readonly"])])),
    )!;
    const b = decodeGwsToken(
      "authorize",
      params(client([multi("scope", [G + "gmail.readonly", G + "drive", G + "drive"])])),
    )!;
    const c = decodeGwsToken(
      "authorize",
      params([
        value("client_id", "999-other.apps.googleusercontent.com"),
        value("app_name", "Mail Backup Pro"),
        multi("scope", [G + "drive", G + "gmail.readonly"]),
      ]),
    )!;
    const d = decodeGwsToken("authorize", params(client([multi("scope", [G + "drive"])])))!;
    expect(a.keySegment).toBe(b.keySegment);
    expect(a.keySegment).not.toBe(c.keySegment);
    expect(a.keySegment).not.toBe(d.keySegment);
    expect(a.keySegment).toContain(`|oauth:authorize|${CLIENT}|`);
  });
  it("the client words survive a missing name, id or type", () => {
    expect(decodeGwsToken("authorize", params([value("client_id", CLIENT)]))!.object).toBe(
      `client ${CLIENT}`,
    );
    expect(decodeGwsToken("authorize", params([value("app_name", "App")]))!.object).toBe(
      "App (client id not in this record)",
    );
  });
});

describe("GWS_SCOPE_TIERS — a literal, exhaustive table", () => {
  const high = [
    "https://mail.google.com/",
    ...[
      "gmail.readonly",
      "gmail.modify",
      "gmail.insert",
      "gmail.compose",
      "gmail.send",
      "gmail.settings.basic",
      "gmail.settings.sharing",
      "drive",
      "drive.readonly",
      "documents",
      "documents.readonly",
      "spreadsheets",
      "spreadsheets.readonly",
      "presentations",
      "presentations.readonly",
      "calendar",
      "calendar.events",
      "calendar.acls",
      "contacts",
      "contacts.other.readonly",
      "admin.directory.user",
      "admin.directory.user.readonly",
      "admin.directory.group",
      "admin.directory.group.readonly",
      "admin.directory.orgunit",
      "admin.directory.device.mobile",
      "admin.directory.device.chromeos",
      "admin.directory.customer",
      "admin.directory.domain",
      "admin.directory.rolemanagement",
      "admin.reports.audit.readonly",
      "admin.reports.usage.readonly",
      "apps.groups.settings",
      "ediscovery",
      "cloud-platform",
      "script.projects",
      "script.external_request",
      "script.scriptapp",
      "script.deployments",
      "chat.messages",
      "chat.messages.readonly",
      "chat.spaces",
    ].map((s) => G + s),
  ];
  const medium = [
    "gmail.metadata",
    "gmail.labels",
    "drive.metadata",
    "drive.metadata.readonly",
    "drive.photos.readonly",
    "drive.activity",
    "drive.activity.readonly",
    "calendar.readonly",
    "calendar.events.readonly",
    "calendar.settings.readonly",
    "contacts.readonly",
    "keep",
    "keep.readonly",
    "tasks",
    "tasks.readonly",
    "chat.spaces.readonly",
    "directory.readonly",
    "user.addresses.read",
    "user.birthday.read",
    "user.emails.read",
    "user.phonenumbers.read",
  ].map((s) => G + s);
  const low = [
    ...["drive.file", "drive.appdata", "drive.install", "userinfo.email", "userinfo.profile"].map(
      (s) => G + s,
    ),
    "openid",
    "email",
    "profile",
  ];
  it("every listed URI has its tier and the table holds exactly these", () => {
    for (const s of high) expect(scopeTier(s), s).toBe("High");
    for (const s of medium) expect(scopeTier(s), s).toBe("Medium");
    for (const s of low) expect(scopeTier(s), s).toBe("Low");
    expect(Object.keys(GWS_SCOPE_TIERS).sort()).toEqual([...high, ...medium, ...low].sort());
  });
  it("has no family shorthand: every key is a full URI or an OpenID Connect scope", () => {
    for (const k of Object.keys(GWS_SCOPE_TIERS)) {
      expect(k.startsWith("https://") || ["openid", "email", "profile"].includes(k), k).toBe(true);
    }
    expect(scopeTier("gmail")).toBe("Medium"); // a bare family name is unknown, not a match
    expect(scopeTier(G + "gmail.readonly ")).toBe("High"); // whitespace tolerated
    expect(scopeTier("")).toBe("Medium");
  });
});

describe("decodeGwsToken — activity: the API call, Info, with its bytes", () => {
  const activity = (extra: Record<string, unknown>[] = []) =>
    decodeGwsToken(
      "activity",
      params(
        client([
          value("api_name", "drive"),
          value("method_name", "drive.files.get"),
          multi("product_bucket", ["DRIVE"]),
          ...extra,
        ]),
      ),
    )!;
  it("names the API and method, the client, the bytes returned and the qualifier", () => {
    const d = activity([p("num_response_bytes", { intValue: "4096" })]);
    expect(d.kind).toBe("activity");
    expect(d.severity).toBe("Info");
    expect(d.mitre).toEqual([]);
    expect(d.posture).toBe("API call drive.drive.files.get");
    expect(d.object).toBe(`by Mail Backup Pro (client ${CLIENT})`);
    expect(d.optional).toEqual(["4096 bytes returned", "product DRIVE"]);
    expect(d.qualifiers).toEqual(["bytes returned are not proof that file contents were downloaded"]);
    expect(d.bytes).toBe(4096);
    expect(d.api).toEqual({ name: "drive", method: "drive.files.get" });
  });
  it("claims no bytes when the record carries none", () => {
    const d = activity();
    expect(d.bytes).toBeUndefined();
    expect(d.optional).toEqual(["product DRIVE"]);
    expect(d.qualifiers).toEqual([]);
  });
  it("two calls to one method with different sizes are two rows", () => {
    const a = activity([p("num_response_bytes", { intValue: "10" })]);
    const b = activity([p("num_response_bytes", { intValue: "999999" })]);
    const c = activity([p("num_response_bytes", { intValue: "10" })]);
    expect(a.keySegment).not.toBe(b.keySegment);
    expect(a.keySegment).toBe(c.keySegment);
    expect(a.keySegment).toContain("|drive.drive.files.get:10:DRIVE");
  });
  it("says when the method is not in the record", () => {
    const d = decodeGwsToken("activity", params(client()))!;
    expect(d.posture).toBe("API call (method not in this record)");
  });
});

describe("decodeGwsToken — request, deny, revoke: what one record establishes", () => {
  it("request: Low, the classes, the requester, and 'not granted by this record'", () => {
    const d = decodeGwsToken(
      "request",
      params(
        client([multi("scope", [G + "gmail.readonly"]), value("requester_email", "bob@example.invalid")]),
      ),
    )!;
    expect(d.kind).toBe("request");
    expect(d.severity).toBe("Low");
    expect(d.posture).toBe("requests access:");
    expect(d.object).toBe(`Mail Backup Pro (client ${CLIENT}, WEB)`);
    expect(d.optional).toEqual(["for 1 scope: gmail.readonly", "requester bob@example.invalid"]);
    expect(d.qualifiers).toEqual(["access requested, not granted by this record"]);
    expect(d.keySegment).toContain("|:bob@example.invalid:");
  });
  it("a delegated request claims no scope count and says Google does not display the scopes", () => {
    const d = decodeGwsToken(
      "request",
      params(
        client([value("app_request_info", "APP_REQUEST_TYPE_DELEGATED"), multi("scope", [G + "drive"])]),
      ),
    )!;
    expect(d.optional).toEqual(["delegated request — Google does not display the requested scopes"]);
    expect(d.keySegment).toContain("|APP_REQUEST_TYPE_DELEGATED::");
    const other = decodeGwsToken("request", params(client([value("app_request_info", "OTHER_KIND")])))!;
    expect(other.optional).toEqual(["scopes not in this record", "OTHER_KIND"]);
  });
  it("deny: Low, the rejection type verbatim in the words and the key", () => {
    const d = decodeGwsToken("deny", params(client([value("rejection_type", "ADMIN_BLOCKED")])))!;
    expect(d.severity).toBe("Low");
    expect(d.posture).toBe("denied access:");
    expect(d.object).toBe(`Mail Backup Pro (client ${CLIENT}, WEB)`);
    expect(d.optional).toEqual(["rejection ADMIN_BLOCKED"]);
    expect(d.keySegment).toContain("|::ADMIN_BLOCKED");
    expect(decodeGwsToken("deny", params(client()))!.optional).toEqual(["rejection type not in this record"]);
  });
  it("revoke: Low, the client, the scopes when present, no claim about what followed", () => {
    const withScope = decodeGwsToken(
      "revoke",
      params(client([multi("scope", [G + "drive", G + "gmail.readonly"])])),
    )!;
    expect(withScope.severity).toBe("Low");
    expect(withScope.posture).toBe("revokes");
    expect(withScope.optional).toEqual(["scopes: drive, gmail.readonly"]);
    expect(withScope.qualifiers).toEqual([]);
    const without = decodeGwsToken("revoke", params(client()))!;
    expect(without.optional).toEqual([]);
    expect(without.keySegment).toContain(`|oauth:revoke|${CLIENT}|`);
  });
  it("returns null for an event the token application does not carry", () => {
    expect(decodeGwsToken("login_success", params(client()))).toBeNull();
    expect(decodeGwsToken("", [])).toBeNull();
  });
  it("bounds attacker-shaped words", () => {
    const d = decodeGwsToken(
      "deny",
      params([
        value("client_id", "c".repeat(300)),
        value("app_name", "a".repeat(300)),
        value("client_type", "t".repeat(300)),
        value("rejection_type", "r".repeat(300)),
      ]),
    )!;
    expect(d.object.length).toBeLessThan(220);
    expect(d.optional[0].length).toBeLessThanOrEqual(90);
    expect(d.client.id).toBe("c".repeat(300)); // the identity itself is whole in the key
  });
});
