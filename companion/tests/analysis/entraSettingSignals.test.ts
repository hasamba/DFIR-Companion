// #2604 items 5–7 — Entra directory changes graded by the property delta the record itself holds:
// the per-user MFA requirement cleared, user consent opened to every user, and the advanced
// auditing plan disabled in a user's licence. Both export shapes (the UAL AzureActiveDirectory
// record and the Graph directoryAudits object) are exercised through the public import path.
// Synthetic records: example.test names, documentation IPs, invented ids. The licence detail keeps
// the real nesting — ExtendedProperties.additionalDetails is JSON whose `b` is a JSON string whose
// `targetUpdatedProperties` is a JSON string — and the real chunking (`seq` 1 of `c`, `b` cut at
// 10,000 characters, so `b` alone does not parse).
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

const TENANT = "00000000-0000-4000-8000-0000000000aa";
const ADMIN_ID = "33333333-0000-4000-8000-000000000001";
const USER_ID = "44444444-0000-4000-8000-000000000002";
const USER2_ID = "44444444-0000-4000-8000-000000000003";
const SKU = "55555555-0000-4000-8000-000000000004";
const POLICY_ID = "66666666-0000-4000-8000-000000000005";
const MFA_ON =
  '[\r\n  {\r\n    "RelyingParty": "*",\r\n    "State": 1,\r\n    "RememberDevicesNotIssuedBefore": "2026-03-07T20:17:18+00:00"\r\n  }\r\n]';
const CONSENT = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy";

const ual = (operation: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  CreationTime: "2026-06-03T07:00:15",
  Id: "00000000-0000-4000-8000-00000000f001",
  Operation: operation,
  OrganizationId: TENANT,
  RecordType: 8,
  ResultStatus: "Success",
  UserKey: "1000000000000001@example.test",
  UserType: 0,
  Version: 1,
  Workload: "AzureActiveDirectory",
  ObjectId: "dana@example.test",
  UserId: "operator@example.test",
  ClientIP: "203.0.113.41",
  AzureActiveDirectoryEventType: 1,
  ExtendedProperties: [
    { Name: "additionalDetails", Value: '{"UserType":"Member"}' },
    { Name: "extendedAuditEventCategory", Value: "User" },
  ],
  ModifiedProperties: [],
  Actor: [
    { ID: "operator@example.test", Type: 5 },
    { ID: "1000000000000001", Type: 3 },
    { ID: `User_${ADMIN_ID}`, Type: 2 },
    { ID: ADMIN_ID, Type: 2 },
    { ID: "User", Type: 2 },
  ],
  ActorContextId: TENANT,
  Target: [
    { ID: `User_${USER_ID}`, Type: 2 },
    { ID: USER_ID, Type: 2 },
    { ID: "User", Type: 2 },
    { ID: "dana@example.test", Type: 5 },
    { ID: "1000000000000002", Type: 3 },
  ],
  TargetContextId: TENANT,
  ...over,
});

const mfaProps = (oldValue: string, newValue: string) => [
  { Name: "StrongAuthenticationRequirement", OldValue: oldValue, NewValue: newValue },
  { Name: "Included Updated Properties", OldValue: "", NewValue: "StrongAuthenticationRequirement" },
  { Name: "TargetId.UserType", OldValue: "", NewValue: "Member" },
];

const graph = (activity: string, targets: unknown[], over: Record<string, unknown> = {}) => ({
  id: "Directory_00000000-0000-4000-8000-00000000f101",
  activityDateTime: "2026-06-03T07:00:15Z",
  activityDisplayName: activity,
  category: "UserManagement",
  result: "success",
  loggedByService: "Core Directory",
  initiatedBy: {
    user: { id: ADMIN_ID, userPrincipalName: "operator@example.test", ipAddress: "203.0.113.41" },
  },
  targetResources: targets,
  ...over,
});

const graphUser = (id: string, upn: string, props: unknown[]) => ({
  id,
  type: "User",
  userPrincipalName: upn,
  modifiedProperties: props,
});

const rows = (records: Record<string, unknown>[]) => parseM365Audit(JSON.stringify(records)).events;

describe("per-user MFA requirement cleared on Update user (#2604 item 5)", () => {
  it("UAL: StrongAuthenticationRequirement non-empty → [] is High + T1556.006", () => {
    const [e] = rows([ual("Update user.", { ModifiedProperties: mfaProps(MFA_ON, "[]") })]);
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toEqual(["T1556.006"]);
    expect(e.description).toContain("StrongAuthenticationRequirement");
    expect(e.description).toContain("dana@example.test");
    expect(e.canonical?.target).toMatchObject({ kind: "account", id: USER_ID, name: "dana@example.test" });
  });

  it("Graph: the same change on the user's modifiedProperties is High", () => {
    const [e] = rows([
      graph("Update user", [
        graphUser(USER_ID, "dana@example.test", [
          {
            displayName: "StrongAuthenticationRequirement",
            oldValue: JSON.stringify(MFA_ON),
            newValue: '"[]"',
          },
        ]),
      ]),
    ]);
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toEqual(["T1556.006"]);
  });

  it("an unchanged, newly set or still-set requirement keeps the plain Info row", () => {
    for (const [o, n] of [
      ["[]", "[]"],
      ["[]", MFA_ON],
      [MFA_ON, MFA_ON],
      ["not json", "[]"],
    ]) {
      const [e] = rows([ual("Update user.", { ModifiedProperties: mfaProps(o, n) })]);
      expect(e.severity).toBe("Info");
    }
  });

  it("a failed clear is an attempt: Medium, no technique", () => {
    const [e] = rows([
      ual("Update user.", { ModifiedProperties: mfaProps(MFA_ON, "[]"), ResultStatus: "Failure" }),
    ]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques ?? []).toEqual([]);
    expect(e.description).toMatch(/attempted to/);
  });

  it("Graph, two targets: each is read against its own properties", () => {
    const cleared = {
      displayName: "StrongAuthenticationRequirement",
      oldValue: JSON.stringify(MFA_ON),
      newValue: '"[]"',
    };
    const kept = { displayName: "StrongAuthenticationRequirement", oldValue: '"[]"', newValue: '"[]"' };
    const one = rows([
      graph("Update user", [
        graphUser(USER_ID, "dana@example.test", [kept]),
        graphUser(USER2_ID, "eli@example.test", [cleared]),
      ]),
    ]);
    expect(one).toHaveLength(1);
    expect(one[0].description).toContain("eli@example.test");
    const both = rows([
      graph("Update user", [
        graphUser(USER_ID, "dana@example.test", [cleared]),
        graphUser(USER2_ID, "eli@example.test", [cleared]),
      ]),
    ]);
    expect(both).toHaveLength(2);
    expect(both.every((e) => e.severity === "High")).toBe(true);
  });

  it("a routine Update user and an MFA clear never fold into one row, in either order", () => {
    const routine = ual("Update user.", {
      Id: "00000000-0000-4000-8000-00000000f002",
      ModifiedProperties: [{ Name: "DisplayName", OldValue: '["Dana"]', NewValue: '["Dana R"]' }],
    });
    const signal = ual("Update user.", { ModifiedProperties: mfaProps(MFA_ON, "[]") });
    for (const order of [
      [routine, signal],
      [signal, routine],
    ]) {
      const out = rows(order);
      expect(out.map((e) => e.severity).sort()).toEqual(["High", "Info"]);
    }
  });
});

describe("user consent opened to every user (#2604 item 6)", () => {
  const authUal = (oldValue: string, newValue: string, over: Record<string, unknown> = {}) =>
    ual("Update authorization policy.", {
      ObjectId: `AuthorizationPolicy_${POLICY_ID}`,
      ExtendedProperties: [{ Name: "extendedAuditEventCategory", Value: "AuthorizationPolicy" }],
      ModifiedProperties: [
        { Name: "PermissionGrantPolicyIdsAssignedToDefaultUserRole", NewValue: newValue, OldValue: oldValue },
        {
          Name: "Included Updated Properties",
          NewValue: "PermissionGrantPolicyIdsAssignedToDefaultUserRole",
          OldValue: "",
        },
      ],
      Target: [
        { ID: `AuthorizationPolicy_${POLICY_ID}`, Type: 2 },
        { ID: POLICY_ID, Type: 2 },
        { ID: "Other", Type: 2 },
        { ID: "Authorization Policy", Type: 1 },
      ],
      ...over,
    });

  it("UAL: gaining a ManagePermissionGrantsForSelf policy is Medium + T1528 and names it", () => {
    const [e] = rows([authUal("[]", `[\r\n  "${CONSENT}"\r\n]`)]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1528"]);
    expect(e.description).toContain(CONSENT);
  });

  it("Graph: the same change is Medium", () => {
    const [e] = rows([
      graph(
        "Update authorization policy",
        [
          {
            id: POLICY_ID,
            type: "Policy",
            displayName: "Authorization Policy",
            modifiedProperties: [
              {
                displayName: "PermissionGrantPolicyIdsAssignedToDefaultUserRole",
                oldValue: '"[]"',
                newValue: JSON.stringify(`["${CONSENT}"]`),
              },
            ],
          },
        ],
        { category: "Policy" },
      ),
    ]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1528"]);
  });

  it("removing the consent policy, keeping it, or a look-alike id keeps the plain row", () => {
    for (const [o, n] of [
      [`["${CONSENT}"]`, "[]"],
      [`["${CONSENT}"]`, `["${CONSENT}"]`],
      ["[]", '["XManagePermissionGrantsForSelf.other"]'],
      ["[]", '["ManagePermissionGrantsForSelf"]'],
    ]) {
      const [e] = rows([authUal(o, n)]);
      expect(e.severity).toBe("Info");
    }
  });
});

// ── the licence detail ──

const licence = (plans: string[], sku = SKU) =>
  `[SkuName=EXAMPLEPACK_E5, AccountId=${TENANT}, SkuId=${sku}, DisabledPlans=[${plans.join(",")}]]`;
const planEntry = (n: number) => ({
  SubscribedPlanId: `77777777-0000-4000-8000-${String(n).padStart(12, "0")}`,
  ServiceInstance: `Service${n}/NA001`,
  CapabilityStatus: 0,
  AssignedTimestamp: "2026-01-09T17:32:47Z",
  InitialState: null,
  Capability: null,
  ServicePlanId: `88888888-0000-4000-8000-${String(n).padStart(12, "0")}`,
});
const updated = (oldPlans: string[] | null, newPlans: string[], sku = SKU) =>
  JSON.stringify([
    {
      Name: "AssignedLicense",
      OldValue: oldPlans ? [licence(oldPlans)] : [],
      NewValue: [licence(newPlans, sku)],
    },
    {
      Name: "AssignedPlan",
      OldValue: Array.from({ length: 60 }, (_, i) => planEntry(i)),
      NewValue: Array.from({ length: 58 }, (_, i) => planEntry(i)),
    },
  ]);
/** additionalDetails as the UAL writes it, chunked: `b` cut at 10,000 characters, seq 1 of c. */
const chunked = (inner: string, seq = "1", count = "4") => {
  const b = JSON.stringify({ targetUpdatedProperties: inner });
  const part = seq === "1" ? b.slice(0, 10000) : b.slice(10000, 20000);
  return JSON.stringify({ id: "99999999-0000-4000-8000-000000000006", seq, b: part, c: count });
};
const whole = (inner: string) =>
  JSON.stringify({
    id: "99999999-0000-4000-8000-000000000006",
    seq: "1",
    b: JSON.stringify({ targetUpdatedProperties: inner }),
    c: "1",
  });
const licenceUal = (details: string, over: Record<string, unknown> = {}) =>
  ual("Update user.", {
    ObjectId: "matt@example.test",
    Target: [
      { ID: `User_${USER2_ID}`, Type: 2 },
      { ID: USER2_ID, Type: 2 },
      { ID: "User", Type: 2 },
      { ID: "matt@example.test", Type: 5 },
    ],
    ExtendedProperties: [
      { Name: "additionalDetails", Value: details },
      { Name: "extendedAuditEventCategory", Value: "User" },
    ],
    ...over,
  });
const AUDIT_OFF = ["M365_ADVANCED_AUDITING", "EXAMPLE_PLAN_A", "EXAMPLE_PLAN_B"];

describe("advanced auditing plan disabled in a licence (#2604 item 7)", () => {
  it("the fixture really is chunked: `b` alone does not parse", () => {
    const b = (JSON.parse(chunked(updated([], AUDIT_OFF))) as { b: string }).b;
    expect(b.length).toBe(10000);
    expect(() => JSON.parse(b)).toThrow();
  });

  it("UAL, chunked (the real shape): DisabledPlans gaining M365_ADVANCED_AUDITING is Medium + T1562.008", () => {
    const [e] = rows([licenceUal(chunked(updated([], AUDIT_OFF)))]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1562.008"]);
    expect(e.description).toContain("M365_ADVANCED_AUDITING");
    expect(e.description).toContain("matt@example.test");
  });

  it("UAL, one complete chunk grades the same", () => {
    const [e] = rows([licenceUal(whole(updated([], AUDIT_OFF)))]);
    expect(e.severity).toBe("Medium");
  });

  it("Graph: an AssignedLicense modified property with the same delta is Medium", () => {
    const [e] = rows([
      graph("Update user", [
        graphUser(USER_ID, "matt@example.test", [
          {
            displayName: "AssignedLicense",
            oldValue: JSON.stringify([licence([])]),
            newValue: JSON.stringify([licence(AUDIT_OFF)]),
          },
        ]),
      ]),
    ]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1562.008"]);
  });

  it("no inferred change without a parsed prior value or a real addition", () => {
    const cases = [
      licenceUal(chunked(updated(AUDIT_OFF, AUDIT_OFF))), // already disabled
      licenceUal(chunked(updated(null, AUDIT_OFF))), // no prior licence
      licenceUal(chunked(updated([], AUDIT_OFF, "55555555-0000-4000-8000-0000000000ff"))), // another SKU
      licenceUal(chunked(updated(["M365_ADVANCED_AUDITING"], []))), // re-enabled
      licenceUal(chunked(updated([], ["EXAMPLE_PLAN_A"]))), // another plan
      licenceUal(chunked(updated([], AUDIT_OFF), "2")), // a later chunk alone
      licenceUal("{not json"),
      licenceUal(JSON.stringify({ b: "x".repeat(70000) })), // oversized
      licenceUal(
        JSON.stringify({
          seq: "1",
          b: '{"targetUpdatedProperties":"[{\\"Name\\":\\"AssignedLicense\\",\\"OldVa',
        }),
      ),
    ];
    for (const r of cases) {
      const [e] = rows([r]);
      expect(e.severity).toBe("Info");
    }
  });

  it("a routine Update user and a licence change never fold into one row, in either order", () => {
    const routine = licenceUal('{"UserType":"Member"}', { Id: "00000000-0000-4000-8000-00000000f003" });
    const signal = licenceUal(chunked(updated([], AUDIT_OFF)));
    for (const order of [
      [routine, signal],
      [signal, routine],
    ]) {
      expect(
        rows(order)
          .map((e) => e.severity)
          .sort(),
      ).toEqual(["Info", "Medium"]);
    }
  });
});
