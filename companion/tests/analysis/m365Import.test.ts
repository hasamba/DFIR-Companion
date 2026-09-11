import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

// One Entra sign-in record. Module-scoped so every describe block can build one.
const signinRec = (over: Record<string, unknown>) => ({
  createdDateTime: "2023-05-02T08:10:00Z",
  userPrincipalName: "v@victim.com",
  appDisplayName: "Azure CLI",
  ipAddress: "198.51.100.9",
  ...over,
});

// ── M365 Unified Audit Log records (Search-UnifiedAuditLog shape: AuditData JSON string) ──
function ualRow(auditData: Record<string, unknown>, outer: object = {}): object {
  return {
    RecordType: 1,
    CreationDate: "2023-05-01T10:00:00",
    UserIds: "attacker@victim.com",
    Operations: auditData.Operation as string | undefined,
    AuditData: JSON.stringify(auditData),
    ...outer,
  };
}
function inboxRule(): object {
  return ualRow({
    CreationTime: "2023-05-01T10:00:00",
    Operation: "New-InboxRule",
    Workload: "Exchange",
    UserId: "attacker@victim.com",
    ClientIP: "[203.0.113.7]:443",
    ResultStatus: "True",
    ObjectId: "victim@victim.com\\Inbox Rule",
  });
}

describe("parseM365Audit — Unified Audit Log", () => {
  it("parses the AuditData blob and derives High for an inbox rule (BEC)", () => {
    const r = parseM365Audit(JSON.stringify([inboxRule()]));
    expect(r.format).toBe("m365-ual");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("M365 Exchange: New-InboxRule");
    expect(e.description).toContain("attacker@victim.com");
    expect(e.description).toContain("from 203.0.113.7"); // ClientIP de-bracketed/de-ported
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1564.008");
    expect(e.sources).toEqual(["Microsoft 365"]);
    expect(e.timestamp).toBe("2023-05-01T10:00:00Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.7");
  });

  it("treats an unknown operation as Info and a failed login as Medium", () => {
    const ok = ualRow({
      CreationTime: "2023-05-01T11:00:00",
      Operation: "MailItemsAccessed",
      Workload: "Exchange",
      UserId: "u@victim.com",
    });
    const fail = ualRow({
      CreationTime: "2023-05-01T11:01:00",
      Operation: "UserLoginFailed",
      Workload: "AzureActiveDirectory",
      UserId: "u@victim.com",
      ClientIP: "198.51.100.4",
    });
    const r = parseM365Audit([ok, fail].map((o) => JSON.stringify(o)).join("\n"));
    const byOp = (s: string) => r.events.find((e) => e.description.includes(s));
    expect(byOp("MailItemsAccessed")?.severity).toBe("Low"); // table: Low
    expect(byOp("UserLoginFailed")?.severity).toBe("Medium"); // brute-force signal
    expect(byOp("UserLoginFailed")?.mitreTechniques).toContain("T1110");
  });

  it("reads the raw Management-API AuditData object (no wrapper) via Workload+RecordType", () => {
    const raw = {
      CreationTime: "2023-05-01T12:00:00",
      RecordType: 8,
      Operation: "Add member to role.",
      Workload: "AzureActiveDirectory",
      UserId: "admin@victim.com",
      ClientIP: "203.0.113.9",
    };
    const r = parseM365Audit(JSON.stringify([raw]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High"); // role grant
    expect(r.events[0].mitreTechniques).toContain("T1098.003");
  });

  it("reads CSV exports with an AuditData column", () => {
    const ad = JSON.stringify({
      CreationTime: "2023-05-01T13:00:00",
      Operation: "Add service principal credentials.",
      Workload: "AzureActiveDirectory",
      UserId: "admin@victim.com",
      ClientIP: "203.0.113.20",
    });
    const csv = `RecordType,CreationDate,UserIds,Operations,AuditData\n8,2023-05-01T13:00:00,admin@victim.com,"Add service principal credentials.","${ad.replace(/"/g, '""')}"`;
    const r = parseM365Audit(csv);
    expect(r.format).toBe("m365-ual");
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1098.001");
  });
});

describe("parseM365Audit — Entra sign-in & audit", () => {
  it("maps an Entra sign-in: risk verdict drives severity, IP becomes an IOC", () => {
    const signin = {
      createdDateTime: "2023-05-02T08:00:00Z",
      userPrincipalName: "victim@victim.com",
      appDisplayName: "Office 365 Exchange Online",
      ipAddress: "203.0.113.50",
      status: { errorCode: 0, failureReason: "Other." },
      riskLevelDuringSignIn: "high",
      location: { city: "Lagos", countryOrRegion: "NG" },
    };
    const r = parseM365Audit(JSON.stringify([signin]));
    expect(r.format).toBe("entra-signin");
    const e = r.events[0];
    expect(e.description).toContain("Entra sign-in: victim@victim.com from 203.0.113.50");
    expect(e.description).toContain("(Lagos, NG)");
    expect(e.description).toContain("[risk: high]");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1078.004");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.50");
  });

  it("maps a failed Entra sign-in (errorCode != 0) as Medium", () => {
    const signin = {
      createdDateTime: "2023-05-02T08:05:00Z",
      userPrincipalName: "v@victim.com",
      appDisplayName: "X",
      ipAddress: "198.51.100.9",
      status: { errorCode: 50126, failureReason: "Invalid username or password." },
    };
    const r = parseM365Audit(JSON.stringify([signin]));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[FAILED");
  });

  it("flags a SUCCESSFUL ROPC legacy-auth sign-in (BAV2ROPC UserAgent) as Medium", () => {
    const r = parseM365Audit(
      JSON.stringify([signinRec({ status: { errorCode: 0 }, userAgent: "python-requests/2.28 BAV2ROPC" })]),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.description).toContain("legacy-auth ROPC");
  });

  // ROPC is a legacy grant that shows no interactive MFA prompt. It is NOT an observed MFA bypass,
  // and it is neither T1556.007 (Hybrid Identity) nor T1621 (MFA Request Generation — push
  // bombing, which ROPC does not do). Both were asserted here, so the mis-mapping was pinned green.
  it("does not claim an MFA-bypass technique for a ROPC sign-in", () => {
    const r = parseM365Audit(
      JSON.stringify([signinRec({ status: { errorCode: 0 }, userAgent: "python-requests/2.28 BAV2ROPC" })]),
    );
    const e = r.events[0];
    expect(e.mitreTechniques).not.toContain("T1556.007");
    expect(e.mitreTechniques).not.toContain("T1621");
    expect(e.description).not.toContain("MFA bypass");
  });

  it("does not describe a BLOCKED ROPC attempt as a successful bypass", () => {
    const r = parseM365Audit(
      JSON.stringify([
        signinRec({
          status: { errorCode: 53003, failureReason: "Blocked by Conditional Access." },
          userAgent: "python-requests/2.28 BAV2ROPC",
        }),
      ]),
    );
    const e = r.events[0];
    expect(e.description).toContain("[FAILED 53003");
    expect(e.severity).not.toBe("Medium"); // a blocked attempt is not graded like a landed one
  });

  // Every nonzero errorCode used to become Medium + T1110. Most failed sign-ins in a real tenant
  // are interrupts, not password attacks (#931 item 3).
  it.each([
    [50074, "MFA challenge not passed"],
    [50076, "MFA required by policy"],
    [53003, "blocked by Conditional Access"],
    [50055, "expired password"],
    [50140, "keep-me-signed-in interrupt"],
    [50058, "no SSO session — the most common code in a tenant export"],
    [16000, "interaction required"],
  ])("does not call errorCode %i a brute-force attempt (%s)", (code) => {
    const r = parseM365Audit(JSON.stringify([signinRec({ status: { errorCode: code } })]));
    const e = r.events[0];
    expect(e.mitreTechniques).not.toContain("T1110");
    expect(e.severity).toBe("Low");
    expect(e.description).toContain(`[FAILED ${code}`);
  });

  it.each([50126, 50034, 50056, 50064])("keeps errorCode %i as a credential failure (T1110)", (code) => {
    const r = parseM365Audit(JSON.stringify([signinRec({ status: { errorCode: code } })]));
    const e = r.events[0];
    expect(e.mitreTechniques).toContain("T1110");
    expect(e.severity).toBe("Medium");
  });

  // `Number(x) || 0` folded a non-numeric status into 0 — the value a genuine success carries — so
  // an unreadable outcome took the success path and shared the success aggregation bucket.
  it("does not read an unparseable errorCode as a success", () => {
    const r = parseM365Audit(
      JSON.stringify([
        signinRec({ status: { errorCode: "unavailable" } }),
        signinRec({ status: { errorCode: 0 } }),
      ]),
    );
    expect(r.events).toHaveLength(2); // distinct aggregation keys, not one merged row
    const unknown = r.events.find((e) => e.description.includes("outcome unknown"));
    expect(unknown).toBeDefined();
    expect(unknown?.severity).toBe("Low");
    expect(unknown?.mitreTechniques).not.toContain("T1110");
  });

  it("keeps a ROPC sign-in distinct from an ordinary one by the same user", () => {
    const r = parseM365Audit(
      JSON.stringify([
        signinRec({ status: { errorCode: 0 }, userAgent: "python-requests/2.28 BAV2ROPC" }),
        signinRec({ status: { errorCode: 0 }, userAgent: "Mozilla/5.0" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });

  it("maps an Entra directory audit (initiatedBy + targetResources)", () => {
    const audit = {
      activityDateTime: "2023-05-02T09:00:00Z",
      activityDisplayName: "Add member to role",
      result: "success",
      initiatedBy: { user: { userPrincipalName: "admin@victim.com", ipAddress: "203.0.113.60" } },
      targetResources: [{ userPrincipalName: "attacker@victim.com", displayName: "attacker" }],
    };
    const r = parseM365Audit(JSON.stringify([audit]));
    expect(r.format).toBe("entra-audit");
    const e = r.events[0];
    expect(e.description).toContain("Entra audit: Add member to role by admin@victim.com");
    expect(e.description).toContain("→ attacker@victim.com");
    expect(e.severity).toBe("High");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.60");
  });
});

describe("parseM365Audit — options & edges", () => {
  it("aggregates repeated identical operations and applies a severity floor", () => {
    const r = parseM365Audit([inboxRule(), inboxRule()].map((o) => JSON.stringify(o)).join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);

    const mixed = [
      inboxRule(),
      ualRow({
        CreationTime: "2023-05-01T10:00:00",
        Operation: "MailItemsAccessed",
        Workload: "Exchange",
        UserId: "u@victim.com",
      }),
    ];
    const floored = parseM365Audit(mixed.map((o) => JSON.stringify(o)).join("\n"), { minSeverity: "Medium" });
    expect(floored.events).toHaveLength(1); // the Low MailItemsAccessed dropped
    expect(floored.events[0].severity).toBe("High");
  });

  it("reports empty for a non-M365 file", () => {
    const r = parseM365Audit("not json");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
  // ADVERSARIAL: a record can reach mapSignIn via `riskState` alone, with no status field at all.
  // Mapping an ABSENT errorCode to success asserts an outcome the record does not carry — the same
  // hole as the old `Number(x) || 0`, kept open for the absent case while the malformed case closed.
  it("does not read an ABSENT errorCode as a success", () => {
    const r = parseM365Audit(JSON.stringify([signinRec({ riskState: "atRisk" })]));
    expect(r.events[0].description).toContain("outcome unknown");
  });

  it("does not read an empty-string errorCode as a success", () => {
    const r = parseM365Audit(JSON.stringify([signinRec({ status: { errorCode: "" } })]));
    const e = r.events[0];
    expect(e.description).toContain("outcome unknown");
    expect(e.mitreTechniques).not.toContain("T1110");
  });

  it("does not elevate a ROPC record whose outcome is unknown as though the grant landed", () => {
    const r = parseM365Audit(
      JSON.stringify([signinRec({ status: {}, userAgent: "python-requests/2.28 BAV2ROPC" })]),
    );
    const e = r.events[0];
    expect(e.description).toContain("outcome unknown");
    expect(e.severity).not.toBe("Medium");
  });

  // ADVERSARIAL: Microsoft documents 50053 as TWO different conditions — a credential lockout, or
  // a sign-in blocked because the IP had malicious activity. Asserting T1110 for both turns a
  // policy/risk block into brute-force evidence, which is the overstatement this file is fixing.
  it("does not claim brute force for a 50053 that does not state a lockout", () => {
    const r = parseM365Audit(
      JSON.stringify([
        signinRec({
          status: {
            errorCode: 50053,
            failureReason: "Sign-in was blocked because it came from an IP address with malicious activity.",
          },
        }),
      ]),
    );
    expect(r.events[0].mitreTechniques).not.toContain("T1110");
  });

  it("does not claim brute force for a bare 50053 with no failure reason", () => {
    const r = parseM365Audit(JSON.stringify([signinRec({ status: { errorCode: 50053 } })]));
    expect(r.events[0].mitreTechniques).not.toContain("T1110");
  });

  it("does claim brute force for a 50053 whose reason states the account is locked", () => {
    const r = parseM365Audit(
      JSON.stringify([
        signinRec({
          status: {
            errorCode: 50053,
            failureReason:
              "The account is locked, you've tried to sign in too many times with an incorrect user ID or password.",
          },
        }),
      ]),
    );
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });
});

describe("parseM365Audit — Entra application changes (#931 item 1)", () => {
  const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
  const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
  const USER = "4d9f5e3c-3333-4ccc-addd-000000000003";
  const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
  const audit = (activity: string, targets: unknown[], over: Record<string, unknown> = {}) => ({
    id: `rec-${activity.length}-${JSON.stringify(targets).length}`,
    activityDateTime: "2024-05-01T10:00:00Z",
    activityDisplayName: activity,
    result: "success",
    initiatedBy: { user: { id: USER, userPrincipalName: "admin@victim.com", ipAddress: "203.0.113.60" } },
    targetResources: targets,
    ...over,
  });
  const prop = (displayName: string, newValue: unknown, oldValue: unknown = null) => ({
    displayName,
    oldValue,
    newValue,
  });

  it("one record with three consented scopes is three rows, each with its own key and a schema-valid envelope", () => {
    const consent = audit("Consent to application", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "Sync",
        modifiedProperties: [
          prop("ConsentContext.IsAdminConsent", "True"),
          prop("ConsentContext.IsAppOnly", "False"),
          prop("ConsentContext.OnBehalfOfAll", "True"),
          prop(
            "ConsentAction.Permissions",
            `[] => [[Id: g1, ClientId: ${SP}, PrincipalId: , ResourceId: ${GRAPH_SP}, ConsentType: AllPrincipals, Scope: openid Mail.ReadWrite Directory.ReadWrite.All, CreatedDateTime: 2024-05-01, ExpiryTime: ]]`,
          ),
        ],
      },
    ]);
    const r = parseM365Audit(JSON.stringify([consent]), { aggregate: false });
    expect(r.events).toHaveLength(3);
    expect(new Set(r.events.map((e) => e.aggKey)).size).toBe(3);
    const mail = r.events.find((e) => e.description.includes("Mail.ReadWrite"))!;
    expect(mail.description).toContain(
      "Entra audit: Consent to application by admin@victim.com from 203.0.113.60",
    );
    expect(mail.description).toContain(
      "grants delegated permission Mail.ReadWrite on API 3c8e4d2b… for Sync (admin consent, for all users)",
    );
    expect(mail.description).toContain("API not identified in this record");
    expect(mail.description).toContain("for Sync (admin consent, for all users)");
    expect(mail.description).toContain("assigned, not yet observed in use");
    expect(mail.severity).toBe("Medium");
    expect(mail.canonical?.event).toMatchObject({
      category: "cloud",
      type: "directory-change",
      action: "Consent to application",
      outcome: "success",
    });
    expect(mail.canonical?.actor).toMatchObject({ kind: "account", id: USER, name: "admin@victim.com" });
    expect(mail.canonical?.object).toMatchObject({ kind: "cloud_principal", id: SP, name: "Sync" });
    expect(mail.canonical?.cloud?.provider).toBe("entra");
    expect(mail.canonical?.evidence.rawRecords[0]).toMatchObject({
      source: "entra-audit",
      locator: "record:0",
    });
  });
  it("another record of the export that names Graph's object id lets the consent identify the API and grade by class", () => {
    const grant = audit("Add app role assignment to service principal", [
      {
        type: "ServicePrincipal",
        id: GRAPH_SP,
        displayName: "Microsoft Graph",
        modifiedProperties: [
          prop("AppRole.Value", "User.Read.All"),
          prop("ServicePrincipal.ObjectID", SP),
          prop("TargetId.ServicePrincipalNames", [GRAPH_APP, "https://graph.microsoft.com"]),
        ],
      },
    ]);
    const consent = audit("Consent to application", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "Sync",
        modifiedProperties: [
          prop("ConsentContext.IsAdminConsent", "True"),
          prop("ConsentContext.IsAppOnly", "False"),
          prop(
            "ConsentAction.Permissions",
            `[] => [[Id: g1, ClientId: ${SP}, PrincipalId: , ResourceId: ${GRAPH_SP}, ConsentType: AllPrincipals, Scope: Mail.ReadWrite, CreatedDateTime: 2024-05-01, ExpiryTime: ]]`,
          ),
        ],
      },
    ]);
    const r = parseM365Audit(JSON.stringify([consent, grant]), { aggregate: false });
    const mail = r.events.find((e) => e.description.includes("Mail.ReadWrite"))!;
    expect(mail.description).toContain("on Microsoft Graph");
    expect(mail.description).toContain("can read and change every mailbox");
    expect(mail.severity).toBe("High");
  });
  it("a credential added to a service principal is a High row that names the key, never a secret; the plain row survives for an undecoded change", () => {
    const cred = audit("Add service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "Sync",
        modifiedProperties: [
          prop(
            "KeyDescription",
            JSON.stringify(["[KeyIdentifier=k-1,KeyType=Password,KeyUsage=Verify,DisplayName=deploy]"]),
            JSON.stringify([]),
          ),
        ],
      },
    ]);
    const plain = audit("Update user", [{ type: "User", id: USER, userPrincipalName: "bob@victim.com" }]);
    const r = parseM365Audit(JSON.stringify([cred, plain]), { aggregate: false });
    const c = r.events.find((e) => e.description.includes("credential"))!;
    expect(c.severity).toBe("High");
    expect(c.description).toContain('adds Password credential k-1 "deploy" (1 now) for Sync');
    const p = r.events.find((e) => e.description.includes("Update user"))!;
    expect(p.description).toBe(
      "Entra audit: Update user by admin@victim.com from 203.0.113.60 → bob@victim.com",
    );
    expect(p.canonical?.target).toMatchObject({ kind: "account", id: USER, name: "bob@victim.com" });
  });
  it("a failed grant reads as an attempt, with the failure next to the posture", () => {
    const r = parseM365Audit(
      JSON.stringify([
        audit(
          "Add app role assignment to service principal",
          [
            {
              type: "ServicePrincipal",
              id: GRAPH_SP,
              modifiedProperties: [
                prop("AppRole.Value", "RoleManagement.ReadWrite.Directory"),
                prop("ServicePrincipal.ObjectID", SP),
                prop("TargetId.ServicePrincipalNames", [GRAPH_APP]),
              ],
            },
          ],
          { result: "failure" },
        ),
      ]),
    );
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.description).toMatch(
      /attempted to grant application permission RoleManagement\.ReadWrite\.Directory — failed on Microsoft Graph for/,
    );
    expect(e.description).toContain("requested, not granted");
  });
  it("the UAL shape of the same change goes through the same decoder", () => {
    const ual = {
      Id: "ual-1",
      CreationTime: "2024-05-01T10:00:00Z",
      Workload: "AzureActiveDirectory",
      RecordType: 8,
      Operation: "Add member to role.",
      ResultStatus: "Success",
      OrganizationId: "tenant-1",
      ActorIpAddress: "203.0.113.61",
      Actor: [
        { ID: "admin@victim.com", Type: 5 },
        { ID: "User", Type: 2 },
        { ID: USER, Type: 3 },
      ],
      Target: [
        { ID: "Sync", Type: 1 },
        { ID: "ServicePrincipal", Type: 2 },
        { ID: SP, Type: 3 },
      ],
      ModifiedProperties: [
        { Name: "Role.DisplayName", NewValue: "Global Administrator", OldValue: "" },
        { Name: "Role.TemplateId", NewValue: "62e90394-69f5-4237-9190-012177145e10", OldValue: "" },
      ],
    };
    const r = parseM365Audit(JSON.stringify([ual]));
    expect(r.format).toBe("m365-ual");
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("assigns directory role Global Administrator to service principal Sync");
    expect(e.description).toContain("can take over the tenant");
    expect(e.canonical?.cloud?.tenant).toBe("tenant-1");
    expect(e.canonical?.evidence.rawRecords[0]).toMatchObject({ source: "m365-ual", recordId: "ual-1" });
  });
  it("the description of a maximal row keeps the head, the posture, the object and the qualifiers inside 600", () => {
    const r = parseM365Audit(
      JSON.stringify([
        audit(
          "Consent to application",
          [
            {
              type: "ServicePrincipal",
              id: SP,
              displayName: "S".repeat(400),
              modifiedProperties: [
                prop("ConsentContext.IsAdminConsent", "False"),
                prop(
                  "ConsentAction.Permissions",
                  `[] => [[Id: g1, ClientId: ${SP}, PrincipalId: ${USER}, ResourceId: ${GRAPH_SP}, ConsentType: Principal, Scope: ${"Scope.X".repeat(60)}, CreatedDateTime: 2024-05-01, ExpiryTime: ]]`,
                ),
              ],
            },
          ],
          {
            initiatedBy: {
              user: {
                id: USER,
                userPrincipalName: `${"p".repeat(300)}@victim.com`,
                ipAddress: "203.0.113.60",
              },
            },
          },
        ),
      ]),
    );
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toMatch(/^Entra audit: Consent to application by p+/);
    expect(d).toContain("grants delegated permission");
    expect(d).toContain("for SSSS");
    expect(d).toContain("delegated — bounded by the consenting user's own access");
    expect(d).toContain("assigned, not yet observed in use");
  });
});

describe("parseM365Audit — service-principal sign-ins (#931 item 1)", () => {
  const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
  const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
  const spSignIn = (over: Record<string, unknown> = {}) => ({
    id: "sp-1",
    createdDateTime: "2024-05-01T11:00:00Z",
    appId: "app-1",
    servicePrincipalId: SP,
    servicePrincipalName: "Sync",
    resourceDisplayName: "Microsoft Graph",
    resourceServicePrincipalId: GRAPH_SP,
    resourceId: "00000003-0000-0000-c000-000000000000",
    ipAddress: "198.51.100.7",
    clientCredentialType: "clientSecret",
    servicePrincipalCredentialKeyId: "k-1",
    resourceTenantId: "tenant-1",
    status: { errorCode: 0 },
    ...over,
  });
  it("is a row now, not a dropped record: token issued, the credential type from clientCredentialType, Low for a secret", () => {
    const r = parseM365Audit(JSON.stringify([spSignIn()]));
    expect(r.format).toBe("entra-signin");
    const e = r.events[0];
    expect(e.description).toBe(
      "Entra sign-in: application Sync (app-1) token issued → Microsoft Graph from 198.51.100.7 credential: clientSecret k-1",
    );
    expect(e.severity).toBe("Low");
    expect(e.canonical?.event).toMatchObject({
      category: "authentication",
      type: "sign-in",
      action: "service-principal",
      outcome: "success",
    });
    expect(e.canonical?.actor).toMatchObject({ kind: "cloud_principal", id: SP, name: "Sync" });
    expect(e.canonical?.cloud).toMatchObject({
      provider: "entra",
      tenant: "tenant-1",
      principalId: SP,
      resource: GRAPH_SP,
    });
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("198.51.100.7");
    expect(
      parseM365Audit(JSON.stringify([spSignIn({ clientCredentialType: "certificate" })])).events[0].severity,
    ).toBe("Info");
  });
  it("a workload credential rejection is Medium and says so; any other failure is Low with the code", () => {
    const rejected = parseM365Audit(JSON.stringify([spSignIn({ status: { errorCode: 7000215 } })])).events[0];
    expect(rejected.severity).toBe("Medium");
    expect(rejected.description).toContain("credential rejected (invalid client secret, AADSTS7000215)");
    const blocked = parseM365Audit(JSON.stringify([spSignIn({ status: { errorCode: 53003 } })])).events[0];
    expect(blocked.severity).toBe("Low");
    expect(blocked.description).toContain("failed (AADSTS53003)");
    expect(blocked.mitreTechniques ?? []).toEqual([]);
  });
  it("keys on tenant, client, resource, credential, type, outcome and code — two credentials are two rows", () => {
    const r = parseM365Audit(
      JSON.stringify([spSignIn(), spSignIn({ servicePrincipalCredentialKeyId: "k-2" }), spSignIn()]),
    );
    expect(r.events).toHaveLength(2);
  });
});
