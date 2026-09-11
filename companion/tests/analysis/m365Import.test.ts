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
