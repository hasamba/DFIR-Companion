import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

// ── M365 Unified Audit Log records (Search-UnifiedAuditLog shape: AuditData JSON string) ──
function ualRow(auditData: object, outer: object = {}): object {
  return { RecordType: 1, CreationDate: "2023-05-01T10:00:00", UserIds: "attacker@victim.com", Operations: (auditData as any).Operation, AuditData: JSON.stringify(auditData), ...outer };
}
function inboxRule(): object {
  return ualRow({
    CreationTime: "2023-05-01T10:00:00", Operation: "New-InboxRule", Workload: "Exchange",
    UserId: "attacker@victim.com", ClientIP: "[203.0.113.7]:443", ResultStatus: "True",
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
    expect(e.description).toContain("from 203.0.113.7");   // ClientIP de-bracketed/de-ported
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1564.008");
    expect(e.sources).toEqual(["Microsoft 365"]);
    expect(e.timestamp).toBe("2023-05-01T10:00:00Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.7");
  });

  it("treats an unknown operation as Info and a failed login as Medium", () => {
    const ok = ualRow({ CreationTime: "2023-05-01T11:00:00", Operation: "MailItemsAccessed", Workload: "Exchange", UserId: "u@victim.com" });
    const fail = ualRow({ CreationTime: "2023-05-01T11:01:00", Operation: "UserLoginFailed", Workload: "AzureActiveDirectory", UserId: "u@victim.com", ClientIP: "198.51.100.4" });
    const r = parseM365Audit([ok, fail].map((o) => JSON.stringify(o)).join("\n"));
    const byOp = (s: string) => r.events.find((e) => e.description.includes(s));
    expect(byOp("MailItemsAccessed")?.severity).toBe("Low");      // table: Low
    expect(byOp("UserLoginFailed")?.severity).toBe("Medium");     // brute-force signal
    expect(byOp("UserLoginFailed")?.mitreTechniques).toContain("T1110");
  });

  it("reads the raw Management-API AuditData object (no wrapper) via Workload+RecordType", () => {
    const raw = { CreationTime: "2023-05-01T12:00:00", RecordType: 8, Operation: "Add member to role.", Workload: "AzureActiveDirectory", UserId: "admin@victim.com", ClientIP: "203.0.113.9" };
    const r = parseM365Audit(JSON.stringify([raw]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");                    // role grant
    expect(r.events[0].mitreTechniques).toContain("T1098.003");
  });

  it("reads CSV exports with an AuditData column", () => {
    const ad = JSON.stringify({ CreationTime: "2023-05-01T13:00:00", Operation: "Add service principal credentials.", Workload: "AzureActiveDirectory", UserId: "admin@victim.com", ClientIP: "203.0.113.20" });
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
      createdDateTime: "2023-05-02T08:00:00Z", userPrincipalName: "victim@victim.com",
      appDisplayName: "Office 365 Exchange Online", ipAddress: "203.0.113.50",
      status: { errorCode: 0, failureReason: "Other." },
      riskLevelDuringSignIn: "high", location: { city: "Lagos", countryOrRegion: "NG" },
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
    const signin = { createdDateTime: "2023-05-02T08:05:00Z", userPrincipalName: "v@victim.com", appDisplayName: "X", ipAddress: "198.51.100.9", status: { errorCode: 50126, failureReason: "Invalid username or password." } };
    const r = parseM365Audit(JSON.stringify([signin]));
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].description).toContain("[FAILED");
  });

  it("maps an Entra directory audit (initiatedBy + targetResources)", () => {
    const audit = {
      activityDateTime: "2023-05-02T09:00:00Z", activityDisplayName: "Add member to role",
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

    const mixed = [inboxRule(), ualRow({ CreationTime: "2023-05-01T10:00:00", Operation: "MailItemsAccessed", Workload: "Exchange", UserId: "u@victim.com" })];
    const floored = parseM365Audit(mixed.map((o) => JSON.stringify(o)).join("\n"), { minSeverity: "Medium" });
    expect(floored.events).toHaveLength(1);                       // the Low MailItemsAccessed dropped
    expect(floored.events[0].severity).toBe("High");
  });

  it("reports empty for a non-M365 file", () => {
    const r = parseM365Audit("not json");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});
