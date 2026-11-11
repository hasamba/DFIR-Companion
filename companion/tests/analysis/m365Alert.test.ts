import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { alertSeverity, decodeM365Alert } from "../../src/analysis/m365Alert.js";

// A Security & Compliance alert record (RecordType 40) in the Search-UnifiedAuditLog shape: the
// detail sits in AuditData, and again in `Data`, a second JSON string nested inside it (#2551).
const alertAd = (over: Record<string, unknown> = {}, data: Record<string, unknown> | string | null = {}) => {
  const nested =
    data === null
      ? {}
      : {
          Data:
            typeof data === "string"
              ? data
              : JSON.stringify({
                  an: "Creation of forwarding/redirect rule",
                  sev: "Informational",
                  f3u: "victim@example.com",
                  op: "MailRedirect",
                  reid: "rec-0001",
                  ...data,
                }),
        };
  return {
    CreationTime: "2026-03-01T10:00:00",
    Id: "00000000-0000-0000-0000-0000000000a1",
    Operation: "AlertTriggered",
    Workload: "SecurityComplianceCenter",
    RecordType: 40,
    UserId: "SecurityComplianceAlerts",
    ObjectId: "a1b2c3d4-alert",
    AlertId: "a1b2c3d4-alert",
    Name: "Top-level alert name",
    Severity: "Low",
    ...nested,
    ...over,
  };
};
const row = (ad: Record<string, unknown>) => ({
  RecordType: 40,
  CreationDate: ad.CreationTime,
  UserIds: "SecurityComplianceAlerts",
  Operations: ad.Operation,
  AuditData: JSON.stringify(ad),
});
const parse = (...ads: Record<string, unknown>[]) => parseM365Audit(JSON.stringify(ads.map(row)));

describe("M365 Security & Compliance alerts (#2551)", () => {
  it("shows the alert name, vendor severity, user, operation and triggering record, graded Medium", () => {
    const r = parse(alertAd());
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toMatch(/^M365 SecurityComplianceCenter: AlertTriggered\b/);
    expect(e.description).toContain('"Creation of forwarding/redirect rule"');
    expect(e.description).toContain("(Informational)");
    expect(e.description).toContain("for victim@example.com");
    expect(e.description).toContain("op MailRedirect");
    expect(e.description).toContain("(record rec-0001)");
    expect(e.description).not.toContain("by SecurityComplianceAlerts");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1114.003");
  });

  it("a vendor Medium or High alert is graded High", () => {
    expect(parse(alertAd({}, { sev: "High" })).events[0].severity).toBe("High");
    expect(parse(alertAd({}, { sev: "Medium" })).events[0].severity).toBe("High");
  });

  it("two distinct alerts stay two rows", () => {
    const r = parse(
      alertAd(),
      alertAd(
        { Id: "00000000-0000-0000-0000-0000000000a2", AlertId: "e5f6-alert", ObjectId: "e5f6-alert" },
        { f3u: "other@example.com", reid: "rec-0002" },
      ),
    );
    expect(r.events).toHaveLength(2);
    expect(r.events.map((e) => e.description).join("\n")).toContain("other@example.com");
  });

  it("AlertEntityGenerated sits one level below its AlertTriggered", () => {
    const ad = alertAd({ Operation: "AlertEntityGenerated", Id: "00000000-0000-0000-0000-0000000000a3" });
    expect(parse(ad).events[0].severity).toBe("Low");
    expect(parse(alertAd({ Operation: "AlertEntityGenerated" }, { sev: "High" })).events[0].severity).toBe(
      "Medium",
    );
  });

  it.each([
    ["malformed JSON", "{not json"],
    ["a non-object", "[1,2,3]"],
    ["an oversized string", `{"an":"${"x".repeat(70_000)}"}`],
  ])("Data that is %s falls back to the top-level Name/Severity", (_label, data) => {
    const r = parse(alertAd({}, data));
    expect(r.events[0].description).toContain('"Top-level alert name"');
    expect(r.events[0].description).toContain("(Low)");
    expect(r.events[0].severity).toBe("Medium");
  });

  it("missing Data falls back without throwing", () => {
    const r = parse(alertAd({}, null));
    expect(r.events[0].description).toContain('"Top-level alert name"');
    expect(r.events[0].severity).toBe("Medium");
  });

  it("an adversary-controlled alert name is put on one line and capped", () => {
    const long = `evil\r\nline2\u0007${"A".repeat(500)}`;
    const alert = decodeM365Alert(alertAd({}, { an: long }), "AlertTriggered");
    expect(alert?.name).not.toMatch(/[\r\n\u0007]/);
    expect(alert?.name.length).toBeLessThanOrEqual(200);
    const e = parse(alertAd({}, { an: long })).events[0];
    expect(e.description).not.toMatch(/[\r\n]/);
    expect(e.description.length).toBeLessThanOrEqual(600);
  });

  it("only the two alert operations decode", () => {
    expect(decodeM365Alert(alertAd(), "New-InboxRule")).toBeNull();
    const a = decodeM365Alert(alertAd(), "alerttriggered");
    expect(a && alertSeverity(a)).toBe("Medium");
  });
});
