import { describe, it, expect } from "vitest";
import {
  buildComplianceView,
  computeDeadline,
  parseDuration,
  availableFrameworks,
} from "../../src/analysis/complianceView.js";
import type { ComplianceResult } from "../../src/analysis/complianceMap.js";

const GDPR_33 = {
  framework: "GDPR",
  control: "Art. 33",
  title: "Notification of a personal data breach to the supervisory authority",
  obligation: "Notify the supervisory authority.",
  notification: {
    within: "PT72H",
    unit: "calendar" as const,
    from: "becoming aware of the personal data breach",
  },
};

const SEC_8K = {
  framework: "SEC",
  control: "Item 1.05 of Form 8-K",
  title: "Material Cybersecurity Incidents",
  obligation: "Report a material incident on a current report.",
  notification: {
    within: "P4D",
    unit: "business" as const,
    from: "determination that the incident is material",
  },
};

// A control cadence, not a clock — must never produce a countdown.
const NIST_CP9 = {
  framework: "NIST 800-53",
  control: "CP-9",
  title: "System Backup",
  obligation: "Backups must exist and be recoverable.",
};

function results(): ComplianceResult[] {
  return [{ technique: "T1486", findingId: "f1", frameworks: [GDPR_33, SEC_8K, NIST_CP9] }];
}

describe("parseDuration", () => {
  it("parses the day and hour forms the dataset uses", () => {
    expect(parseDuration("P4D")).toEqual({ days: 4 });
    expect(parseDuration("P60D")).toEqual({ days: 60 });
    expect(parseDuration("PT72H")).toEqual({ hours: 72 });
  });

  it("returns null rather than guessing at anything else", () => {
    // "P72H" is the invalid spelling of PT72H — hours belong after the T. Accepting it would let a
    // malformed dataset silently produce a deadline.
    expect(parseDuration("P72H")).toBeNull();
    expect(parseDuration("P1Y")).toBeNull();
    expect(parseDuration("")).toBeNull();
    expect(parseDuration("72 hours")).toBeNull();
  });
});

describe("computeDeadline", () => {
  it("adds calendar hours for a calendar clock", () => {
    const d = computeDeadline(GDPR_33.notification, "2026-03-02T00:00:00.000Z", new Date("2026-03-02T00:00:00.000Z"));
    expect(d?.dueAt).toBe("2026-03-05T00:00:00.000Z"); // +72h, weekend or not
    expect(d?.status).toBe("due-soon");
  });

  it("skips weekends for a business-day clock", () => {
    // Discovery on Thursday 2026-03-05. Four business days lands on Wednesday 2026-03-11,
    // because the 7th and 8th are a Saturday and Sunday. A naive +4 days would say the 9th.
    expect(new Date("2026-03-05T00:00:00.000Z").getUTCDay()).toBe(4); // Thursday
    const d = computeDeadline(SEC_8K.notification, "2026-03-05T00:00:00.000Z", new Date("2026-03-05T00:00:00.000Z"));
    expect(d?.dueAt).toBe("2026-03-11T00:00:00.000Z");
  });

  it("counts remaining business days in business days", () => {
    // Due Wednesday, asking on the preceding Friday: Mon/Tue/Wed remain, not the 5 calendar days.
    const d = computeDeadline(SEC_8K.notification, "2026-03-05T00:00:00.000Z", new Date("2026-03-06T00:00:00.000Z"));
    expect(d?.remainingDays).toBe(3);
  });

  it("reports overdue once the due date has passed", () => {
    const d = computeDeadline(GDPR_33.notification, "2026-03-02T00:00:00.000Z", new Date("2026-03-09T00:00:00.000Z"));
    expect(d?.status).toBe("overdue");
    expect(d!.remainingDays).toBeLessThan(0);
  });

  it("reports open when the deadline is far out", () => {
    const hipaa = { within: "P60D", unit: "calendar" as const, from: "discovery of the breach" };
    const d = computeDeadline(hipaa, "2026-03-02T00:00:00.000Z", new Date("2026-03-03T00:00:00.000Z"));
    expect(d?.status).toBe("open");
    expect(d?.remainingDays).toBe(59);
  });

  it("returns undefined for an unparseable duration or start date", () => {
    expect(
      computeDeadline({ ...GDPR_33.notification, within: "soon" }, "2026-03-02T00:00:00.000Z", new Date()),
    ).toBeUndefined();
    expect(computeDeadline(GDPR_33.notification, "not a date", new Date())).toBeUndefined();
  });
});

describe("buildComplianceView", () => {
  const now = new Date("2026-03-02T00:00:00.000Z");

  it("computes no deadlines at all until the analyst sets a discovery date", () => {
    // The clocks start on a legal determination, so there is nothing to count from. Manufacturing
    // one from case data would invent a regulatory deadline.
    const view = buildComplianceView(results(), { now });
    const rows = view[0].frameworks;
    expect(rows).toHaveLength(3);
    for (const row of rows) expect(row.deadline).toBeUndefined();
  });

  it("attaches deadlines only to rows carrying a notification clock", () => {
    const view = buildComplianceView(results(), {
      control: { discoveredAt: "2026-03-02T00:00:00.000Z" },
      now,
    });
    const byControl = Object.fromEntries(view[0].frameworks.map((r) => [r.control, r]));
    expect(byControl["Art. 33"].deadline).toBeDefined();
    expect(byControl["Item 1.05 of Form 8-K"].deadline).toBeDefined();
    // The control cadence gets nothing — this is the regression the old `deadline` field invited.
    expect(byControl["CP-9"].deadline).toBeUndefined();
  });

  it("filters to the analyst's chosen frameworks", () => {
    const view = buildComplianceView(results(), { control: { frameworks: ["GDPR"] }, now });
    expect(view[0].frameworks).toHaveLength(1);
    expect(view[0].frameworks[0].framework).toBe("GDPR");
  });

  it("treats an absent framework list as everything, and an empty list as nothing", () => {
    expect(buildComplianceView(results(), { now })[0].frameworks).toHaveLength(3);
    expect(buildComplianceView(results(), { control: { frameworks: [] }, now })).toHaveLength(0);
  });

  it("drops a technique whose every row was filtered out rather than showing an empty card", () => {
    const view = buildComplianceView(results(), { control: { frameworks: ["HIPAA"] }, now });
    expect(view).toHaveLength(0);
  });

  it("lists the frameworks actually present so the filter UI matches the data", () => {
    expect(availableFrameworks(results())).toEqual(["GDPR", "SEC", "NIST 800-53"]);
  });
});
