import { describe, it, expect } from "vitest";
import { parseOktaSystemLog } from "../../src/analysis/oktaImport.js";

function evt(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    uuid: "e1",
    published: "2026-05-02T10:00:00.000Z",
    eventType: "user.session.start",
    displayMessage: "User login to Okta",
    severity: "INFO",
    actor: { id: "00u1", type: "User", alternateId: "jdoe@example.invalid", displayName: "J Doe" },
    client: {
      ipAddress: "203.0.113.10",
      geographicalContext: { city: "Tel Aviv", country: "Israel" },
    },
    outcome: { result: "SUCCESS" },
    ...over,
  };
}

describe("parseOktaSystemLog", () => {
  it("reports an empty result for empty input", () => {
    const r = parseOktaSystemLog("");
    expect(r.total).toBe(0);
    expect(r.format).toBe("empty");
  });

  it("reads a JSON array and a single NDJSON record identically", () => {
    const one = evt();
    const array = parseOktaSystemLog(JSON.stringify([one]));
    const ndjson = parseOktaSystemLog(JSON.stringify(one));
    expect(array.total).toBe(1);
    expect(ndjson.total).toBe(1);
    expect(array.events[0].description).toBe(ndjson.events[0].description);
  });

  it("maps a successful login to Info and records the source IP as an IOC", () => {
    const r = parseOktaSystemLog(JSON.stringify([evt()]));
    expect(r.events[0].severity).toBe("Info");
    expect(r.events[0].description).toContain("jdoe@example.invalid");
    expect(r.events[0].description).toContain("203.0.113.10");
    expect(r.iocs.map((i) => i.value)).toContain("203.0.113.10");
    expect(r.events[0].sources).toContain("Okta");
  });

  it("escalates a failed login and tags brute force", () => {
    const r = parseOktaSystemLog(
      JSON.stringify([evt({ outcome: { result: "FAILURE", reason: "INVALID_CREDENTIALS" }, uuid: "e2" })]),
    );
    expect(r.events[0].severity).toBe("Medium");
    expect(r.events[0].mitreTechniques).toContain("T1110");
    expect(r.events[0].description).toContain("FAILED");
  });

  it("treats MFA factor removal as High with the MFA-modification technique", () => {
    const r = parseOktaSystemLog(
      JSON.stringify([evt({ eventType: "user.mfa.factor.deactivate", uuid: "e3" })]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1556.006");
  });

  it("treats an admin privilege grant as High", () => {
    const r = parseOktaSystemLog(
      JSON.stringify([evt({ eventType: "user.account.privilege.grant", uuid: "e4" })]),
    );
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1098.003");
  });

  it("treats API token creation and impersonation as High", () => {
    const token = parseOktaSystemLog(
      JSON.stringify([evt({ eventType: "system.api_token.create", uuid: "e5" })]),
    );
    const imp = parseOktaSystemLog(
      JSON.stringify([evt({ eventType: "user.session.impersonation.initiate", uuid: "e6" })]),
    );
    expect(token.events[0].severity).toBe("High");
    expect(imp.events[0].severity).toBe("High");
  });

  it("names the target application when one is present", () => {
    const r = parseOktaSystemLog(
      JSON.stringify([
        evt({
          eventType: "application.user_membership.add",
          uuid: "e7",
          target: [{ id: "0oa1", type: "AppInstance", displayName: "Salesforce" }],
        }),
      ]),
    );
    expect(r.events[0].description).toContain("Salesforce");
  });

  it("carries the geographic context, which is what makes impossible travel visible", () => {
    const r = parseOktaSystemLog(JSON.stringify([evt()]));
    expect(r.events[0].description).toContain("Tel Aviv");
  });

  it("keeps an unknown event type at Info rather than dropping it", () => {
    const r = parseOktaSystemLog(JSON.stringify([evt({ eventType: "some.future.event", uuid: "e8" })]));
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
  });

  it("ignores a record that is not an Okta event", () => {
    const r = parseOktaSystemLog(JSON.stringify([{ hello: "world" }]));
    expect(r.events).toHaveLength(0);
  });

  it("honours a minimum-severity floor", () => {
    const r = parseOktaSystemLog(
      JSON.stringify([evt(), evt({ eventType: "user.mfa.factor.deactivate", uuid: "e9" })]),
      { minSeverity: "High" },
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
  });
});
