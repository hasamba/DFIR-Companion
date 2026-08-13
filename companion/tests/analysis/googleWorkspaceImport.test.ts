import { describe, it, expect } from "vitest";
import { parseGoogleWorkspaceReport } from "../../src/analysis/googleWorkspaceImport.js";

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
