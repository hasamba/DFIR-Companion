import { describe, expect, it } from "vitest";
import { assertRemoteBindingSafe, resolveTeamAuthConfig } from "../../src/auth/authConfig.js";
import { caseRoleAllows, resolveRequestPolicy } from "../../src/auth/policy.js";

describe("team-auth configuration and policy", () => {
  it("keeps team mode opt-in and refuses unsafe remote single-user binding", () => {
    expect(resolveTeamAuthConfig({}).enabled).toBe(false);
    expect(() => assertRemoteBindingSafe("0.0.0.0", resolveTeamAuthConfig({}), {})).toThrow(
      /authentication/i,
    );
    expect(() =>
      assertRemoteBindingSafe("0.0.0.0", resolveTeamAuthConfig({ DFIR_AUTH_MODE: "team" }), {}),
    ).not.toThrow();
  });

  it("keeps reviewer separation of duties instead of treating roles as a rank", () => {
    expect(caseRoleAllows("reader", "read")).toBe(true);
    expect(caseRoleAllows("reader", "write")).toBe(false);
    expect(caseRoleAllows("investigator", "write")).toBe(true);
    expect(caseRoleAllows("investigator", "review")).toBe(false);
    expect(caseRoleAllows("reviewer", "review")).toBe(true);
    expect(caseRoleAllows("reviewer", "write")).toBe(false);
    expect(caseRoleAllows("administrator", "admin")).toBe(true);
  });

  it("classifies case, review, export, capture, and global-admin boundaries explicitly", () => {
    expect(resolveRequestPolicy("GET", "/cases/c1/state")).toMatchObject({
      permission: "read",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/events")).toMatchObject({
      permission: "write",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/unlock")).toMatchObject({
      permission: "read",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/%70assword")).toMatchObject({
      permission: "admin",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/cockpit/review")).toMatchObject({
      permission: "review",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("GET", "/cases/c1/report.docx")).toMatchObject({
      permission: "export",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/report")).toMatchObject({
      permission: "export",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/export/encrypted")).toMatchObject({
      permission: "export",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/captures")).toEqual({ kind: "capture" });
    expect(resolveRequestPolicy("GET", "/cases")).toEqual({ kind: "case-list" });
    expect(resolveRequestPolicy("GET", "/api/jobs")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/api/jobs/job_1/cancel")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/settings/env")).toEqual({ kind: "global", permission: "admin" });
  });
});
