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

  // The public demo at the Railway URL binds 0.0.0.0 in single-user mode, which the guard otherwise
  // refuses. It is allowed because demoModeReadOnlyGate answers every non-GET with 403, so there is
  // no writable surface to protect — and refusing would leave the advertised demo unable to start.
  it("accepts a public bind in read-only demo mode, and only in demo mode", () => {
    const single = resolveTeamAuthConfig({});
    expect(() => assertRemoteBindingSafe("0.0.0.0", single, { DFIR_DEMO_MODE: "1" })).not.toThrow();
    expect(() => assertRemoteBindingSafe("0.0.0.0", single, { DFIR_DEMO_MODE: "true" })).not.toThrow();

    // Anything that is not the documented spelling leaves the server writable, so it must still
    // refuse rather than half-enabling a demo the read-only gate was never mounted for.
    for (const value of ["yes", "on", "0", "false", ""]) {
      expect(() => assertRemoteBindingSafe("0.0.0.0", single, { DFIR_DEMO_MODE: value })).toThrow(
        /refusing to bind/,
      );
    }
    expect(() => assertRemoteBindingSafe("0.0.0.0", single, {})).toThrow(/refusing to bind/);
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
    expect(resolveRequestPolicy("POST", "/cases/c1/report-versions/v1/review/approve")).toMatchObject({
      permission: "review",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/report-versions/v1/workflow/release")).toMatchObject({
      permission: "write",
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
    // /import-file reads an operator-named absolute path off the server's own filesystem, so it
    // carries the same trust as /nsrl/import-file and /kev/import-file — global admin, never the
    // per-case "write" a plain investigator holds (#520).
    expect(resolveRequestPolicy("POST", "/cases/c1/import-file")).toEqual({
      kind: "global",
      permission: "admin",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/%69mport-file")).toEqual({
      kind: "global",
      permission: "admin",
    });
    // Express routing is case-insensitive by default, so /IMPORT-FILE reaches the same handler.
    // The classifier has to fold case too, or the elevated segments are one shift key from the
    // permissive default branch — for /import-file and for the case-admin segments alike.
    expect(resolveRequestPolicy("POST", "/cases/c1/IMPORT-FILE")).toEqual({
      kind: "global",
      permission: "admin",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/PassWord")).toMatchObject({
      permission: "admin",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("POST", "/cases/c1/ARCHIVE")).toMatchObject({
      permission: "admin",
      caseId: "c1",
    });
    // ...but only where the match is anchored at a literal route segment. The export and review
    // checks scan the whole suffix, which contains user-named values (an MCP server id, a report
    // version): folding those would let a server named "Report" pull POST /mcp/:id/run — a write
    // route — into the export bucket, which a reader holds.
    expect(resolveRequestPolicy("POST", "/cases/c1/mcp/Report/run")).toMatchObject({
      permission: "write",
      caseId: "c1",
    });
    // "import" and "seed-demo" are valid case ids (isValidCaseId accepts them) and any authenticated
    // user can create a case so named. Only the two real collection-level endpoints may skip the
    // case classifier — anything deeper is a case route and gets case rules, or /cases/import/delete
    // and /cases/import/import-file would answer to a plain authenticated session.
    expect(resolveRequestPolicy("POST", "/cases/import/import-file")).toEqual({
      kind: "global",
      permission: "admin",
    });
    expect(resolveRequestPolicy("POST", "/cases/import/delete")).toMatchObject({
      permission: "admin",
      caseId: "import",
    });
    expect(resolveRequestPolicy("GET", "/cases/import/state")).toMatchObject({
      permission: "read",
      caseId: "import",
    });
    expect(resolveRequestPolicy("POST", "/cases/import/encrypted")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/cases/seed-demo")).toEqual({
      kind: "global",
      permission: "admin",
    });
    // Express serves those two endpoints for any casing and with a trailing slash, so the exemption
    // has to recognise the same spellings the router does. Otherwise POST /cases/seed-demo/ reads as
    // a case named "seed-demo" and the demo seeder drops from global admin to plain case write.
    expect(resolveRequestPolicy("POST", "/cases/seed-demo/")).toEqual({
      kind: "global",
      permission: "admin",
    });
    expect(resolveRequestPolicy("POST", "/cases/SEED-DEMO")).toEqual({
      kind: "global",
      permission: "admin",
    });
    expect(resolveRequestPolicy("POST", "/cases/import/encrypted/")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/cases/import/ENCRYPTED")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("GET", "/js/safe-dom.js")).toEqual({ kind: "public" });
    expect(resolveRequestPolicy("GET", "/cases")).toEqual({ kind: "case-list" });
    expect(resolveRequestPolicy("GET", "/api/jobs")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/api/jobs/job_1/cancel")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/settings/env")).toEqual({ kind: "global", permission: "admin" });
  });
});
