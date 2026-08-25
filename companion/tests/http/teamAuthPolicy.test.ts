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

  // The public demo is deliberately unauthenticated, so it needs a way to say so. The two override
  // values are not interchangeable: one claims the port is loopback-published, the other admits the
  // exposure is real. A typo in either must still refuse rather than half-open the server.
  it("accepts both documented unauthenticated-remote overrides and nothing else", () => {
    const single = resolveTeamAuthConfig({});
    for (const value of ["container-loopback-proxy", "public-demo"]) {
      expect(() =>
        assertRemoteBindingSafe("0.0.0.0", single, { DFIR_ALLOW_UNAUTHENTICATED_REMOTE: value }),
      ).not.toThrow();
    }
    for (const value of ["public", "demo", "true", "1", "yes", ""]) {
      expect(() =>
        assertRemoteBindingSafe("0.0.0.0", single, { DFIR_ALLOW_UNAUTHENTICATED_REMOTE: value }),
      ).toThrow(/refusing to bind/);
    }
    // Demo mode alone is not an opt-out: its gate still allow-lists POST /cases/seed-demo.
    expect(() => assertRemoteBindingSafe("0.0.0.0", single, { DFIR_DEMO_MODE: "1" })).toThrow(
      /refusing to bind/,
    );
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

  // The proxied basemap (routes/geoTiles.ts). It carries no case data — a tile is the same picture
  // of the world for every user — but an unlisted top-level path falls through to the global-admin
  // default, which would leave the Geographic Map blank for every reader, investigator and
  // reviewer while working perfectly for whoever added the route.
  it("treats a basemap tile as an authenticated asset, and only for GET", () => {
    expect(resolveRequestPolicy("GET", "/geo-tiles/3/4/5.png")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/geo-tiles/3/4/5.png")).toEqual({
      kind: "global",
      permission: "admin",
    });
  });

  // The wizard's suggested incident number. It reads across every case on disk, so it must not be
  // per-case gated — but anyone who may create a case may ask what to call it, so it is no more
  // than authenticated either. It deliberately does NOT live under /cases/, where a single
  // segment would have made it a case policy for a case named "next-id".
  it("treats the next-case-id suggestion as authenticated, and only for GET", () => {
    expect(resolveRequestPolicy("GET", "/api/next-case-id")).toEqual({ kind: "authenticated" });
    expect(resolveRequestPolicy("POST", "/api/next-case-id")).toEqual({
      kind: "global",
      permission: "admin",
    });
  });

  // The regression that moved it out of /cases/: every /cases/<segment> path is a per-case policy,
  // so the suggestion would have 404'd for every non-admin as a case they cannot see.
  it("would have made a /cases-mounted suggestion a per-case policy", () => {
    expect(resolveRequestPolicy("GET", "/cases/next-id")).toEqual({
      kind: "case",
      permission: "read",
      caseId: "next-id",
    });
  });
});

/**
 * A permission bucket must be chosen by the ROUTE, never by a value the route carries.
 *
 * The review and export checks used to scan the whole path suffix for a substring, and that suffix
 * contains user-named segments: an MCP server id, a hostname read out of evidence. So naming an MCP
 * server "report" moved POST /cases/:id/mcp/report/run into the export bucket — which a READER
 * holds — and naming one "review" moved it into the reviewer's. The scan was also case-sensitive
 * while Express routing is not, so POST /cases/c1/SECOND-OPINION/APPLY reached the reviewer-only
 * handler holding only investigator "write".
 */
describe("case permission buckets are chosen by route, not by path content", () => {
  const permission = (method: string, path: string): string => {
    const policy = resolveRequestPolicy(method, path) as { kind: string; permission?: string };
    return policy.permission ?? policy.kind;
  };

  it("classifies the real review routes as review, in any casing", () => {
    for (const path of [
      "/cases/c1/cockpit/review",
      "/cases/c1/presidio-pending/approve",
      "/cases/c1/presidio-pending/suppress",
      "/cases/c1/second-opinion/apply",
      "/cases/c1/second-opinion/apply-all",
      "/cases/c1/report-versions/v3/review/approve",
    ]) {
      expect(permission("POST", path), path).toBe("review");
      expect(permission("POST", path.toUpperCase().replace("/CASES/C1", "/cases/c1")), path).toBe("review");
    }
  });

  it("classifies the real export routes as export, in any casing", () => {
    for (const path of [
      "/cases/c1/attack-layer.json",
      "/cases/c1/custody/manifest",
      "/cases/c1/export/stix",
      "/cases/c1/geo-map.csv",
      "/cases/c1/incident-timeline.csv",
      "/cases/c1/present/export",
      "/cases/c1/report.docx",
      "/cases/c1/report/interactive",
      "/cases/c1/super-timeline.jsonl",
      "/cases/c1/timeline.jsonl",
    ]) {
      expect(permission("GET", path), path).toBe("export");
      expect(permission("GET", path.toUpperCase().replace("/CASES/C1", "/cases/c1")), path).toBe("export");
    }
    expect(permission("POST", "/cases/c1/export/encrypted")).toBe("export");
    expect(permission("POST", "/cases/c1/report")).toBe("export");
  });

  it("does not let a user-named path segment buy a weaker permission", () => {
    // Running an MCP server is a write, whatever the operator called the server. "report" and
    // "export" are the dangerous names: export is held by a READER, the lowest role there is.
    for (const name of ["report", "export", "review", "Report", "EXPORT", "second-opinion"]) {
      expect(permission("POST", `/cases/c1/mcp/${name}/run`), name).toBe("write");
    }
    // A hostname comes out of evidence, so an adversary has a say in it.
    for (const host of ["report", "export", "review"]) {
      expect(permission("POST", `/cases/c1/host-scope/${host}`), host).toBe("write");
    }
  });

  // Express is not in "strict routing" mode, so /cockpit/review/ reaches the same handler as
  // /cockpit/review. Anchoring the patterns with $ made the trailing-slash spelling miss every one
  // of them and fall through to the "write" default — reintroducing, in a new spelling, the exact
  // bypass the anchoring was added to close. policy.ts already had collectionPath() for this on
  // NON_CASE_PATHS; the suffix needs the same treatment.
  it("classifies a trailing-slash spelling the same as the bare route", () => {
    for (const path of [
      "/cases/c1/cockpit/review",
      "/cases/c1/presidio-pending/approve",
      "/cases/c1/second-opinion/apply",
      "/cases/c1/report-versions/v3/review/approve",
    ]) {
      expect(permission("POST", `${path}/`), path).toBe("review");
    }
    for (const path of ["/cases/c1/attack-layer.json", "/cases/c1/custody/manifest"]) {
      expect(permission("GET", `${path}/`), path).toBe("export");
    }
  });

  // The review bucket has to cover the whole report-review workflow, not just approve. These two
  // were caught by the old substring check and are the reviewer's actual day job: a reviewer holds
  // "review" but NOT "write", so classifying them as write locks the assigned reviewer out with a
  // 403 rather than letting anyone through.
  it("covers every report-version review mutation, not only approve", () => {
    for (const action of ["approve", "annotations", "request-changes"]) {
      expect(permission("POST", `/cases/c1/report-versions/v3/review/${action}`), action).toBe("review");
      expect(caseRoleAllows("reviewer", "review")).toBe(true);
      expect(caseRoleAllows("reviewer", "write")).toBe(false);
    }
  });

  it("keeps export out of a reader's reach on anything that is not an export route", () => {
    // The concrete escalation: reader holds "export", so any route that lands in that bucket by
    // accident is reachable by the least-privileged role in the case.
    expect(caseRoleAllows("reader", "export")).toBe(true);
    expect(caseRoleAllows("reader", "write")).toBe(false);
    expect(permission("POST", "/cases/c1/mcp/report/run")).not.toBe("export");
  });
});
