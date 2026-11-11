// A failed UAL sign-in says why it failed (#2553): the row carries the record's LogonError and
// ErrorNumber inside its "[FAILED …]" bracket, the same form the Entra sign-in rows use, and a
// different error is a different row — so an account lockout (IdsLocked) is never folded under
// the wrong-password row that happened to come first.
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { ualFailureDetail } from "../../src/analysis/ualLogon.js";

const failedLogin = (minute: number, logonError?: string, errorNumber?: string) => ({
  CreationTime: `2023-05-01T11:0${minute}:00`,
  Operation: "UserLoginFailed",
  Workload: "AzureActiveDirectory",
  RecordType: 15,
  UserId: "victim@victim.example",
  ClientIP: "198.51.100.7",
  ObjectId: "Unknown",
  ResultStatus: "Failed",
  ...(logonError ? { LogonError: logonError } : {}),
  ...(errorNumber ? { ErrorNumber: errorNumber } : {}),
});

const parse = (recs: object[]) => parseM365Audit(recs.map((r) => JSON.stringify(r)).join("\n"));

describe("ualFailureDetail (#2553)", () => {
  it("reads LogonError and ErrorNumber from a UAL logon record", () => {
    expect(ualFailureDetail(failedLogin(0, "IdsLocked", "50053"))).toBe("IdsLocked 50053");
  });
  it("is empty when the record names no error, and for a record that is not a sign-in", () => {
    expect(ualFailureDetail(failedLogin(0))).toBe("");
    expect(ualFailureDetail({ Operation: "FileAccessed", LogonError: "IdsLocked" })).toBe("");
  });
  it("keeps the bracket intact: no brackets, no line breaks, a bounded length", () => {
    const d = ualFailureDetail(failedLogin(0, `Bad]\n[x ${"A".repeat(200)}`, "1"));
    expect(d).not.toMatch(/[[\]\r\n]/);
    expect(d.length).toBeLessThanOrEqual(80);
  });
});

describe("parseM365Audit — failed UAL sign-ins name their error (#2553)", () => {
  it("renders [FAILED <LogonError> <ErrorNumber>] and keeps the grade", () => {
    const r = parse([failedLogin(0, "IdsLocked", "50053")]);
    const e = r.events[0];
    expect(e.description).toContain("→ Unknown [FAILED IdsLocked 50053]");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1110");
  });

  it("keeps the plain [FAILED] when the record names no error", () => {
    const e = parse([failedLogin(0)]).events[0];
    expect(e.description).toMatch(/\[FAILED\]$/);
  });

  it("splits sign-ins from one user and one address by error, so a lockout is searchable", () => {
    const r = parse([
      failedLogin(0, "InvalidUserNameOrPassword", "50126"),
      failedLogin(1, "IdsLocked", "50053"),
      failedLogin(2, "UserStrongAuthEnrollmentRequiredInterrupt", "50072"),
    ]);
    const failed = r.events.filter((e) => e.description.includes("UserLoginFailed"));
    expect(failed).toHaveLength(3);
    expect(failed.filter((e) => e.description.includes("IdsLocked"))).toHaveLength(1);
  });

  it("still folds repeats of the same error into one row", () => {
    const r = parse([failedLogin(0, "IdsLocked", "50053"), failedLogin(1, "IdsLocked", "50053")]);
    expect(r.events.filter((e) => e.description.includes("UserLoginFailed"))).toHaveLength(1);
  });
});
