import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// Log Analytics exports, JSON and CSV (synthetic fixtures — see matrix.ts). The JSON sign-in and
// audit tables carry OperationName + ResourceId/CorrelationId, so isAzure (cloudJsonDetect.ts)
// claims them before isM365 is asked: those rows assert "cloud" today, expected "m365".
describe("cloud compat — Log Analytics exports (#2300)", () => {
  it.each(rowsFor("Log Analytics export").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  const forced = (fixture: string) =>
    parseM365Audit(fixtureText(COMPAT_ROWS.find((r) => r.fixture === fixture)!)).events;

  it("SigninLogs forced through m365: the Status string column is unread, so a wrong password grades Low", () => {
    const failed = forced("log-analytics/SigninLogs.json").find((e) => e.description.includes("user1@"));
    expect(failed?.severity).toBe("Low");
  });

  it("AuditLogs forced through m365: 'Add member to role' grades High", () => {
    expect(forced("log-analytics/AuditLogs.json").map((e) => e.severity)).toEqual(["High"]);
  });
});
