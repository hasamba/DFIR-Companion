import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// Log Analytics exports, JSON and CSV (synthetic fixtures — see matrix.ts). The JSON sign-in and
// audit tables carry OperationName + ResourceId/CorrelationId, which isAzure would claim, so their
// own signatures (cloudExportDetect.ts) are asked first (#2302).
describe("cloud compat — Log Analytics exports (#2300, #2302)", () => {
  it.each(rowsFor("Log Analytics export").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  const parsed = (fixture: string) =>
    parseM365Audit(fixtureText(COMPAT_ROWS.find((r) => r.fixture === fixture)!), { aggregate: false }).events;

  it.each(["log-analytics/SigninLogs.json", "log-analytics/SigninLogs.csv"])(
    "%s: a wrong password grades Medium + T1110, the same as the Graph sign-in",
    (fixture) => {
      const graph = parsed("mes-4.1.0/SignInLogs-20261101.json").find((e) =>
        e.description.includes("user1@"),
      );
      const la = parsed(fixture).find((e) => e.description.includes("user1@"));
      expect(la?.severity).toBe("Medium");
      expect(la?.mitreTechniques).toContain("T1110");
      expect(la?.severity).toBe(graph?.severity);
      expect(la?.description).toContain("[FAILED 50126");
      // The successful sign-in reads as a success, not as an unreadable status.
      const ok = parsed(fixture).find((e) => e.description.includes("user2@"));
      expect(ok?.severity).toBe("Info");
      expect(ok?.description).not.toContain("outcome unknown");
    },
  );

  it.each(["log-analytics/AuditLogs.json", "log-analytics/AuditLogs.csv"])(
    "%s: 'Add member to role' reads exactly as the Graph directoryAudit does, actor and role included",
    (fixture) => {
      const graph = parsed("dfir-o365rc-2.0/AADAuditLog_example.com_2026-11-01.json");
      const rows = parsed(fixture);
      expect(rows).toHaveLength(1);
      expect(rows[0].description).toContain("by admin@example.com");
      expect(rows[0].description).toContain("Global Administrator");
      expect(rows.map((e) => [e.severity, e.description])).toEqual(
        graph.map((e) => [e.severity, e.description]),
      );
    },
  );
});
