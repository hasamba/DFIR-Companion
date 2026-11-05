import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// Azure diagnostic-settings export to a storage account, PT1H.json (synthetic fixtures — see matrix.ts).
describe("cloud compat — Azure diagnostic settings PT1H.json (#2300)", () => {
  it.each(rowsFor("Azure diagnostic settings").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  it("the Entra sign-in under `properties` is read: user, IP, outcome and grade (#2304)", () => {
    const row = COMPAT_ROWS.find((r) => r.fixture === "azure-diagnostic/signinlogs/PT1H.json")!;
    const [e] = parseM365Audit(fixtureText(row)).events;
    expect(e.timestamp).toBe("2026-11-01T11:01:00Z");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1078.004", "T1110"]);
    expect(e.description).toBe(
      "Entra sign-in: user1@example.com from 203.0.113.10 (Example City, XX) via Example App [FAILED 50126: Invalid username or password.]",
    );
  });
});
