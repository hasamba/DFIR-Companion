import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// Azure diagnostic-settings export to a storage account, PT1H.json (synthetic fixtures — see matrix.ts).
describe("cloud compat — Azure diagnostic settings PT1H.json (#2300)", () => {
  it.each(rowsFor("Azure diagnostic settings").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  it("an Entra sign-in under `properties` maps to nothing in m365 — parser work, not a detection fix", () => {
    const row = COMPAT_ROWS.find((r) => r.fixture === "azure-diagnostic/signinlogs/PT1H.json")!;
    expect(parseM365Audit(fixtureText(row)).events).toHaveLength(0);
  });
});
