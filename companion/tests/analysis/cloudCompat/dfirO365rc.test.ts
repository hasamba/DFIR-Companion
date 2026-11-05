import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// DFIR-O365RC 2.0.x outputs (synthetic fixtures — see matrix.ts).
describe("cloud compat — DFIR-O365RC 2.0.x (#2300)", () => {
  it.each(rowsFor("DFIR-O365RC").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  it("the concatenated-arrays file (`][`) is read whole: every record of both writes", () => {
    const row = COMPAT_ROWS.find((r) => r.output.includes("concatenated-arrays"))!;
    const text = fixtureText(row);
    expect(text).toContain("][");
    const parsed = parseM365Audit(text);
    expect(parsed.total).toBe(4);
    expect(parsed.events).toHaveLength(4);
    // The seam is a repair, counted so the import note can disclose it (#2302).
    expect(parsed.repairs).toEqual({ bomStripped: 0, documentsJoined: 1, garbageSkipped: 0 });
  });
});
