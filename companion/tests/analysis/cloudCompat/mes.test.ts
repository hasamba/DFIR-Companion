import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { checkRow } from "./harness.js";
import { COMPAT_ROWS, fixtureText, rowsFor } from "./matrix.js";

// Microsoft-Extractor-Suite 4.1.0 outputs (synthetic fixtures — see matrix.ts). Each row asserts
// the kind detected TODAY; a misrouted row asserts the wrong kind and names the expected one.
describe("cloud compat — Microsoft-Extractor-Suite 4.1.0 (#2300)", () => {
  it.each(rowsFor("Microsoft-Extractor-Suite").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });

  it("mailboxAuditLog CSV: forced through m365 the rows map but carry no time (LastAccessed unread)", () => {
    const row = COMPAT_ROWS.find((r) => r.fixture.includes("mailboxAuditLog-"))!;
    const { events } = parseM365Audit(fixtureText(row));
    expect(events).toHaveLength(2);
    expect(events.every((e) => !e.timestamp)).toBe(true);
  });
});
