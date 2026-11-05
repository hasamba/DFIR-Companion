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

  it("mailboxAuditLog CSV: each row carries its LastAccessed time and the mailbox owner (#2302)", () => {
    const row = COMPAT_ROWS.find((r) => r.fixture.includes("mailboxAuditLog-"))!;
    const { events } = parseM365Audit(fixtureText(row), { aggregate: false });
    expect(events.map((e) => e.timestamp)).toEqual(["2026-11-01T10:05:00Z", "2026-11-01T10:06:00Z"]);
    expect(events.every((e) => e.description.includes("by user1@example.com"))).toBe(true);
  });
});
