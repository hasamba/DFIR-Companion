import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  autocompleteFor,
  buildPivotQuery,
  csvFromRows,
  pivotButtonHost,
} from "../../../public/js/hunt-workbench.js";

describe("hunt workbench UI helpers", () => {
  it("builds escaped, typed pivots for core entities", () => {
    expect(buildPivotQuery("event", 'e"1')).toBe('id="e\\"1"');
    expect(buildPivotQuery("ioc", "192.0.2.1")).toBe('ioc="192.0.2.1"');
    expect(buildPivotQuery("finding", "f1")).toBe('related.finding_id="f1"');
    expect(buildPivotQuery("asset", "DC01")).toBe('host.name="DC01"');
  });

  it("offers fields, operators and pipeline stages at the cursor", () => {
    const fields = autocompleteFor("event.cat", 9);
    expect(fields.some((item) => item.value === "event.category")).toBe(true);
    const pipelines = autocompleteFor("severity=High | gr", 18);
    expect(pipelines.some((item) => item.value === "group by")).toBe(true);
  });

  it("escapes formulas and quotes in CSV exports", () => {
    expect(
      csvFromRows(
        ["host", "count"],
        [
          { host: "=cmd|'/C calc'!A0", count: 1 },
          { host: 'a,"b"', count: 2 },
        ],
      ),
    ).toBe('host,count\r\n"\'=cmd|\'/C calc\'!A0",1\r\n"a,""b""",2\r\n');
  });

  it("is wired into the dashboard as a view-managed section", async () => {
    const dashboard = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(dashboard).toContain('<script type="module" src="/js/hunt-workbench.js"></script>');
    expect(dashboard).toContain('id="sec-hunt-workbench"');
    expect(dashboard).toContain('{ id: "sec-hunt-workbench", label: "Hunt Workbench" }');
  });

  // The pivot button was appended to the IOC row itself. That row is a four-column grid, so the
  // button became a fifth child and sat alone on a second line under the indicator.
  describe("pivot button placement", () => {
    const fakeRow = (rowClass: string, actionsCell: object | null) => ({
      classList: { contains: (name: string) => name === rowClass },
      querySelector: (sel: string) => (sel === ".ioc-actions-cell" ? actionsCell : null),
    });

    it("puts an IOC row's button in its actions cell, with the other row buttons", () => {
      const cell = { id: "actions" };
      const row = fakeRow("ioc-row", cell);
      expect(pivotButtonHost(row as unknown as Element)).toBe(cell);
    });

    it("falls back to the row when an IOC row has no actions cell", () => {
      const row = fakeRow("ioc-row", null);
      expect(pivotButtonHost(row as unknown as Element)).toBe(row);
    });

    it("leaves event, finding and asset rows as they were", () => {
      const row = fakeRow("ev-row", { id: "actions" });
      expect(pivotButtonHost(row as unknown as Element)).toBe(row);
    });
  });
});
