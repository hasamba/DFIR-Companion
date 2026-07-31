import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { autocompleteFor, buildPivotQuery, csvFromRows } from "../../../public/js/hunt-workbench.js";

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
});
