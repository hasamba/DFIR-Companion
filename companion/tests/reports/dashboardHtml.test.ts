import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";

describe("dashboard.html", () => {
  it("contains websocket wiring and report button", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain("/ws?caseId=");
    expect(html).toContain('id="findings"');
    expect(html).toContain('id="timeline"');
    expect(html).toContain('id="openThreads"');
    expect(html).toContain('id="generateReport"');
  });

  it("wires the Report Details form (people fields + save) to /report-meta", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="saveReportMeta"');
    expect(html).toContain('id="rm-investigators"');
    expect(html).toContain('id="rm-reviewer"');
    expect(html).toContain('id="rm-incidentManager"');
    expect(html).toContain("/report-meta");
    expect(html).not.toContain('id="rm-investigator"'); // replaced by the plural field
  });
});
