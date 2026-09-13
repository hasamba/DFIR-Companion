// A generated report that shipped with an evidence-safety warning says so on the status line (#1006).
//
// The server returns the warning lines with the report paths; the document itself carries the same
// banner and the activity log has the line. This is the third place — where the analyst is looking
// when the button was pressed.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface UnifiedExportApi {
  initUnifiedExport: () => void;
}

function harness(response: Record<string, unknown>) {
  const status = { textContent: "" };
  const reportLinks = { innerHTML: "" };
  const exportSelect = { value: "", onchange: null as null | ((e: { target: { value: string } }) => void) };
  const elements: Record<string, unknown> = {
    status,
    reportLinks,
    exportSelect,
    caseId: { value: "case-1" },
  };
  const globals = {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      querySelector: () => null,
      addEventListener: () => {},
    },
    location: { href: "" },
    fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(response) }),
  };
  const api = loadDashboardModule<UnifiedExportApi>(
    "dashboard-unified-export.js",
    ["dashboard-escape.js"],
    globals,
  );
  api.initUnifiedExport();
  return { status, reportLinks, choose: (v: string) => exportSelect.onchange!({ target: { value: v } }) };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

describe("report generation status line", () => {
  it("names the evidence-safety warning the server returned", async () => {
    const h = harness({
      html: "/x/report.html",
      evidenceSafety: ["1 live indicator(s) not defanged: hxxp://evil[.]example"],
    });
    h.choose("report");
    await settle();
    expect(h.status.textContent).toBe(
      "report written — ⚠ evidence-safety warning: 1 live indicator(s) not defanged: hxxp://evil[.]example",
    );
    expect(h.reportLinks.innerHTML).toContain("Open HTML"); // the report still shipped
  });

  it("says nothing extra when the report was clean, or when an older server returns no field", async () => {
    const clean = harness({ html: "/x/report.html", evidenceSafety: [] });
    clean.choose("report");
    await settle();
    expect(clean.status.textContent).toBe("report written");
    const older = harness({ html: "/x/report.html" });
    older.choose("report");
    await settle();
    expect(older.status.textContent).toBe("report written");
  });
});
