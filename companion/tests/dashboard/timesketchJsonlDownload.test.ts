// The Timesketch JSONL download tells the analyst how many rows it left out (#957).
//
// Before, the export was a bare navigation: the file arrived, undated rows were missing, and the
// status line said nothing. Now the module asks the server what the export will leave out, puts the
// count on the status line, and then navigates — so the browser still streams the file to disk.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface UnifiedExportApi {
  initUnifiedExport: () => void;
}

function harness(preview: { ok: boolean; omitted?: number }) {
  const status = { textContent: "" };
  const reportLinks = { innerHTML: "" };
  const exportSelect = { value: "", onchange: null as null | ((e: { target: { value: string } }) => void) };
  const elements: Record<string, unknown> = {
    status,
    reportLinks,
    exportSelect,
    caseId: { value: "case-1" },
  };
  const fetched: string[] = [];
  const location = { href: "" };
  const globals = {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      querySelector: () => null,
      addEventListener: () => {},
    },
    location, // the loader makes `window` the sandbox itself, so window.location is this
    fetch: (url: string) => {
      fetched.push(url);
      return Promise.resolve({
        ok: preview.ok,
        status: preview.ok ? 200 : 500,
        json: () => Promise.resolve({ scope: "forensic", events: 1, omitted: preview.omitted ?? 0 }),
      });
    },
  };
  const api = loadDashboardModule<UnifiedExportApi>(
    "dashboard-unified-export.js",
    ["dashboard-escape.js"],
    globals,
  );
  api.initUnifiedExport();
  return {
    status,
    fetched,
    location,
    choose: (v: string) => exportSelect.onchange!({ target: { value: v } }),
  };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

describe("Timesketch JSONL download", () => {
  it("asks what the forensic export leaves out, says so, then navigates to the file", async () => {
    const h = harness({ ok: true, omitted: 2 });
    h.choose("timesketch-jsonl");
    await settle();
    expect(h.fetched).toEqual(["/cases/case-1/timesketch-omitted?scope=forensic"]);
    expect(h.location.href).toBe("/cases/case-1/timeline.jsonl");
    expect(h.status.textContent).toBe(
      "Timesketch JSONL downloading — 2 undated row(s) left out (Timesketch requires a time; they stay in the Companion)",
    );
  });

  it("says nothing extra for the super-timeline when nothing is left out", async () => {
    const h = harness({ ok: true, omitted: 0 });
    h.choose("timesketch-jsonl-super");
    await settle();
    expect(h.fetched).toEqual(["/cases/case-1/timesketch-omitted?scope=super"]);
    expect(h.location.href).toBe("/cases/case-1/super-timeline.jsonl");
    expect(h.status.textContent).toBe("Timesketch JSONL downloading");
  });

  it("still downloads when the preview request fails", async () => {
    const h = harness({ ok: false });
    h.choose("timesketch-jsonl");
    await settle();
    expect(h.location.href).toBe("/cases/case-1/timeline.jsonl");
    expect(h.status.textContent).toBe("Timesketch JSONL downloading");
  });
});
