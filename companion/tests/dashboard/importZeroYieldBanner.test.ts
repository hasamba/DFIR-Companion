// #2460: the import banner warns when an AI-triage import produced no events from a file that HAD
// rows — at any size, not only from 500 lines up — and does not cry wolf on a re-import whose events
// were all already in the timeline (addedCount 0, but the extraction kept events).
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Banner {
  innerHTML: string;
  style: { display: string };
}

async function renderBanner(meta: Record<string, unknown>): Promise<string> {
  const banner: Banner = { innerHTML: "", style: { display: "" } };
  const mod = loadDashboardModule<{ loadImportMeta(caseId: string): void }>(
    "dashboard-import-changes.js",
    ["dashboard-escape.js"],
    {
      document: { getElementById: (id: string) => (id === "importMeta" ? banner : null) },
      DfirState: { lastFt: () => null, lastState: () => null },
      relTime: () => "just now",
      fetch: async () => ({ ok: true, json: async () => meta }),
    },
  );
  mod.loadImportMeta("c1");
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  return banner.innerHTML;
}

const BASE = {
  lastImportedAt: "2026-11-09T10:00:00Z",
  lastImportKind: "csv",
  lastImportFile: "0001_sysmon<b>.csv",
  addedCount: 0,
  removedCount: 0,
  lastDiff: { added: [], removed: [] },
  linesIn: 15,
  path: "ai",
};

describe("import banner — AI extraction kept nothing (#2460)", () => {
  it("warns when a small AI import kept 0 of its rows, and says to check the provider", async () => {
    const html = await renderBanner({ ...BASE, aiExtraction: { rowsIn: 14, kept: 0 } });
    expect(html).toContain("AI extraction produced no events from 14 rows");
    expect(html).toContain("Check the AI provider");
    expect(html).toContain("not as clean");
    expect(html).toContain("0001_sysmon&lt;b&gt;.csv"); // escaped
    expect(html).not.toMatch(/AI off/i); // AI-off saves a CSV as evidence without analyzing it
  });

  it("says nothing extra for a re-import that kept events but added none (all deduplicated)", async () => {
    const html = await renderBanner({ ...BASE, aiExtraction: { rowsIn: 14, kept: 14 } });
    expect(html).toContain("no new events");
    expect(html).not.toContain("AI extraction produced no events");
  });

  it("says nothing extra for an older record without the extraction count", async () => {
    const html = await renderBanner({ ...BASE });
    expect(html).not.toContain("AI extraction produced no events");
  });

  it("shows ONE warning for a large file, the precise one, not the 500-line warning as well", async () => {
    const html = await renderBanner({
      ...BASE,
      linesIn: 27290,
      aiExtraction: { rowsIn: 27289, kept: 0 },
    });
    expect(html).toContain("AI extraction produced no events from 27,289 rows");
    expect(html).not.toContain("lines → 0 events via AI triage");
  });

  it("keeps the 500-line warning for a large AI import recorded before the count existed", async () => {
    const html = await renderBanner({ ...BASE, linesIn: 27290 });
    expect(html).toContain("lines → 0 events via AI triage");
  });
});
