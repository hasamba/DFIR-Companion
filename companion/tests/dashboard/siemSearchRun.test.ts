import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2666 — the "Run in Falcon" button on CQL hunt cards: shown only when the server has the
// Next-Gen SIEM search set up, and only on CQL cards.

interface Api {
  loadMainSource: () => Promise<void>;
  setPlaybookLanguageHunts: (h: unknown[]) => void;
  playbookLanguageHuntsHtml: (taskId: string) => string;
  loadSiemSearch: () => Promise<void>;
}

function load(siem: unknown) {
  const elements: Record<string, Record<string, unknown>> = { caseId: { value: "c1" } };
  const document = { getElementById: (id: string) => elements[id] ?? null };
  const fetch = async (url: string) => ({
    ok: true,
    json: async () => (String(url).endsWith("/crowdstrike/siem") ? siem : null),
  });
  return loadDashboardModule<Api>(
    "dashboard-main-source.js",
    ["dashboard-escape.js", "dashboard-siem-search.js"],
    { document, fetch },
  );
}

const hunt = (over: Record<string, unknown> = {}) => ({
  taskId: "t1",
  language: "cql",
  title: "Find the loader",
  query: "#event_simpleName=ProcessRollup2 | table([ComputerName])",
  severity: "High",
  ...over,
});

const CONFIGURED = {
  configured: true,
  repository: "search-all",
  maxWindowDays: 7,
  maxRows: 10000,
  timeoutMs: 300000,
  defaultRange: { start: "2026-11-10T00:00:00.000Z", end: "2026-11-17T00:00:00.000Z" },
};

describe("Run in Falcon on CQL cards (#2666)", () => {
  it("is absent when the SIEM search is not set up — the card stays copy-ready", async () => {
    const api = load({ configured: false });
    await api.loadSiemSearch();
    api.setPlaybookLanguageHunts([hunt()]);
    const html = api.playbookLanguageHuntsHtml("t1");
    expect(html).not.toContain("msh-siem-run");
    expect(html).toContain("copy-ready");
  });

  it("appears on CQL cards only when the search is set up", async () => {
    const api = load(CONFIGURED);
    await api.loadSiemSearch();
    api.setPlaybookLanguageHunts([hunt(), hunt({ taskId: "t2", language: "spl", query: "index=main" })]);
    const cql = api.playbookLanguageHuntsHtml("t1");
    expect(cql).toContain("msh-siem-run");
    expect(cql).toContain("Run in Falcon");
    expect(cql).toContain("runnable");
    const spl = api.playbookLanguageHuntsHtml("t2");
    expect(spl).not.toContain("msh-siem-run");
    expect(spl).toContain("copy-ready");
  });
});
