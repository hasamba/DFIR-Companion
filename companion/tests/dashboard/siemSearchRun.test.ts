import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FALCON_CONSOLE_ORIGINS } from "../../src/integrations/crowdstrike/falconConsole.js";

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

describe("Open in Falcon (#2685)", () => {
  interface UrlApi extends Api {
    falconSearchUrl: (q: string, s?: string, e?: string, repo?: string) => string;
  }
  const loadUrl = (siem: unknown) => load(siem) as unknown as UrlApi;
  const ORIGINS = [
    "https://falcon.crowdstrike.com",
    "https://falcon.us-2.crowdstrike.com",
    "https://falcon.eu-1.crowdstrike.com",
    "https://falcon.laggar.gcw.crowdstrike.com",
  ];

  it.each(ORIGINS)(
    "builds the Advanced event search URL on %s with the query encoded and the range in ms",
    async (origin) => {
      const api = loadUrl({ ...CONFIGURED, consoleUrl: origin });
      await api.loadSiemSearch();
      const q = '#event_simpleName=ProcessRollup2 | CommandLine=/enc/i & x="a b"';
      const url = api.falconSearchUrl(q, "2026-11-10T00:00:00.000Z", "2026-11-17T00:00:00.000Z");
      expect(url).toBe(
        `${origin}/investigate/search?query=${encodeURIComponent(q)}&repo=all` +
          `&start=${Date.parse("2026-11-10T00:00:00.000Z")}&end=${Date.parse("2026-11-17T00:00:00.000Z")}`,
      );
      expect(new URL(url).searchParams.get("query")).toBe(q);
    },
  );

  it("leaves out repo for a repository other than search-all, and the range when it is unreadable", async () => {
    const api = loadUrl({ ...CONFIGURED, consoleUrl: ORIGINS[0] });
    await api.loadSiemSearch();
    expect(api.falconSearchUrl("x", "nope", "", "investigate_view")).toBe(
      `${ORIGINS[0]}/investigate/search?query=x`,
    );
  });

  it("no link without a console host, an unexpected host, or when the search is not set up", async () => {
    for (const siem of [
      CONFIGURED,
      { ...CONFIGURED, consoleUrl: "https://evil.example" },
      { configured: false },
    ]) {
      const api = loadUrl(siem);
      await api.loadSiemSearch();
      expect(api.falconSearchUrl("x")).toBe("");
    }
  });

  it("accepts exactly the console origins the server can emit — lookalikes get no link (#2696)", async () => {
    const api = loadUrl(CONFIGURED) as UrlApi & { FALCON_CONSOLE_ORIGINS: string[] };
    expect([...api.FALCON_CONSOLE_ORIGINS].sort()).toEqual([...FALCON_CONSOLE_ORIGINS].sort());
    for (const consoleUrl of [
      "https://falcon.example.com",
      "https://falcon.crowdstrike.com.evil.com",
      "https://falcon.evil-crowdstrike.com",
      "https://falcon.us-2.crowdstrike.mil",
      "https://falcon.eu-9.crowdstrike.com",
      "http://falcon.crowdstrike.com",
      "https://falcon.crowdstrike.com/",
      "https://falcon.crowdstrike.com/x",
      "https://FALCON.crowdstrike.com",
    ]) {
      const bad = loadUrl({ ...CONFIGURED, consoleUrl });
      await bad.loadSiemSearch();
      expect(bad.falconSearchUrl("x"), consoleUrl).toBe("");
    }
  });

  it("a CQL card carries the link with noopener noreferrer; other languages do not", async () => {
    const api = load({ ...CONFIGURED, consoleUrl: ORIGINS[1] });
    await api.loadSiemSearch();
    api.setPlaybookLanguageHunts([hunt(), hunt({ taskId: "t2", language: "spl", query: "index=main" })]);
    const cql = api.playbookLanguageHuntsHtml("t1");
    expect(cql).toContain('class="msh-siem-open"');
    expect(cql).toContain('rel="noopener noreferrer"');
    expect(cql).toContain('target="_blank"');
    expect(cql).toContain(`${ORIGINS[1]}/investigate/search?query=`);
    expect(api.playbookLanguageHuntsHtml("t2")).not.toContain("msh-siem-open");
  });
});
