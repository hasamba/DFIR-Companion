// #2915: a cancelled (or failed) case load must not leave the cancelled case's content in the light
// panels. The per-panel table runs in caseSwitchLightPanels; these are the panels with their own
// harness, and one run against the REAL js/dashboard-panel-defer.js (not the fake reset hook).
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument } from "./serverSetsFakeDom.js";

const ESC = ["dashboard-escape.js", "dashboard-time.js", "dashboard-text.js", "dashboard-glyphs.js"];
type Api = Record<string, (...args: unknown[]) => unknown>;

describe("duplicate hosts after a cancelled load (#2915)", () => {
  const pair = (host: string) => ({ canonical: `${host}.corp.test`, other: host, reason: "shortname-fqdn" });
  function hd() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-host-duplicates.js", ESC, {
      ...p.globals,
      applySectionsVis: () => {},
      SECTIONS_VIS_KEY: "dfir.sectionsVis",
    });
    return { p, api };
  }
  async function answerBoth(p: ReturnType<typeof fakePage>, from: number, host: string) {
    p.requests[from].answer({ pending: [pair(host)] });
    p.requests[from + 1].answer({ dismissed: [] });
    await drainAll();
  }

  it("the cancelled case's pairs and badge go, and reopening it reads them again", async () => {
    const { p, api } = hd();
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-a");
    void api.loadHostDuplicates("CASE-A"); // on its way at the cancel: never settles
    p.cancel(api);
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
    expect(p.el("hostDuplicatesBadge").style.display).toBe("none");
    p.switchCase("CASE-A", api);
    void api.loadHostDuplicates("CASE-A");
    expect(p.requests).toHaveLength(6);
    await answerBoth(p, 4, "ws-a");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-a");
  });
});

describe("client baseline after a cancelled load (#2915)", () => {
  type BaselineApi = { loadClientBaseline(caseId: string): Promise<void> };
  it("the cancelled case's panel is blanked and a render still running adds nothing", async () => {
    const p = fakePage();
    const doc = new FakeDocument();
    const { caseId, clientBaselinePanel } = doc.add("div", "caseId", "clientBaselinePanel");
    caseId.value = "CASE-A";
    const api = loadDashboardModule<BaselineApi>("dashboard-client-baseline.js", [], {
      document: doc,
      fetch: p.globals.fetch,
      DfirPanelDefer: p.globals.DfirPanelDefer,
    });
    void api.loadClientBaseline("CASE-A");
    p.requests[0].answer({ hunt: null });
    await drainAll();
    expect(clientBaselinePanel.children.length).toBeGreaterThan(0);
    void api.loadClientBaseline("CASE-A");
    caseId.value = "";
    p.cancel();
    expect(clientBaselinePanel.children).toHaveLength(0);
    caseId.value = "CASE-A";
    p.requests[1].answer({ hunt: null });
    await drainAll();
    expect(clientBaselinePanel.children).toHaveLength(0);
  });
});

describe("the real DfirPanelDefer reset reaches the light panels (#2915)", () => {
  it("custody: reset(null) blanks the panel; reset(caseId) does not; the reopen loads again", async () => {
    const p = fakePage();
    const globals: Record<string, unknown> = { ...p.globals };
    delete globals.DfirPanelDefer; // the real module publishes its own
    const api = loadDashboardModule<Api & { DfirPanelDefer: { reset(c: string | null): void } }>(
      "dashboard-custody.js",
      [...ESC, "dashboard-panel-defer.js"],
      globals,
    );
    const records = {
      records: [{ artifactPath: "AAA.png", event: "stored", at: "2020-01-01T00:00:00Z", sha256: "x" }],
    };
    api.loadCustody("CASE-A");
    p.requests[0].answer(records);
    await drainAll();
    expect(p.el("custodyPanel").innerHTML).toContain("AAA");
    api.DfirPanelDefer.reset("CASE-A"); // a case opening: the light panels keep their content
    expect(p.el("custodyPanel").innerHTML).toContain("AAA");
    p.el("caseId").value = "";
    api.DfirPanelDefer.reset(null); // the cancel
    expect(p.el("custodyPanel").innerHTML).toBe("");
    p.switchCase("CASE-A");
    api.loadCustody("CASE-A");
    expect(p.requests).toHaveLength(2);
    p.requests[1].answer(records);
    await drainAll();
    expect(p.el("custodyPanel").innerHTML).toContain("AAA");
  });
});
