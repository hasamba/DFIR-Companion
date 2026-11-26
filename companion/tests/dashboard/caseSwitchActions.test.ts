// #2929: more action answers (a click's request) that checked only which case is on screen. After a
// cancelled load and a reopen of the same case — or A -> B -> A — the case on screen matches again, so
// each module now also checks an action generation that moves only when its owner case changes.
// Custody Verify, duplicate hosts and tagger rows are in caseSwitchCancel.test.ts.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown>;
// The page's shared helper scripts the loaded modules call at render time (as caseSwitchLightPanels).
const ESC = [
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-text.js",
  "dashboard-glyphs.js",
  "dashboard-values.js",
  "dashboard-fragments.js",
  "dashboard-filters.js",
  "dashboard-ioc.js",
];

/** Cancel, then reopen case A and run its loader, whose answer the test gives next. */
function cancelAndReopen(p: Page, api: object, load: () => void) {
  p.cancel(api);
  p.switchCase("CASE-A", api);
  load();
  return p.requests.length - 1;
}

describe("Presidio decisions (#2929)", () => {
  const row = (value: string) => ({ value, category: "PERSON" });
  function presidio() {
    const p = fakePage();
    const refreshed: string[] = [];
    // The rows' buttons are wired by querySelectorAll on the panel; hand back one fake button each.
    const clicks: Record<string, () => void> = {};
    Object.assign(p.el("presidioPending"), {
      querySelectorAll: (sel: string) => [
        {
          disabled: false,
          getAttribute: () => "AAA",
          addEventListener: (_t: string, fn: () => void) => (clicks[sel] = fn),
        },
      ],
    });
    const api = loadDashboardModule<Api>("dashboard-presidio.js", ESC, {
      ...p.globals,
      refreshAiState: (c: string) => refreshed.push(c),
      loadAnonEntities: () => Promise.resolve(),
      renderAutoEntities: () => {},
    });
    return { p, api, clicks, refreshed };
  }
  async function shownA(p: Page, api: Api, values: string[]) {
    api.loadPresidioPending("CASE-A");
    p.requests[p.requests.length - 1].answer({ pending: values.map(row) });
    await drainAll();
  }

  it.each(["[data-presidio-approve]", "[data-presidio-suppress]"])(
    "%s: the old answer paints nothing after a cancel and a reopen",
    async (sel) => {
      const { p, api, clicks, refreshed } = presidio();
      await shownA(p, api, ["AAA"]);
      clicks[sel]();
      const old = p.requests.length - 1;
      const reload = cancelAndReopen(p, api, () => api.loadPresidioPending("CASE-A"));
      p.requests[reload].answer({ pending: [row("NEW")] });
      await drainAll();
      p.requests[old].answer({ pending: [row("OLD")] });
      await drainAll();
      expect(p.el("presidioPending").innerHTML).toContain("NEW");
      expect(p.el("presidioPending").innerHTML).not.toContain("OLD");
      expect(refreshed).toEqual([]);
    },
  );

  it("a refusal answering after a cancel and a reopen says nothing", async () => {
    const { p, api, clicks } = presidio();
    await shownA(p, api, ["AAA"]);
    clicks["[data-presidio-suppress]"]();
    const old = p.requests.length - 1;
    cancelAndReopen(p, api, () => api.loadPresidioPending("CASE-A"));
    p.requests[old].answer({ error: "presidio_not_pending", pending: [row("OLD")] }, false, 409);
    await drainAll();
    expect(p.el("anonMsg").textContent).toBe("");
  });

  it("Leave all visible stops after a cancel: no more requests, no message, no AI refresh", async () => {
    const { p, api, refreshed } = presidio();
    await shownA(p, api, ["AAA", "BBB"]);
    const run = api.suppressAllPresidioPending("CASE-A") as Promise<void>;
    await drainAll();
    const first = p.requests.length - 1;
    expect(JSON.parse(p.requests[first].init?.body ?? "{}").value).toBe("AAA");
    const reload = cancelAndReopen(p, api, () => api.loadPresidioPending("CASE-A"));
    p.requests[reload].answer({ pending: [row("AAA"), row("BBB")] });
    await drainAll();
    p.requests[first].answer({ pending: [row("BBB")] });
    await run;
    await drainAll();
    expect(p.requests.filter((r) => r.url.endsWith("/suppress"))).toHaveLength(1);
    expect(p.el("presidioPending").innerHTML).toContain("AAA");
    expect(refreshed).toEqual([]);
  });
});

describe("finding workflow PATCH (#2929)", () => {
  it("the old answer does not overwrite the reopened case's assignee", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-finding-workflow.js", ESC, {
      ...p.globals,
      render: () => {},
      investigatorName: () => "analyst",
      ICON_FLOW: "<svg/>",
      ICON_USER: "<svg/>",
    });
    api.loadFindingWorkflow("CASE-A");
    p.requests[0].answer([]);
    await drainAll();
    api.setFindingWorkflowStatus("f1", "in_progress");
    const old = p.requests.length - 1;
    const reload = cancelAndReopen(p, api, () => api.loadFindingWorkflow("CASE-A"));
    p.requests[reload].answer([{ findingId: "f1", assignee: "NEWER", status: "done" }]);
    await drainAll();
    p.requests[old].answer({ record: { findingId: "f1", assignee: "OLDER", status: "in_progress" } });
    await drainAll();
    expect(String(api.findingWorkflowControls("f1"))).toContain("NEWER");
    expect(String(api.findingWorkflowControls("f1"))).not.toContain("OLDER");
  });
});

describe("pinned findings (#2929)", () => {
  function pins() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-pinned-findings.js", ESC, {
      ...p.globals,
      render: () => {},
      investigatorName: () => "analyst",
      ICON_PIN: "<svg/>",
    });
    return { p, api };
  }

  it("a pin answer after a cancel and a reopen does not repaint the pins", async () => {
    const { p, api } = pins();
    api.loadPins("CASE-A");
    p.requests[0].answer({ pins: [], limit: 5 });
    await drainAll();
    api.togglePin("f1");
    const old = p.requests.length - 1;
    const reload = cancelAndReopen(p, api, () => api.loadPins("CASE-A"));
    p.requests[reload].answer({ pins: [], limit: 5 });
    await drainAll();
    p.requests[old].answer({ pins: [{ findingId: "f1" }], limit: 5 });
    await drainAll();
    expect(String(api.pinBtn("f1"))).not.toContain(" pinned");
  });

  it("a refused pin after a cancel and a reopen shows no message", async () => {
    const { p, api } = pins();
    api.loadPins("CASE-A");
    p.requests[0].answer({ pins: [], limit: 5 });
    await drainAll();
    api.togglePin("f1");
    const old = p.requests.length - 1;
    const reload = cancelAndReopen(p, api, () => api.loadPins("CASE-A"));
    p.requests[reload].answer({ pins: [], limit: 5 });
    await drainAll();
    const before = p.el("pinnedCount").textContent;
    p.requests[old].answer({ error: "case closed" }, false);
    await drainAll();
    expect(p.el("pinnedCount").textContent).toBe(before);
  });
});

describe("playbook hunt suggestions (#2929)", () => {
  function playbook() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-playbook.js", ESC, { ...p.globals, VHS_SEV_RANK: {} });
    const loaded = async () => {
      api.loadPlaybook("CASE-A");
      p.requests[p.requests.length - 1].answer({ tasks: [], stats: null, control: null });
      await drainAll();
    };
    return { p, api, loaded };
  }

  it("a cancel frees Suggest, and the old answer neither paints nor frees a newer request's button", async () => {
    const { p, api, loaded } = playbook();
    await loaded();
    api.doSuggestPlaybookHunts();
    const old = p.requests.length - 1;
    expect(p.el("pbHuntBtn").disabled).toBe(true);
    p.cancel(api);
    expect(p.el("pbHuntBtn").disabled, "the cancel left Suggest disabled").toBe(false);
    p.switchCase("CASE-A", api);
    await loaded();
    api.doSuggestPlaybookHunts();
    const newer = p.requests.length - 1;
    p.requests[old].answer({ suggestions: [{ taskId: "t", title: "OLD-HUNT", vql: "x" }], generated: 1 });
    await drainAll();
    expect(p.el("pbHuntBtn").disabled, "the old answer freed the newer request's button").toBe(true);
    expect(p.el("pbHuntMsg").textContent).not.toContain("1 new");
    p.requests[newer].answer({ suggestions: [], generated: 0 });
    await drainAll();
    expect(p.el("pbHuntBtn").disabled).toBe(false);
  });
});

describe("report details Save (#2929)", () => {
  function reportMeta() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-report-meta.js", ESC, p.globals);
    return { p, api };
  }
  const puts = (p: Page) => p.requests.filter((r) => r.init?.method === "PUT");

  it("a Save whose pre-load is abandoned by a cancel sends nothing, even once the reopen fills the form", async () => {
    const { p, api } = reportMeta();
    void api.loadReportMeta("CASE-A");
    const saving = api.saveReportMeta({}) as Promise<void>;
    p.cancel(api);
    p.switchCase("CASE-A", api);
    void api.loadReportMeta("CASE-A");
    p.requests[2].answer({ companyName: "NEW" });
    await drainAll();
    p.requests[1].answer({ companyName: "OLD" });
    await saving;
    await drainAll();
    expect(puts(p)).toHaveLength(0);
    expect(p.el("rm-companyName").value).toBe("NEW");
  });

  it("a Save answering after a cancel and a reopen does not fill the form or say 'saved'", async () => {
    const { p, api } = reportMeta();
    void api.loadReportMeta("CASE-A");
    p.requests[0].answer({ companyName: "FIRST" });
    await drainAll();
    void api.saveReportMeta({ "rm-companyName": "SAVED" });
    const put = p.requests.length - 1;
    expect(p.requests[put].init?.method).toBe("PUT");
    const reload = cancelAndReopen(p, api, () => void api.loadReportMeta("CASE-A"));
    p.requests[reload].answer({ companyName: "NEW" });
    await drainAll();
    p.requests[put].answer({ companyName: "SAVED" });
    await drainAll();
    expect(p.el("rm-companyName").value).toBe("NEW");
    expect(p.el("rmStatus").textContent).not.toContain("saved");
  });
});

describe("false positives and source trust (#2929)", () => {
  function fp() {
    const p = fakePage();
    const docClicks: ((e: unknown) => void)[] = [];
    const doc = {
      ...(p.globals.document as object),
      addEventListener: (_t: string, fn: (e: unknown) => void) => docClicks.push(fn),
    };
    const api = loadDashboardModule<Api>("dashboard-exposure-fp.js", ESC, {
      ...p.globals,
      document: doc,
      render: () => {},
      fpMarkers: [],
      fpReasonFilter: "",
      qaAudit: () => {},
      qaResolveIocId: (r: string) => r,
    });
    api.initExposureFp();
    return { p, api, docClicks };
  }

  it("an un-mark answer after a cancel and a reopen does not repaint the list", async () => {
    const { p, api, docClicks } = fp();
    api.loadFalsePositives("CASE-A");
    p.requests[p.requests.length - 1].answer([]);
    await drainAll();
    const unfp = { dataset: { id: "event:e1" } };
    const target = { closest: (sel: string) => (sel === ".unfp-btn" ? unfp : null) };
    docClicks.forEach((fn) => fn({ target }));
    const old = p.requests.length - 1;
    expect(p.requests[old].url).toContain("/false-positive/remove");
    const reload = cancelAndReopen(p, api, () => api.loadFalsePositives("CASE-A"));
    p.requests[reload].answer([
      { id: "m-new", kind: "event", ref: "NEWER", markedAt: "2020-01-01T00:00:00Z" },
    ]);
    await drainAll();
    p.requests[old].answer([{ id: "m-old", kind: "event", ref: "OLDER", markedAt: "2020-01-01T00:00:00Z" }]);
    await drainAll();
    expect(p.el("false-positive").innerHTML).toContain("NEWER");
    expect(p.el("false-positive").innerHTML).not.toContain("OLDER");
  });

  it("a source-trust Save answering after a cancel and a reopen paints nothing", async () => {
    const { p, api } = fp();
    api.loadSourceTrust("CASE-A");
    p.requests[p.requests.length - 1].answer({ defaults: { AAA: 0.5 }, overrides: {} });
    await drainAll();
    p.el("sourceTrustSaveBtn").fire("click", { stopPropagation: () => {} });
    const old = p.requests.length - 1;
    expect(p.requests[old].init?.method).toBe("PUT");
    const reload = cancelAndReopen(p, api, () => api.loadSourceTrust("CASE-A"));
    p.requests[reload].answer({ defaults: { NEWER: 0.5 }, overrides: {} });
    await drainAll();
    p.requests[old].answer({ defaults: { OLDER: 0.5 }, overrides: {} });
    await drainAll();
    expect(p.el("sourceTrustList").innerHTML).toContain("NEWER");
    expect(p.el("sourceTrustList").innerHTML).not.toContain("OLDER");
    expect(p.el("sourceTrustMsg").textContent).not.toContain("saved");
  });
});
