// #2933: the rest of #2929's action answers. Each one checked only which case is on screen, or
// nothing, so an answer sent before a cancelled load (or an A -> B -> A switch) painted over the same
// case reopened. They now also check an action generation that moves only when the panel's owner
// case changes — never on a same-case reload, whose answers still paint.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown>;
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
const last = (p: Page) => p.requests.length - 1;
const click = { stopPropagation: () => {} };

/** Cancel, then reopen case A and run its loader (the test answers it, or not). */
function cancelAndReopen(p: Page, api: object, load: () => void) {
  p.cancel(api);
  p.switchCase("CASE-A", api);
  load();
  return last(p);
}
/** A -> B -> A, each switch running the loader. */
function awayAndBack(p: Page, api: object, load: (c: string) => void) {
  p.switchCase("CASE-B", api);
  load("CASE-B");
  p.switchCase("CASE-A", api);
  load("CASE-A");
  return last(p);
}

describe("hypotheses (#2933)", () => {
  function hyp() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-hypotheses.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      render: () => {},
      loadSynthMeta: () => {},
    });
    api.initHypotheses();
    return { p, api };
  }
  async function loadedA(p: Page, api: Api, list: unknown[] = []) {
    api.loadHypotheses("CASE-A");
    p.requests[last(p)].answer(list);
    await drainAll();
  }
  const addClick = (p: Page) => (p.el("hypAddBtn") as unknown as { onclick: () => void }).onclick();

  it("Add: a refusal from before a cancel says nothing, and an old success keeps the new title", async () => {
    const { p, api } = hyp();
    await loadedA(p, api);
    p.el("hypTitle").value = "first";
    addClick(p);
    const refused = last(p);
    addClick(p);
    const accepted = last(p);
    cancelAndReopen(p, api, () => api.loadHypotheses("CASE-A"));
    p.el("hypTitle").value = "typed after the reopen";
    p.requests[refused].answer({ error: "OLD-REFUSAL" }, false, 423);
    p.requests[accepted].answer({ id: "h1" });
    await drainAll();
    expect(p.el("hypMsg").textContent).not.toContain("OLD-REFUSAL");
    expect(p.el("hypTitle").value).toBe("typed after the reopen");
  });

  it("Add: a same-case reload mid-request still shows the refusal", async () => {
    const { p, api } = hyp();
    await loadedA(p, api);
    p.el("hypTitle").value = "first";
    addClick(p);
    const old = last(p);
    api.loadHypotheses("CASE-A");
    p.requests[old].answer({ error: "STILL-SHOWN" }, false, 423);
    await drainAll();
    expect(p.el("hypMsg").textContent).toContain("STILL-SHOWN");
  });

  it("an edit refused before a cancel draws no refusal line on the reopened case's card", async () => {
    const { p, api } = hyp();
    const card = { id: "h1", title: "T", status: "open", source: "analyst" };
    await loadedA(p, api, [card]);
    api.hypPatch("h1", { status: "refuted" });
    const old = last(p);
    const reload = cancelAndReopen(p, api, () => api.loadHypotheses("CASE-A"));
    p.requests[reload].answer([card]);
    await drainAll();
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("hypList").innerHTML).not.toContain("OLD-REFUSAL");
  });

  it("an edit refused during a same-case reload still draws its line", async () => {
    const { p, api } = hyp();
    const card = { id: "h1", title: "T", status: "open", source: "analyst" };
    await loadedA(p, api, [card]);
    api.hypPatch("h1", { status: "refuted" });
    const old = last(p);
    api.loadHypotheses("CASE-A");
    p.requests[last(p)].answer([card]);
    p.requests[old].answer({ error: "SHOWN-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("hypList").innerHTML).toContain("SHOWN-REFUSAL");
  });

  it.each(["hypGenerateBtn", "hypReviewBtn"])(
    "%s: a cancel frees the button; the old answer neither paints nor frees a newer request's",
    async (btn) => {
      const { p, api } = hyp();
      await loadedA(p, api);
      p.el(btn).fire("click", click);
      const old = last(p);
      expect(p.el(btn).disabled).toBe(true);
      p.cancel(api);
      expect(p.el(btn).disabled, "the cancel left the button disabled").toBe(false);
      p.switchCase("CASE-A", api);
      await loadedA(p, api);
      p.el(btn).fire("click", click);
      const newer = last(p);
      p.requests[old].answer(
        { error: "OLD-FAIL", reviews: [{ hypothesisId: "h1", verdict: "OLD-REVIEW" }] },
        false,
      );
      await drainAll();
      expect(p.el(btn).disabled, "the old answer freed the newer request's button").toBe(true);
      expect(p.el("hypGenMsg").textContent).not.toContain("failed");
      p.requests[newer].answer({ reviews: [] });
      await drainAll();
      expect(p.el(btn).disabled).toBe(false);
    },
  );

  it("Review: an old answer after A -> B -> A draws no review box", async () => {
    const { p, api } = hyp();
    await loadedA(p, api);
    p.el("hypReviewBtn").fire("click", click);
    const old = last(p);
    awayAndBack(p, api, (c) => api.loadHypotheses(c));
    p.requests[old].answer({
      reviews: [{ hypothesisId: "h1", title: "OLD-REVIEW", recommendedStatus: "refuted" }],
    });
    await drainAll();
    expect(p.el("hypReviewResults").innerHTML).not.toContain("OLD-REVIEW");
  });
});

describe("AI status actions (#2933)", () => {
  function ai() {
    const p = fakePage();
    const resynths: number[] = [];
    const api = loadDashboardModule<Api>("dashboard-ai-status.js", ESC, {
      ...p.globals,
      setAi: () => {},
      paintIngest: () => {},
      hideImportProgress: () => {},
      loadPresidioPending: () => {},
      loadHostDuplicates: () => {},
      loadAnonToggle: () => {},
      resynthesize: () => resynths.push(1),
      ws: null,
    });
    return { p, api, resynths };
  }
  async function offerSkip(p: Page, api: Api) {
    void api.refreshAiState("CASE-A");
    p.requests[last(p)].answer({ state: "idle", screenshotHold: { count: 2, token: "tok" } });
    await drainAll();
  }
  const skipBtn = (p: Page) => p.el("heldSkipBtn") as unknown as { onclick: () => void };

  it.each([
    ["a success", { skipped: 2, remaining: 0 }, true, 200],
    ["a 409", { error: "changed" }, false, 409],
  ] as const)(
    "Skip held screenshots: %s from before a cancel writes no status line",
    async (_n, body, ok, status) => {
      const { p, api } = ai();
      await offerSkip(p, api);
      skipBtn(p).onclick();
      const old = last(p);
      expect(p.requests[old].url).toContain("skip-held-screenshots");
      cancelAndReopen(p, api, () => void api.refreshAiState("CASE-A"));
      p.el("status").textContent = "connected (live)";
      p.requests[old].answer(body, ok, status);
      await drainAll();
      expect(p.el("status").textContent).toBe("connected (live)");
    },
  );

  it("Skip held screenshots: a same-case refresh mid-request still writes the line", async () => {
    const { p, api } = ai();
    await offerSkip(p, api);
    skipBtn(p).onclick();
    const old = last(p);
    void api.refreshAiState("CASE-A");
    p.requests[old].answer({ skipped: 2, remaining: 0 });
    await drainAll();
    expect(p.el("status").textContent).toContain("skipped AI analysis of 2");
  });

  it("Continue without Presidio: a pre-read answering after a cancel sends no switch-off", async () => {
    const { p, api, resynths } = ai();
    api.applyAiStatus({ status: "error", detail: "presidio down" });
    const anon = p.requests.find((r) => r.url.endsWith("/anon-control"));
    anon?.answer({ presidioConfigured: true, presidio: true });
    await drainAll();
    p.requests.find((r) => r.url.endsWith("/presidio-health"))?.answer({ reachable: false });
    await drainAll();
    (p.el("presidioContinueBtn") as unknown as { onclick: () => void }).onclick();
    const pre = last(p);
    cancelAndReopen(p, api, () => void api.refreshAiState("CASE-A"));
    p.requests[pre].answer({ version: 3 });
    await drainAll();
    expect(p.requests.filter((r) => r.init?.method === "POST")).toHaveLength(0);
    expect(resynths).toEqual([]);
  });
});

describe("the cross-module setters (#2933)", () => {
  function fpModule(p: Page) {
    return loadDashboardModule<Api>("dashboard-exposure-fp.js", ESC, {
      ...p.globals,
      document: { ...(p.globals.document as object), addEventListener: () => {} },
      render: () => {},
      fpMarkers: [],
      fpReasonFilter: "",
    });
  }
  const marker = (ref: string) => ({ id: ref, kind: "event", ref, markedAt: "2020-01-01T00:00:00Z" });

  it("commitFalsePositives drops a write from a generation before a cancel and a reopen", async () => {
    const p = fakePage();
    const api = fpModule(p);
    api.loadFalsePositives("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    const gen = api.falsePositiveGen();
    const reload = cancelAndReopen(p, api, () => api.loadFalsePositives("CASE-A"));
    p.requests[reload].answer([marker("NEWER")]);
    await drainAll();
    api.commitFalsePositives("CASE-A", [marker("OLDER")], gen);
    expect(p.el("false-positive").innerHTML).toContain("NEWER");
    expect(p.el("false-positive").innerHTML).not.toContain("OLDER");
  });

  it("commitFalsePositives still takes a write across a same-case reload, and one with no generation", async () => {
    const p = fakePage();
    const api = fpModule(p);
    api.loadFalsePositives("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    const gen = api.falsePositiveGen();
    api.loadFalsePositives("CASE-A");
    api.commitFalsePositives("CASE-A", [marker("SAME-CASE")], gen);
    expect(p.el("false-positive").innerHTML).toContain("SAME-CASE");
    api.commitFalsePositives("CASE-A", [marker("NO-GEN")]);
    expect(p.el("false-positive").innerHTML).toContain("NO-GEN");
  });

  it("setPresidioPending drops a hold's findings from before a cancel; a same-case reload keeps them", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-presidio.js", ESC, {
      ...p.globals,
      refreshAiState: () => {},
      loadAnonEntities: () => Promise.resolve(),
      renderAutoEntities: () => {},
    });
    api.loadPresidioPending("CASE-A");
    p.requests[last(p)].answer({ pending: [] });
    await drainAll();
    const gen = api.presidioPendingGen();
    api.loadPresidioPending("CASE-A");
    api.setPresidioPending([{ value: "SAME-CASE", category: "PERSON" }], "CASE-A", gen);
    expect(p.el("presidioPending").innerHTML).toContain("SAME-CASE");
    cancelAndReopen(p, api, () => api.loadPresidioPending("CASE-A"));
    api.setPresidioPending([{ value: "OLDER", category: "PERSON" }], "CASE-A", gen);
    expect(p.el("presidioPending").innerHTML).not.toContain("OLDER");
  });

  it.each([
    ["dashboard-ioc-whitelist.js", "wlApplyToCase"],
    ["dashboard-nsrl.js", "nsrlApplyToCase"],
  ])("%s passes the generation it started in", async (file, fn) => {
    const p = fakePage();
    const commits: unknown[][] = [];
    const api = loadDashboardModule<Api>(file, ESC, {
      ...p.globals,
      falsePositiveGen: () => 7,
      commitFalsePositives: (...args: unknown[]) => commits.push(args),
    });
    api[fn]();
    p.requests[last(p)].answer({ matched: 1, matchedIocs: 1, matchedEvents: 0, added: 1, legitimate: [] });
    await drainAll();
    expect(commits).toEqual([["CASE-A", [], 7]]);
  });
});

describe("customer exposure (#2933)", () => {
  function ce() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-exposure-fp.js", ESC, {
      ...p.globals,
      DfirPanelDefer: { ...(p.globals.DfirPanelDefer as object), skip: () => false },
      document: { ...(p.globals.document as object), addEventListener: () => {} },
      render: () => {},
      fpMarkers: [],
      fpReasonFilter: "",
    });
    return { p, api };
  }
  const exposure = (domain: string) => ({
    targets: { domains: [domain], emails: [] },
    exposure: {},
    providers: [],
  });

  it("a load answering for a case the analyst left, or behind a newer load, paints nothing", async () => {
    const { p, api } = ce();
    api.loadCustomerExposure("CASE-A");
    const first = last(p);
    api.loadCustomerExposure("CASE-A");
    p.requests[last(p)].answer(exposure("newer.test"));
    await drainAll();
    p.requests[first].answer(exposure("older.test"));
    await drainAll();
    expect(p.el("ceDomainChips").innerHTML).toContain("newer.test");
    expect(p.el("ceDomainChips").innerHTML).not.toContain("older.test");
    api.loadCustomerExposure("CASE-A");
    const left = last(p);
    p.switchCase("CASE-B", api);
    p.requests[left].answer(exposure("left.test"));
    await drainAll();
    expect(p.el("ceDomainChips").innerHTML).not.toContain("left.test");
  });

  it("a cancel blanks the panel; the cancelled case's answer and an old check paint nothing", async () => {
    const { p, api } = ce();
    api.loadCustomerExposure("CASE-A");
    p.requests[last(p)].answer(exposure("a.test"));
    await drainAll();
    api.runCustomerExposureCheck();
    const check = last(p);
    api.loadCustomerExposure("CASE-A");
    const inflight = last(p);
    p.cancel(api);
    expect(p.el("ceDomainChips").innerHTML).not.toContain("a.test");
    p.switchCase("CASE-A", api);
    api.loadCustomerExposure("CASE-A");
    p.requests[inflight].answer(exposure("cancelled.test"));
    p.requests[check].answer({ results: [{}], errors: [] });
    await drainAll();
    expect(p.el("ceDomainChips").innerHTML).not.toContain("cancelled.test");
    expect(p.el("customerExposureMsg").textContent).not.toContain("checked");
  });

  it("a target save answering after A -> B -> A says nothing; a same-case reload still shows 'saved'", async () => {
    const { p, api } = ce();
    api.loadCustomerExposure("CASE-A");
    p.requests[last(p)].answer(exposure("a.test"));
    await drainAll();
    api.ceAddTarget("domain", "x.test");
    const old = last(p);
    expect(p.requests[old].init?.method).toBe("PUT");
    awayAndBack(p, api, (c) => api.loadCustomerExposure(c));
    p.requests[old].answer({});
    await drainAll();
    expect(p.el("customerExposureMsg").textContent).not.toBe("saved");
    p.requests[last(p)].answer(exposure("a.test"));
    await drainAll();
    api.ceAddTarget("domain", "y.test");
    const put = last(p);
    api.loadCustomerExposure("CASE-A");
    p.requests[put].answer({});
    await drainAll();
    expect(p.el("customerExposureMsg").textContent).toBe("saved");
  });

  it("no targets are saved onto a case whose own targets have not loaded yet", async () => {
    const { p, api } = ce();
    api.loadCustomerExposure("CASE-A");
    p.requests[last(p)].answer(exposure("a.test"));
    await drainAll();
    p.switchCase("CASE-B", api);
    api.loadCustomerExposure("CASE-B");
    api.ceAddTarget("domain", "typed.test");
    expect(p.requests.filter((r) => r.init?.method === "PUT")).toHaveLength(0);
  });
});

describe("source trust has its own generation (#2933)", () => {
  it("a first source-trust load for the same case does not drop an un-mark answer", async () => {
    const p = fakePage();
    const docClicks: ((e: unknown) => void)[] = [];
    const api = loadDashboardModule<Api>("dashboard-exposure-fp.js", ESC, {
      ...p.globals,
      document: {
        ...(p.globals.document as object),
        addEventListener: (_t: string, fn: (e: unknown) => void) => docClicks.push(fn),
      },
      render: () => {},
      fpMarkers: [],
      fpReasonFilter: "",
      qaAudit: () => {},
      qaResolveIocId: (r: string) => r,
    });
    api.initExposureFp();
    api.loadFalsePositives("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    const target = {
      closest: (sel: string) => (sel === ".unfp-btn" ? { dataset: { id: "event:e1" } } : null),
    };
    docClicks.forEach((fn) => fn({ target }));
    const old = last(p);
    api.loadSourceTrust("CASE-A"); // the source-trust panel's first load for this case
    p.requests[old].answer([{ id: "m", kind: "event", ref: "KEPT", markedAt: "2020-01-01T00:00:00Z" }]);
    await drainAll();
    expect(p.el("false-positive").innerHTML).toContain("KEPT");
  });
});

describe("attack phases loader (#2933)", () => {
  function phases() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-attack-phases.js", ESC, {
      ...p.globals,
      DfirPanelDefer: { ...(p.globals.DfirPanelDefer as object), skip: () => false },
      DfirState: { lastFt: () => [] },
      _hasActiveFilter: () => false,
      KC_SEV_COLOR: {},
      mitreLinks: () => "",
    });
    return { p, api };
  }
  const phase = (label: string) => [
    { id: label, label, startTimestamp: "2024-01-01T00:00:00Z", eventCount: 1, eventIds: [] },
  ];

  it("only the newest load paints", async () => {
    const { p, api } = phases();
    api.loadPhases("CASE-A");
    api.loadPhases("CASE-A");
    p.requests[1].answer(phase("NEWER"));
    await drainAll();
    p.requests[0].answer(phase("OLDER"));
    await drainAll();
    expect(p.el("phases").innerHTML).toContain("NEWER");
    expect(p.el("phases").innerHTML).not.toContain("OLDER");
  });

  it("a load from before a cancel paints nothing on the reopened case", async () => {
    const { p, api } = phases();
    api.loadPhases("CASE-A");
    p.cancel(api);
    p.switchCase("CASE-A", api);
    p.requests[0].answer(phase("CANCELLED"));
    await drainAll();
    expect(p.el("phases").innerHTML).not.toContain("CANCELLED");
  });
});
