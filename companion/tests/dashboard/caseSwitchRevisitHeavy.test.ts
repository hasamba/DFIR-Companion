// #2940 (continued): the heavier panels, the deferred ones (customer exposure, attack phases — a
// hidden section's loader never runs for B at all), the three panels that had no reset hook (missed
// evidence review, second look, containment check) and the false-positive dialog. A -> B -> A with no
// loader for B retires the first visit's answers at B's open; a reopen of the same case keeps them.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown> & { activeCaseId?: string | null };
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
const onclick = (p: Page, id: string) => (p.el(id) as unknown as { onclick: () => void }).onclick();

/** A -> B -> A: two full case opens (reset listeners run); B never runs this panel's loader. */
function awayUnloaded(p: Page, api: object) {
  p.open("CASE-B", api);
  p.open("CASE-A", api);
}
const noSkip = (p: Page) => ({ ...(p.globals.DfirPanelDefer as object), skip: () => false });

describe("narrative and second opinion (#2940)", () => {
  function narrative() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-narrative.js", ESC, {
      ...p.globals,
      isSectionVisible: () => true,
      loadSectionsVis: () => ({}),
      narrativeViewHtml: (t: string) => t,
      renderSynthMeta: () => {},
    });
    api.loadSynthMeta("CASE-A");
    api.genNarrative();
    return { p, api, old: last(p) };
  }

  it("Generate: B opening frees both buttons; A's old narrative then paints nothing", async () => {
    const { p, api, old } = narrative();
    p.open("CASE-B", api);
    expect(p.el("genNarrativeBtn").disabled).toBe(false);
    expect(p.el("editNarrativeBtn").disabled).toBe(false);
    p.open("CASE-A", api);
    p.requests[old].answer({ narrativeTimeline: "OLD-NARRATIVE" });
    await drainAll();
    expect(p.el("narrativeView").innerHTML).not.toContain("OLD-NARRATIVE");
  });

  it("Generate: a reopen of the same case keeps it", async () => {
    const { p, api, old } = narrative();
    p.open("CASE-A", api);
    p.requests[old].answer({ narrativeTimeline: "FRESH" });
    await drainAll();
    expect(p.el("narrativeView").innerHTML).toContain("FRESH");
  });

  it("second opinion: B opening frees Run; the old answer frees no newer run's button", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-second-opinion.js", ESC, {
      ...p.globals,
      render: () => {},
    });
    api.loadSecondOpinion("CASE-A");
    p.requests[last(p)].answer(null);
    await drainAll();
    api.runSecondOpinion();
    const old = last(p);
    p.open("CASE-B", api);
    expect(p.el("secondOpinion").disabled, "B's open left the button disabled").toBe(false);
    p.open("CASE-A", api);
    api.runSecondOpinion();
    p.requests[old].answer({ error: "OLD-FAIL" });
    await drainAll();
    expect(p.el("status").textContent).not.toContain("OLD-FAIL");
    expect(p.el("secondOpinion").disabled).toBe(true);
  });
});

describe("super-timeline and Velociraptor (#2940)", () => {
  it("starred report: B opening frees the button; the old answer leaves a newer one busy", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-super-timeline.js", ESC, {
      ...p.globals,
      DfirStarred: { count: () => 1, has: () => false },
      presidioHoldText: (s: string) => s,
    });
    api.loadSavedTimeframes("CASE-A"); // registers the reset hook, as the case open does
    api.genStarredReport();
    const old = last(p);
    p.open("CASE-B", api);
    expect(p.el("stStarredReport").disabled, "B's open left the button busy").toBe(false);
    p.open("CASE-A", api);
    api.genStarredReport();
    p.requests[old].answer({ error: "OLD" }, false);
    await drainAll();
    expect(p.el("stStarredReport").disabled).toBe(true);
  });

  it("promote: rows ticked on A are not sent to B when B opens before its super-timeline loads", () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-super-timeline.js", ESC, {
      ...p.globals,
      DfirStarred: { count: () => 0, has: () => false },
    });
    api.loadSavedTimeframes("CASE-A");
    api.toggleSuperPromote("A-ROW", true);
    p.open("CASE-A", api);
    api.promoteSuperSelected();
    const promotes = () => p.urls().filter((u) => u.endsWith("/super-timeline/promote"));
    expect(promotes(), "a reopen of the same case kept the ticks").toEqual([
      "/cases/CASE-A/super-timeline/promote",
    ]);
    api.toggleSuperPromote("A-ROW-2", true);
    p.open("CASE-B", api);
    api.promoteSuperSelected();
    expect(promotes()).not.toContain("/cases/CASE-B/super-timeline/promote");
  });

  function velo(file: string, extra: Record<string, unknown> = {}) {
    const p = fakePage();
    const ref: { api?: Api } = {};
    const api = loadDashboardModule<Api>(file, ESC, {
      ...p.globals,
      veloCaseId: () => ref.api?.activeCaseId ?? null,
      veloEnabled: true,
      veloMonAutoBrowsed: () => true,
      setVeloMonAutoBrowsed: () => {},
      veloClientsList: () => [],
      revealSection: () => {},
      ...extra,
    });
    ref.api = api;
    return { p, api };
  }

  it("monitors: B opening frees Start; the old answer says nothing and frees no newer Start", async () => {
    const { p, api } = velo("dashboard-velo-monitors.js");
    api.loadVeloMonitors("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("veloMonArtifactManual").value = "Generic.Client.Stats";
    p.el("veloMonAllClients").checked = true;
    api.veloMonStart();
    const old = last(p);
    p.open("CASE-B", api);
    expect(p.el("veloMonStartBtn").disabled, "B's open left Start disabled").toBe(false);
    p.open("CASE-A", api);
    api.veloMonStart();
    p.requests[old].answer({ error: "OLD-ERROR" }, false);
    await drainAll();
    expect(p.el("veloMonMsg").textContent).not.toContain("OLD-ERROR");
    expect(p.el("veloMonStartBtn").disabled).toBe(true);
  });

  it("external import: B opening clears a shown re-import prompt; the old answer paints nothing", async () => {
    const { p, api } = velo("dashboard-velo-triage.js", { renderVeloJobs: () => {} });
    api.loadVeloHuntJobs("CASE-A");
    p.el("veloExtRef").value = "H.123";
    api.veloImportExternal();
    const old = last(p);
    p.el("veloExtMsg").innerHTML = "Hunt H.1 was already pulled into this case — Re-import";
    p.open("CASE-B", api);
    expect(p.el("veloExtMsg").innerHTML).not.toContain("already pulled");
    expect(p.el("veloExtGo").disabled).toBe(false);
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-ERROR" }, false);
    await drainAll();
    expect(p.el("veloExtMsg").textContent).not.toContain("OLD-ERROR");
  });

  it("external import: a reopen of the same case keeps it", async () => {
    const { p, api } = velo("dashboard-velo-triage.js", { renderVeloJobs: () => {} });
    api.loadVeloHuntJobs("CASE-A");
    p.el("veloExtRef").value = "H.123";
    api.veloImportExternal();
    const old = last(p);
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "SHOWN-ERROR" }, false);
    await drainAll();
    expect(p.el("veloExtMsg").textContent).toContain("SHOWN-ERROR");
  });
});

describe("import changes Run all (#2940)", () => {
  async function runAll() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-import-changes.js", ESC, {
      ...p.globals,
      openSettingsTab: () => {},
      renderTimelineEvents: () => {},
      renderIocs: () => {},
      confirm: () => true,
    });
    api.loadImportMeta("CASE-A");
    api.loadDropStatus("CASE-A");
    const pending = [{ relpath: "x.evtx", configured: true, suggestedTool: "hayabusa" }];
    p.requests.find((r) => r.url.endsWith("/drop-status"))!.answer({ status: { pendingRawInputs: pending } });
    await drainAll();
    onclick(p, "dropRunAll");
    return { p, api, old: last(p) };
  }

  it("an answer after A -> B -> A says nothing", async () => {
    const { p, api, old } = await runAll();
    awayUnloaded(p, api);
    p.requests[old].answer({ ran: 3 });
    await drainAll();
    expect(p.el("status").textContent).not.toContain("Ran 3");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await runAll();
    p.open("CASE-A", api);
    p.requests[old].answer({ ran: 3 });
    await drainAll();
    expect(p.el("status").textContent).toContain("Ran 3");
  });
});

describe("false positives, customer exposure and source trust (#2940)", () => {
  function fp() {
    const p = fakePage();
    const docClicks: ((e: unknown) => void)[] = [];
    const api = loadDashboardModule<Api>("dashboard-exposure-fp.js", ESC, {
      ...p.globals,
      DfirPanelDefer: noSkip(p),
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
    return { p, api, docClicks };
  }
  const marker = (ref: string) => ({ id: ref, kind: "event", ref, markedAt: "2020-01-01T00:00:00Z" });
  async function unmarking() {
    const h = fp();
    h.api.loadFalsePositives("CASE-A");
    h.p.requests[last(h.p)].answer([]);
    await drainAll();
    const target = {
      closest: (sel: string) => (sel === ".unfp-btn" ? { dataset: { id: "event:e1" } } : null),
    };
    h.docClicks.forEach((fn) => fn({ target }));
    return { ...h, old: last(h.p) };
  }

  it("un-mark: an answer after A -> B -> A does not repaint the list", async () => {
    const { p, api, old } = await unmarking();
    awayUnloaded(p, api);
    p.requests[old].answer([marker("OLDER")]);
    await drainAll();
    expect(p.el("false-positive").innerHTML).not.toContain("OLDER");
  });

  it("un-mark: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await unmarking();
    p.open("CASE-A", api);
    p.requests[old].answer([marker("KEPT")]);
    await drainAll();
    expect(p.el("false-positive").innerHTML).toContain("KEPT");
  });

  const exposure = (domain: string) => ({
    targets: { domains: [domain], emails: [] },
    exposure: {},
    providers: [],
  });
  async function savingTarget() {
    const h = fp();
    h.api.loadCustomerExposure("CASE-A");
    h.p.requests[last(h.p)].answer(exposure("a.test"));
    await drainAll();
    h.api.ceAddTarget("domain", "x.test");
    return { ...h, old: last(h.p) };
  }

  it("customer exposure (deferred): a target save after A -> B -> A says nothing", async () => {
    const { p, api, old } = await savingTarget();
    expect(p.requests[old].init?.method).toBe("PUT");
    p.open("CASE-B", api);
    expect(p.el("ceDomainChips").innerHTML, "B's open left A's chips").not.toContain("a.test");
    p.open("CASE-A", api);
    p.requests[old].answer({});
    await drainAll();
    expect(p.el("customerExposureMsg").textContent).not.toBe("saved");
  });

  it("customer exposure: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await savingTarget();
    p.open("CASE-A", api);
    p.requests[old].answer({});
    await drainAll();
    expect(p.el("customerExposureMsg").textContent).toBe("saved");
  });

  async function savingTrust() {
    const h = fp();
    h.api.loadSourceTrust("CASE-A");
    h.p.requests[last(h.p)].answer({ defaults: { AAA: 0.5 }, overrides: {} });
    await drainAll();
    h.p.el("sourceTrustSaveBtn").fire("click", { stopPropagation: () => {} });
    return { ...h, old: last(h.p) };
  }

  it("source trust: a Save after A -> B -> A paints nothing", async () => {
    const { p, api, old } = await savingTrust();
    awayUnloaded(p, api);
    p.requests[old].answer({ defaults: { OLDER: 0.5 }, overrides: {} });
    await drainAll();
    expect(p.el("sourceTrustList").innerHTML).not.toContain("OLDER");
    expect(p.el("sourceTrustMsg").textContent).not.toContain("saved");
  });

  it("source trust: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await savingTrust();
    p.open("CASE-A", api);
    p.requests[old].answer({ defaults: { KEPT: 0.5 }, overrides: {} });
    await drainAll();
    expect(p.el("sourceTrustList").innerHTML).toContain("KEPT");
  });
});

describe("attack phases (deferred) (#2940)", () => {
  function phases() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-attack-phases.js", ESC, {
      ...p.globals,
      DfirPanelDefer: noSkip(p),
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

  it("a load from the first visit to A paints nothing after A -> B -> A", async () => {
    const { p, api } = phases();
    api.loadPhases("CASE-A");
    awayUnloaded(p, api);
    p.requests[0].answer(phase("FIRST-VISIT"));
    await drainAll();
    expect(p.el("phases").innerHTML).not.toContain("FIRST-VISIT");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api } = phases();
    api.loadPhases("CASE-A");
    p.open("CASE-A", api);
    p.requests[0].answer(phase("KEPT"));
    await drainAll();
    expect(p.el("phases").innerHTML).toContain("KEPT");
  });
});

describe("missed evidence review, second look, containment check (#2940)", () => {
  async function jev() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-jev-review.js", ESC, p.globals);
    api.initJevReview();
    void api.loadJevReview("CASE-A");
    p.requests[last(p)].answer({ configured: true });
    await drainAll();
    p.el("jevRunBtn").fire("click");
    return { p, api, old: last(p) };
  }

  it("review: B opening ends the wait; the old failure then paints nothing on A", async () => {
    const { p, api, old } = await jev();
    expect(p.requests[old].url).toContain("/jev/review");
    p.open("CASE-B", api);
    expect(p.el("jevCancelBtn").hidden, "B's open left the review running").toBe(true);
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("jevReviewPanel").innerHTML).not.toContain("OLD-FAIL");
  });

  it("review: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await jev();
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("jevReviewPanel").innerHTML).toContain("OLD-FAIL");
  });

  async function secondLook() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-second-look.js", ESC, {
      ...p.globals,
      loadSynthMeta: () => {},
    });
    void api.loadSecondLookPreview("CASE-A");
    p.requests[last(p)].answer({ configured: true, questions: 1 });
    await drainAll();
    void api.runSecondLook();
    return { p, api, old: last(p) };
  }

  it("second look: B opening frees Run; the old failure then says nothing on A", async () => {
    const { p, api, old } = await secondLook();
    expect(p.requests[old].url).toContain("/second-look");
    p.open("CASE-B", api);
    expect(p.el("secondLookRunBtn").textContent).not.toBe("Looking…");
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("secondLookStatus").textContent).not.toContain("OLD-FAIL");
  });

  it("second look: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await secondLook();
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("secondLookStatus").textContent).toContain("OLD-FAIL");
  });

  async function containment() {
    const p = fakePage();
    const docClicks: ((e: unknown) => void)[] = [];
    const api = loadDashboardModule<Api>("dashboard-containment-check.js", ESC, {
      ...p.globals,
      document: {
        ...(p.globals.document as object),
        addEventListener: (t: string, fn: (e: unknown) => void) => t === "click" && docClicks.push(fn),
      },
      render: () => {},
      DfirState: { lastState: () => null },
      loadPlaybook: () => {},
    });
    void api.loadContainmentCheck("CASE-A");
    p.requests[last(p)].answer({ configured: true });
    await drainAll();
    const self: Record<string, unknown> = {
      getAttribute: (n: string) => (n === "data-ccheck-run" ? "f1" : null),
    };
    self.closest = (sel: string) => (sel === "[data-ccheck-run]" ? self : null);
    docClicks.forEach((fn) => fn({ target: self }));
    return { p, api, old: last(p) };
  }
  const RESULT = {
    checkId: "c",
    model: "m",
    checkedAt: "2026-01-01T00:00:00Z",
    answers: [],
    steps: [{ id: "s1", title: "OLD-STEP", priority: "high", basis: [], basisLabels: [] }],
  };

  it("containment check: an answer after A -> B -> A paints nothing", async () => {
    const { p, api, old } = await containment();
    expect(p.requests[old].url).toContain("/containment-check");
    awayUnloaded(p, api);
    p.requests[old].answer(RESULT);
    await drainAll();
    expect(String(api.containmentCheckPanel("f1"))).not.toContain("OLD-STEP");
  });

  it("containment check: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await containment();
    p.open("CASE-A", api);
    p.requests[old].answer(RESULT);
    await drainAll();
    expect(String(api.containmentCheckPanel("f1"))).toContain("OLD-STEP");
  });
});

describe("false-positive dialog (#2940)", () => {
  function modal() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-false-positive.js", ESC, {
      ...p.globals,
      commitFalsePositives: () => {},
      investigatorName: () => "analyst",
    });
    api.initFalsePositiveModal();
    api.openFalsePositiveModal("ioc", "IOC-ONE", "x", []);
    p.el("fpConfirmBtn").fire("click");
    return { p, api };
  }

  it("another case opening clears 'marking…' and closes A's dialog: its Save sends nothing to B", async () => {
    const { p, api } = modal();
    await drainAll();
    expect(p.el("fpMsg").textContent).toContain("marking");
    p.open("CASE-B", api);
    expect(p.el("fpMsg").textContent).toBe("");
    const before = p.requests.length;
    p.el("fpConfirmBtn").fire("click");
    await drainAll();
    expect(p.requests.length, "A's dialog posted to B").toBe(before);
  });

  it("a cancel does the same; a reopen of the same case keeps the line and the dialog", async () => {
    const { p, api } = modal();
    await drainAll();
    p.open("CASE-A", api);
    expect(p.el("fpMsg").textContent).toContain("marking");
    const before = p.requests.length;
    p.el("fpConfirmBtn").fire("click");
    await drainAll();
    expect(p.requests.length).toBe(before + 1);
    p.cancel(api);
    expect(p.el("fpMsg").textContent).toBe("");
  });
});
