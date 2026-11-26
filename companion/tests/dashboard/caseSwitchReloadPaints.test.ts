// #2937 (item 8): the other half of #2933's action-answer gates. A same-case reload of the panel
// while an action is in flight must NOT retire that action — its answer still paints. Each module
// below had only the cancel / switch half tested.
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
];
const last = (p: Page) => p.requests.length - 1;
const onclick = (p: Page, id: string) => (p.el(id) as unknown as { onclick: () => void }).onclick();

describe("a same-case reload keeps an action's answer (#2937)", () => {
  it("notebook: an add refused during a reload still says why", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-notebook.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      aiEnabled: true,
    });
    api.initNotebook();
    api.loadNotebook("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("nbText").value = "note";
    onclick(p, "nbAddBtn");
    const old = last(p);
    api.loadNotebook("CASE-A");
    p.requests[old].answer({ error: "SHOWN-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("nbMsg").textContent).toContain("SHOWN-REFUSAL");
  });

  it("comments: a post refused during a reload still says why", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-comments.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      targetKey: (t: string, i: string) => `${t}:${i}`,
      refreshSuperRows: () => {},
      mentionHtml: (t: string) => t,
      ICON_COMMENT: "",
    });
    api.loadComments("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    api.openCommentModal("event", "e1");
    p.el("commentText").value = "comment";
    api.postComment();
    const old = last(p);
    api.loadComments("CASE-A");
    p.requests[old].answer({ error: "SHOWN-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("commentMsg").textContent).toContain("SHOWN-REFUSAL");
  });

  it("tags: a failed add during a reload still says so", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-tags.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      targetKey: (t: string, i: string) => `${t}:${i}`,
      tagColor: () => "#fff",
      SUGGESTED_TAGS: [],
      loadSuperTimeline: () => {},
    });
    api.loadTags("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    api.setBulkTagTarget(["e1"], "event");
    api.addTag("suspicious");
    await drainAll();
    const old = last(p);
    api.loadTags("CASE-A");
    p.requests[old].answer({}, false);
    await drainAll();
    expect(p.el("tagMsg").textContent).toContain("failed");
  });

  it("correlation profile: Apply answering during a reload still paints info and status", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-correlation-profile.js", ESC, p.globals);
    api.loadCorrProfile("CASE-A");
    p.requests[last(p)].answer({ profileName: "moderate" });
    await drainAll();
    p.el("corrProfileSel").value = "strict";
    api.applyCorrProfile();
    const old = last(p);
    api.loadCorrProfile("CASE-A");
    p.requests[last(p)].answer({ profileName: "moderate" });
    await drainAll();
    p.requests[old].answer({ profileName: "strict" });
    await drainAll();
    expect(p.el("status").textContent).toContain("saved");
  });
});

describe("a same-case reload keeps a Velociraptor action's answer (#2937)", () => {
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

  it("monitors: a Start failing during a reload still says why", async () => {
    const { p, api } = velo("dashboard-velo-monitors.js");
    api.loadVeloMonitors("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("veloMonArtifactManual").value = "Generic.Client.Stats";
    p.el("veloMonAllClients").checked = true;
    api.veloMonStart();
    const old = last(p);
    api.loadVeloMonitors("CASE-A");
    p.requests[old].answer({ error: "SHOWN-ERROR" }, false);
    await drainAll();
    expect(p.el("veloMonMsg").textContent).toContain("SHOWN-ERROR");
  });

  it("external import: a failure during a reload still says why and frees Import", async () => {
    const { p, api } = velo("dashboard-velo-triage.js");
    api.loadVeloHuntJobs("CASE-A");
    p.el("veloExtRef").value = "H.123";
    api.veloImportExternal();
    const old = last(p);
    api.loadVeloHuntJobs("CASE-A");
    p.requests[old].answer({ error: "SHOWN-ERROR" }, false);
    await drainAll();
    expect(p.el("veloExtMsg").textContent).toContain("SHOWN-ERROR");
    expect(p.el("veloExtGo").disabled).toBe(false);
  });
});

describe("a same-case reload keeps second opinion and super-timeline answers (#2937)", () => {
  it("second opinion: a run failing during a reload still says why and frees the button", async () => {
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
    api.loadSecondOpinion("CASE-A");
    p.requests[old].answer({ error: "SHOWN-FAIL" });
    await drainAll();
    expect(p.el("status").textContent).toContain("SHOWN-FAIL");
    expect(p.el("secondOpinion").disabled).toBe(false);
  });

  function superTimeline() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-super-timeline.js", ESC, {
      ...p.globals,
      DfirStarred: { count: () => 1, has: () => false },
      presidioHoldText: (s: string) => s,
      mdToHtml: (s: string) => s,
      URLSearchParams,
      DfirTimelineView: { from: () => "", to: () => "", search: () => "", excludeTerms: () => [] },
    });
    api.loadSavedTimeframes("CASE-A");
    return { p, api };
  }

  it.each([
    ["genStarredReport", "stStarredReport"],
    ["genViewSummary", "stViewSummary"],
  ])("super-timeline %s: an answer during a reload still paints and frees the button", async (fn, btn) => {
    const { p, api } = superTimeline();
    api[fn]();
    const old = last(p);
    api.loadSavedTimeframes("CASE-A");
    p.requests[old].answer({ markdown: "FRESH-REPORT", eventCount: 2 });
    await drainAll();
    expect(p.el("stAiPanel").innerHTML).toContain("FRESH-REPORT");
    expect(p.el(btn).disabled).toBe(false);
  });
});
