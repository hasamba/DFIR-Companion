// #2933: action answers whose status line, input or button checked no case at all (or only the case
// on screen). An answer sent before a cancelled load — or before an A -> B -> A switch — must not
// write over the case reopened; a same-case reload mid-action still lets it paint.
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

function cancelAndReopen(p: Page, api: object, load: () => void) {
  p.cancel(api);
  p.switchCase("CASE-A", api);
  load();
  return last(p);
}

describe("playbook status line (#2933)", () => {
  function playbook() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-playbook.js", ESC, { ...p.globals, VHS_SEV_RANK: {} });
    api.initPlaybook();
    return { p, api };
  }
  async function loaded(p: Page, api: Api) {
    api.loadPlaybook("CASE-A");
    p.requests[last(p)].answer({ tasks: [], stats: null, control: null });
    await drainAll();
  }

  it("Add: an old success keeps the reopened case's typed title; an old failure says nothing", async () => {
    const { p, api } = playbook();
    await loaded(p, api);
    p.el("pbTitle").value = "first";
    onclick(p, "pbAddBtn");
    const ok = last(p);
    onclick(p, "pbAddBtn");
    const failed = last(p);
    cancelAndReopen(p, api, () => api.loadPlaybook("CASE-A"));
    expect(p.el("pbMsg").textContent, "the cancel left 'adding…'").toBe("");
    p.el("pbTitle").value = "typed after the reopen";
    p.requests[ok].answer({ id: "t" });
    p.requests[failed].answer({}, false);
    await drainAll();
    expect(p.el("pbTitle").value).toBe("typed after the reopen");
    expect(p.el("pbMsg").textContent).not.toContain("failed");
  });

  it("Sync: a same-case reload mid-request still shows the failure", async () => {
    const { p, api } = playbook();
    await loaded(p, api);
    onclick(p, "pbSyncBtn");
    const old = last(p);
    api.loadPlaybook("CASE-A");
    p.requests[old].answer({}, false);
    await drainAll();
    expect(p.el("pbMsg").textContent).toContain("sync failed");
  });
});

describe("notebook (#2933)", () => {
  function notebook() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-notebook.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      aiEnabled: true,
    });
    api.initNotebook();
    return { p, api };
  }

  it("a list read from before a cancel does not fill the reopened case's notes", async () => {
    const { p, api } = notebook();
    api.loadNotebook("CASE-A");
    const old = last(p);
    const reload = cancelAndReopen(p, api, () => api.loadNotebook("CASE-A"));
    p.requests[reload].answer([{ id: "n2", type: "note", text: "NEWER" }]);
    await drainAll();
    p.requests[old].answer([{ id: "n1", type: "note", text: "OLDER" }]);
    await drainAll();
    expect(p.el("nbList").innerHTML).toContain("NEWER");
    expect(p.el("nbList").innerHTML).not.toContain("OLDER");
  });

  it("an add from before a cancel keeps the reopened case's typed text and says nothing", async () => {
    const { p, api } = notebook();
    api.loadNotebook("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("nbText").value = "first";
    onclick(p, "nbAddBtn");
    const ok = last(p);
    onclick(p, "nbAddBtn");
    const failed = last(p);
    cancelAndReopen(p, api, () => api.loadNotebook("CASE-A"));
    p.el("nbText").value = "typed after the reopen";
    p.requests[ok].answer({ id: "n1" });
    p.requests[failed].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("nbText").value).toBe("typed after the reopen");
    expect(p.el("nbMsg").textContent).not.toContain("OLD-REFUSAL");
  });

  it("an edit answering after a switch does not load the case left into the panel", async () => {
    const { p, api } = notebook();
    api.loadNotebook("CASE-A");
    p.requests[last(p)].answer([{ id: "n1", type: "note", text: "x" }]);
    await drainAll();
    api.nbStartEdit("n1");
    p.el("nbText").value = "edited";
    onclick(p, "nbAddBtn");
    const old = last(p);
    p.switchCase("CASE-B", api);
    api.loadNotebook("CASE-B");
    const before = p.requests.length;
    p.requests[old].answer({ id: "n1" });
    await drainAll();
    expect(p.requests.slice(before).map((r) => r.url)).not.toContain("/cases/CASE-A/notebook");
  });
});

describe("comments, tags and correlation profile (#2933)", () => {
  it("comments: a post from before a cancel keeps the reopened thread's typed text", async () => {
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
    p.el("commentText").value = "first";
    api.postComment();
    const old = last(p);
    cancelAndReopen(p, api, () => api.loadComments("CASE-A"));
    api.openCommentModal("event", "e1");
    p.el("commentText").value = "typed after the reopen";
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("commentText").value).toBe("typed after the reopen");
    expect(p.el("commentMsg").textContent).not.toContain("OLD-REFUSAL");
  });

  function tags() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-tags.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      targetKey: (t: string, i: string) => `${t}:${i}`,
      tagColor: () => "#fff",
      SUGGESTED_TAGS: [],
      loadSuperTimeline: () => {},
    });
    return { p, api };
  }

  it("tags: a bulk add stops issuing requests after a cancel and says nothing", async () => {
    const { p, api } = tags();
    api.loadTags("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    api.setBulkTagTarget(["e1", "e2", "e3"], "event");
    api.addTag("suspicious");
    await drainAll();
    const first = last(p);
    cancelAndReopen(p, api, () => api.loadTags("CASE-A"));
    p.requests[first].answer({});
    await drainAll();
    expect(p.requests.filter((r) => r.init?.method === "POST")).toHaveLength(1);
    expect(p.el("tagMsg").textContent).not.toContain("adding");
  });

  it("correlation profile: Apply answering after a cancel paints no info and no status", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-correlation-profile.js", ESC, p.globals);
    api.loadCorrProfile("CASE-A");
    p.requests[last(p)].answer({ profileName: "moderate" });
    await drainAll();
    p.el("corrProfileSel").value = "strict";
    api.applyCorrProfile();
    const old = last(p);
    const reload = cancelAndReopen(p, api, () => api.loadCorrProfile("CASE-A"));
    p.requests[reload].answer({ profileName: "moderate" });
    await drainAll();
    p.requests[old].answer({ profileName: "strict" });
    await drainAll();
    expect(p.el("corrProfileInfo").textContent).toBe("±2 s window");
    expect(p.el("status").textContent).not.toContain("saved");
  });
});

describe("velociraptor monitors and external import (#2933)", () => {
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

  it("monitors: a Start answering after a cancel says nothing and frees no newer Start", async () => {
    const { p, api } = velo("dashboard-velo-monitors.js");
    api.loadVeloMonitors("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("veloMonArtifactManual").value = "Generic.Client.Stats";
    p.el("veloMonAllClients").checked = true;
    api.veloMonStart();
    const old = last(p);
    cancelAndReopen(p, api, () => api.loadVeloMonitors("CASE-A"));
    expect(p.el("veloMonStartBtn").disabled, "the cancel left Start disabled").toBe(false);
    api.veloMonStart();
    p.requests[old].answer({ error: "OLD-ERROR" }, false);
    await drainAll();
    expect(p.el("veloMonMsg").textContent).not.toContain("OLD-ERROR");
    expect(p.el("veloMonStartBtn").disabled).toBe(true);
  });

  it("external import: a cancel clears an already-shown prompt, and an old answer paints nothing", async () => {
    const { p, api } = velo("dashboard-velo-triage.js", { renderVeloJobs: () => {} });
    api.loadVeloHuntJobs("CASE-A");
    p.el("veloExtRef").value = "H.123";
    api.veloImportExternal();
    const old = last(p);
    p.el("veloExtMsg").innerHTML = "Hunt H.1 was already pulled into this case — Re-import";
    cancelAndReopen(p, api, () => api.loadVeloHuntJobs("CASE-A"));
    expect(p.el("veloExtMsg").innerHTML).not.toContain("already pulled");
    expect(p.el("veloExtGo").disabled).toBe(false);
    p.requests[old].answer({ error: "OLD-ERROR" }, false);
    await drainAll();
    expect(p.el("veloExtMsg").textContent).not.toContain("OLD-ERROR");
  });
});

describe("narrative and second opinion (#2933)", () => {
  function narrative() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-narrative.js", ESC, {
      ...p.globals,
      isSectionVisible: () => true,
      loadSectionsVis: () => ({}),
      narrativeViewHtml: (t: string) => t,
      renderSynthMeta: () => {},
    });
    return { p, api };
  }

  it("Generate: a switch frees both buttons, and A's narrative never lands in B's view", async () => {
    const { p, api } = narrative();
    api.loadSynthMeta("CASE-A");
    api.genNarrative();
    const old = last(p);
    expect(p.el("editNarrativeBtn").disabled).toBe(true);
    p.switchCase("CASE-B", api);
    api.loadSynthMeta("CASE-B");
    expect(p.el("genNarrativeBtn").disabled).toBe(false);
    expect(p.el("editNarrativeBtn").disabled).toBe(false);
    p.el("narrativeView").innerHTML = "B-NARRATIVE";
    p.requests[old].answer({ narrativeTimeline: "A-NARRATIVE" });
    await drainAll();
    expect(p.el("narrativeView").innerHTML).toBe("B-NARRATIVE");
  });

  it("Generate: a same-case reload mid-request still paints the narrative", async () => {
    const { p, api } = narrative();
    api.loadSynthMeta("CASE-A");
    api.genNarrative();
    const old = last(p);
    api.loadSynthMeta("CASE-A");
    p.requests[old].answer({ narrativeTimeline: "FRESH" });
    await drainAll();
    expect(p.el("narrativeView").innerHTML).toContain("FRESH");
  });

  it("second opinion: a run answering after a cancel writes no status and frees no newer run's button", async () => {
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
    cancelAndReopen(p, api, () => api.loadSecondOpinion("CASE-A"));
    expect(p.el("secondOpinion").disabled, "the cancel left the button disabled").toBe(false);
    api.runSecondOpinion();
    p.requests[old].answer({ error: "OLD-FAIL" });
    await drainAll();
    expect(p.el("status").textContent).not.toContain("OLD-FAIL");
    expect(p.el("secondOpinion").disabled).toBe(true);
  });
});

describe("after the code review (#2933)", () => {
  it("second opinion: a decision's follow-up state read from before a cancel does not render", async () => {
    const p = fakePage();
    const rendered: unknown[] = [];
    const api = loadDashboardModule<Api>("dashboard-second-opinion.js", ESC, {
      ...p.globals,
      render: (st: unknown) => rendered.push(st),
    });
    api.loadSecondOpinion("CASE-A");
    p.requests[last(p)].answer(null);
    await drainAll();
    api.applySecondOpinionDelta("CASE-A", "d1", true);
    p.requests[last(p)].answer({ deltas: [] });
    await drainAll();
    const stateRead = last(p);
    expect(p.requests[stateRead].url).toBe("/cases/CASE-A/state");
    cancelAndReopen(p, api, () => api.loadSecondOpinion("CASE-A"));
    p.requests[stateRead].answer({ caseId: "CASE-A" });
    await drainAll();
    expect(rendered).toEqual([]);
  });

  it("super-timeline: a cancel frees the starred-report button, and the old answer leaves a newer one busy", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-super-timeline.js", ESC, {
      ...p.globals,
      DfirStarred: { count: () => 1, has: () => false },
      presidioHoldText: (s: string) => s,
    });
    api.genStarredReport();
    const old = last(p);
    expect(p.el("stStarredReport").disabled).toBe(true);
    p.cancel(api);
    p.switchCase("CASE-A", api);
    api.loadSavedTimeframes("CASE-A"); // registers the reset hook on a real open
    p.cancel(api);
    expect(p.el("stStarredReport").disabled, "the cancel left the button busy").toBe(false);
    p.switchCase("CASE-A", api);
    api.genStarredReport();
    p.requests[old].answer({ error: "OLD" }, false);
    await drainAll();
    expect(p.el("stStarredReport").disabled).toBe(true);
  });
});
