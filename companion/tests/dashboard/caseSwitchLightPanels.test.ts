// #2904: the light case-open panels must never show the previous case's content after a switch —
// not while the new case's answer is on its way, not when that answer fails, and not when the old
// case's answer lands late. Each panel below runs the same four checks against its real module.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage, type Pending } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument } from "./serverSetsFakeDom.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown>;

interface Panel {
  name: string;
  file: string;
  preload?: string[];
  extra?: Record<string, unknown>;
  loader: string;
  /** Which request is this panel's (a loader may issue more than one). */
  endpoint: string;
  answerA: unknown;
  answerB: unknown;
  /** Is the given marker on screen in this panel? */
  shows(p: Page, api: Api, marker: "AAA" | "BBB"): boolean;
}

// The page's shared helper scripts (the loaded panels call them at render time).
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
const targetKey = (t: string, i: string) => `${t}:${i}`;

const PANELS: Panel[] = [
  {
    name: "false positives",
    file: "dashboard-exposure-fp.js",
    preload: ESC,
    // The two page-level `let`s the module writes and reads (dashboard.html declares them).
    extra: { render: () => {}, fpMarkers: [], fpReasonFilter: "" },
    loader: "loadFalsePositives",
    endpoint: "/false-positive",
    answerA: [{ id: "m1", kind: "event", ref: "AAA", markedAt: "2020-01-01T00:00:00Z" }],
    answerB: [{ id: "m2", kind: "event", ref: "BBB", markedAt: "2020-01-01T00:00:00Z" }],
    shows: (p, _a, m) => p.el("false-positive").innerHTML.includes(m),
  },
  {
    name: "learned patterns",
    file: "dashboard-exposure-fp.js",
    preload: ESC,
    extra: { render: () => {}, fpMarkers: [], fpReasonFilter: "" }, // the cancel reset clears fpMarkers too
    loader: "loadLearnedPatterns",
    endpoint: "/learned-patterns",
    answerA: [{ signature: "AAA", reason: "other", count: 2 }],
    answerB: [{ signature: "BBB", reason: "other", count: 2 }],
    shows: (p, _a, m) => p.el("learnedPatterns").innerHTML.includes(m),
  },
  {
    name: "source trust",
    file: "dashboard-exposure-fp.js",
    preload: ESC,
    extra: { render: () => {}, fpMarkers: [], fpReasonFilter: "" }, // the cancel reset clears fpMarkers too
    loader: "loadSourceTrust",
    endpoint: "/source-trust",
    answerA: { defaults: { AAA: 0.5 }, overrides: {} },
    answerB: { defaults: { BBB: 0.5 }, overrides: {} },
    shows: (p, _a, m) => p.el("sourceTrustList").innerHTML.includes(m),
  },
  {
    name: "second opinion",
    file: "dashboard-second-opinion.js",
    preload: ESC,
    loader: "loadSecondOpinion",
    endpoint: "/second-opinion",
    answerA: { generatedAt: "2020-01-01T00:00:00Z", modelA: "AAA", modelB: "m", deltas: [] },
    answerB: { generatedAt: "2020-01-01T00:00:00Z", modelA: "BBB", modelB: "m", deltas: [] },
    shows: (p, _a, m) => p.el("secondOpinionPanel").innerHTML.includes(m),
  },
  {
    name: "report details",
    file: "dashboard-report-meta.js",
    preload: ESC,
    loader: "loadReportMeta",
    endpoint: "/report-meta",
    answerA: { companyName: "AAA" },
    answerB: { companyName: "BBB" },
    shows: (p, _a, m) => p.el("rm-companyName").value === m,
  },
  {
    name: "Presidio pending values",
    file: "dashboard-presidio.js",
    preload: ESC,
    loader: "loadPresidioPending",
    endpoint: "/presidio-pending",
    answerA: { pending: [{ value: "AAA", category: "PERSON" }] },
    answerB: { pending: [{ value: "BBB", category: "PERSON" }] },
    shows: (p, _a, m) => p.el("presidioPending").innerHTML.includes(m),
  },
  {
    name: "Velociraptor hunt jobs",
    file: "dashboard-velo-triage.js",
    preload: [...ESC, "dashboard-velo-case.js"],
    // Sibling Velociraptor modules the job card asks for its detail lines.
    extra: {
      veloCancelledDetail: () => "",
      veloCanCollect: () => false,
      veloCoverageHtml: () => "",
      veloCollectingDetail: () => "",
      veloCancelHuntBtnHtml: () => "",
    },
    loader: "loadVeloHuntJobs",
    endpoint: "/hunt-jobs",
    answerA: [{ huntId: "h1", status: "error", error: "AAA", artifacts: [] }],
    answerB: [{ huntId: "h2", status: "error", error: "BBB", artifacts: [] }],
    shows: (p, _a, m) => p.el("veloJobCard").innerHTML.includes(m),
  },
  {
    name: "Velociraptor live monitors",
    file: "dashboard-velo-monitors.js",
    preload: [...ESC, "dashboard-velo-case.js"],
    extra: { veloEnabled: false },
    loader: "loadVeloMonitors",
    endpoint: "/monitors",
    answerA: [{ id: "m1", artifact: "AAA", status: "active", clientId: "C.1" }],
    answerB: [{ id: "m2", artifact: "BBB", status: "active", clientId: "C.2" }],
    shows: (p, _a, m) => p.el("veloMonitorList").innerHTML.includes(m),
  },
  {
    name: "hunting profile",
    file: "dashboard-hunt-profile.js",
    preload: ESC,
    loader: "loadHuntProfile",
    endpoint: "/hunt-outcomes",
    answerA: {
      hunts: [{ status: "collected", foundEvidence: true, resultSummary: "AAA" }],
      total: 1,
      hit: 1,
      missed: 0,
      pending: 0,
    },
    answerB: {
      hunts: [{ status: "collected", foundEvidence: true, resultSummary: "BBB" }],
      total: 1,
      hit: 1,
      missed: 0,
      pending: 0,
    },
    shows: (p, _a, m) => p.el("huntProfile").innerHTML.includes(m),
  },
  {
    name: "import changes banner",
    file: "dashboard-import-changes.js",
    preload: ESC,
    loader: "loadImportMeta",
    endpoint: "/import-meta",
    answerA: { lastImportedAt: "2020-01-01T00:00:00Z", addedCount: 7, lastDiff: { added: [], removed: [] } },
    answerB: { lastImportedAt: null },
    shows: (p, _a, m) => (m === "AAA" ? p.el("importMeta").style.display === "block" : false),
  },
  {
    name: "raw-file drop banner",
    file: "dashboard-import-changes.js",
    preload: ESC,
    loader: "loadDropStatus",
    endpoint: "/drop-status",
    answerA: { status: { pendingRawInputs: [{ relpath: "AAA.evtx" }] } },
    answerB: { status: { pendingRawInputs: [{ relpath: "BBB.evtx" }] } },
    shows: (p, _a, m) => p.el("dropStatus").innerHTML.includes(m),
  },
  {
    name: "held hunt-results banner",
    file: "dashboard-import-changes.js",
    preload: ESC,
    loader: "loadDropStatus",
    endpoint: "/drop/held",
    answerA: { files: [{ rel: "drop/_held/AAA.csv", size: 1 }], limits: {} },
    answerB: { files: [{ rel: "drop/_held/BBB.csv", size: 1 }], limits: {} },
    shows: (p, _a, m) => p.el("dropHeld").innerHTML.includes(m),
  },
  {
    name: "synthesis what-changed banner",
    file: "dashboard-narrative.js",
    preload: ESC,
    loader: "loadSynthMeta",
    endpoint: "/synth-meta",
    answerA: {
      lastSynthesizedAt: "2020-01-01T00:00:00Z",
      lastDiff: { added: ["AAA"], removed: [], severityChanged: [] },
    },
    answerB: {
      lastSynthesizedAt: "2020-01-01T00:00:00Z",
      lastDiff: { added: ["BBB"], removed: [], severityChanged: [] },
    },
    shows: (p, _a, m) => p.el("synthMeta").innerHTML.includes(m),
  },
  {
    name: "comment chips",
    file: "dashboard-comments.js",
    preload: ESC,
    extra: { targetKey, ICON_COMMENT: "", refreshSuperRows: () => {} },
    loader: "loadComments",
    endpoint: "/comments",
    answerA: [{ id: "c1", targetType: "event", targetId: "AAA", text: "x" }],
    answerB: [{ id: "c2", targetType: "event", targetId: "BBB", text: "x" }],
    shows: (_p, a, m) => String(a.commentChip("event", m)).includes(" has"),
  },
  {
    name: "tag pills",
    file: "dashboard-tags.js",
    preload: ESC,
    extra: { targetKey, render: () => {}, deriveStarred: () => {}, migrateLocalStars: () => {} },
    loader: "loadTags",
    endpoint: "/tags",
    answerA: [{ id: "t1", targetType: "event", targetId: "e1", label: "AAA" }],
    answerB: [{ id: "t2", targetType: "event", targetId: "e1", label: "BBB" }],
    shows: (_p, a, m) => String(a.tagPills("event", "e1")).includes(m),
  },
  {
    name: "saved timeframes",
    file: "dashboard-super-timeline.js",
    preload: ESC,
    loader: "loadSavedTimeframes",
    endpoint: "/dwell-windows",
    answerA: [{ id: "w1", label: "AAA" }],
    answerB: [{ id: "w2", label: "BBB" }],
    shows: (p, _a, m) => p.el("stTimeframe").innerHTML.includes(m),
  },
  {
    name: "correlation profile",
    file: "dashboard-correlation-profile.js",
    preload: ESC,
    loader: "loadCorrProfile",
    endpoint: "/correlation-profile",
    answerA: { profileName: "aggressive", windowSeconds: 300 },
    answerB: { profileName: "strict", windowSeconds: 0 },
    shows: (p, _a, m) => p.el("corrProfileSel").value === (m === "AAA" ? "aggressive" : "strict"),
  },
  {
    name: "import undo tooltip",
    file: "dashboard-import-undo.js",
    preload: ESC,
    loader: "loadUndoStack",
    endpoint: "/undo-stack",
    answerA: { canUndo: true, nextUndo: { label: "AAA", events: 1, iocs: 0, findings: 0 } },
    answerB: { canUndo: true, nextUndo: { label: "BBB", events: 1, iocs: 0, findings: 0 } },
    shows: (p, _a, m) =>
      p.el("importUndoBtn").style.display !== "none" && (p.el("importUndoBtn").dataset.tip ?? "").includes(m),
  },
  {
    name: "AI status pill",
    file: "dashboard-ai-status.js",
    preload: ESC,
    extra: {
      setAi: (kind: string, text: string) => {
        throw new Error(`setAi is the page's — replaced per test (${kind} ${text})`);
      },
    },
    loader: "refreshAiState",
    endpoint: "/ai-state",
    answerA: { state: "error", detail: "AAA" },
    answerB: { state: "error", detail: "BBB" },
    shows: (p, _a, m) => p.el("aiStatus").textContent.includes(m),
  },
  {
    name: "chain of custody",
    file: "dashboard-custody.js",
    preload: ESC,
    loader: "loadCustody",
    endpoint: "/custody",
    answerA: {
      records: [{ artifactPath: "AAA.png", event: "stored", at: "2020-01-01T00:00:00Z", sha256: "x" }],
    },
    answerB: {
      records: [{ artifactPath: "BBB.png", event: "stored", at: "2020-01-01T00:00:00Z", sha256: "x" }],
    },
    shows: (p, _a, m) => p.el("custodyPanel").innerHTML.includes(m),
  },
  {
    name: "notebook AI toggle",
    file: "dashboard-notebook.js",
    preload: ESC,
    loader: "loadNbAiToggle",
    endpoint: "/ai-control",
    answerA: { includeNotebook: true },
    answerB: { includeNotebook: false },
    shows: (p, _a, m) => p.el("nbAiToggle").checked === (m === "AAA"),
  },
];

function open(panel: Panel) {
  const p = fakePage();
  const api = loadDashboardModule<Api>(panel.file, panel.preload ?? [], { ...p.globals, ...panel.extra });
  if (panel.name === "AI status pill") {
    // The page's pill writer (js/dashboard-presidio.js) — the module under test only calls it.
    api.setAi = (kind: unknown, text: unknown) => {
      const el = p.el("aiStatus");
      el.className = `ai-${String(kind)}`;
      el.textContent = `AI: ${String(text)}`;
    };
  }
  const load = (caseId: string) => void api[panel.loader](caseId);
  const req = (caseId: string): Pending => {
    const found = p.requests.filter((r) => r.url.includes(`/${caseId}/`) && r.url.includes(panel.endpoint));
    if (!found.length) throw new Error(`no ${panel.endpoint} request for ${caseId}: ${p.urls().join(", ")}`);
    return found[found.length - 1];
  };
  const toB = () => p.switchCase("CASE-B", api);
  return { p, api, load, req, toB, shows: (m: "AAA" | "BBB") => panel.shows(p, api, m) };
}

async function shownForA(t: ReturnType<typeof open>) {
  t.load("CASE-A");
  t.req("CASE-A").answer(PANEL_ANSWERS.get(t)!.a);
  await drainAll();
}
const PANEL_ANSWERS = new WeakMap<object, { a: unknown; b: unknown }>();

describe.each(PANELS)("$name: case A's content never shows on case B (#2904)", (panel) => {
  const start = () => {
    const t = open(panel);
    PANEL_ANSWERS.set(t, { a: panel.answerA, b: panel.answerB });
    return t;
  };

  it("A's content is on screen before the switch (the check below can fail)", async () => {
    const t = start();
    await shownForA(t);
    expect(t.shows("AAA")).toBe(true);
  });

  it("A's content goes the moment B's load starts", async () => {
    const t = start();
    await shownForA(t);
    t.toB();
    t.load("CASE-B");
    expect(t.shows("AAA")).toBe(false);
  });

  it("B's read failing (network or error answer) does not bring A's content back", async () => {
    for (const how of ["fail", "error"] as const) {
      const t = start();
      await shownForA(t);
      t.toB();
      t.load("CASE-B");
      if (how === "fail") t.req("CASE-B").fail();
      else t.req("CASE-B").answer({ error: "boom" }, false);
      await drainAll();
      expect(t.shows("AAA"), how).toBe(false);
    }
  });

  it("A's answer landing after B's does not paint over B", async () => {
    const t = start();
    t.load("CASE-A");
    t.toB();
    t.load("CASE-B");
    if (t.p.requests.some((r) => r.url.includes("/CASE-B/"))) {
      t.req("CASE-B").answer(panel.answerB);
      t.req("CASE-A").answer(panel.answerA);
    } else {
      // Tags run one fetch at a time (#2059): B's waits behind A's, which must then paint nothing.
      t.req("CASE-A").answer(panel.answerA);
      await drainAll();
      expect(t.shows("AAA")).toBe(false);
      t.req("CASE-B").answer(panel.answerB);
    }
    await drainAll();
    expect(t.shows("AAA")).toBe(false);
  });

  it("a late call for case A neither fetches nor clears B", async () => {
    const t = start();
    t.toB();
    t.load("CASE-B");
    t.req("CASE-B").answer(panel.answerB);
    await drainAll();
    const before = t.p.requests.length;
    const shownB = t.shows("BBB");
    t.load("CASE-A");
    expect(t.p.requests.length).toBe(before);
    expect(t.shows("BBB")).toBe(shownB);
  });
});

// #2915: more case-open panels that keep a case's content (#2900 item 5 and the notebook). Their
// switch behaviour is covered in caseSwitchStalePanels; here they join the cancel checks below.
const MORE_PANELS: Panel[] = [
  {
    name: "activity log",
    file: "dashboard-activity-log.js",
    preload: ESC,
    loader: "loadActivityLog",
    endpoint: "/activity-log",
    answerA: [{ ts: "2026-01-01T00:00:00Z", category: "import", actor: "x", detail: "AAA" }],
    answerB: [{ ts: "2026-01-01T00:00:00Z", category: "import", actor: "x", detail: "BBB" }],
    shows: (p, _a, m) => p.el("activityLogPanel").innerHTML.includes(m),
  },
  {
    name: "pinned findings",
    file: "dashboard-pinned-findings.js",
    preload: ESC,
    extra: { render: () => {}, ICON_PIN: "<svg/>" },
    loader: "loadPins",
    endpoint: "/pinned-findings",
    answerA: { pins: [{ findingId: "f1" }], limit: 5 },
    answerB: { pins: [], limit: 5 },
    shows: (_p, a, m) => m === "AAA" && String(a.pinBtn("f1")).includes(" pinned"),
  },
  {
    name: "finding workflow",
    file: "dashboard-finding-workflow.js",
    preload: ESC,
    extra: { render: () => {}, ICON_FLOW: "<svg/>", ICON_USER: "<svg/>" },
    loader: "loadFindingWorkflow",
    endpoint: "/finding-workflow",
    answerA: [{ findingId: "f1", assignee: "AAA", status: "in_progress" }],
    answerB: [{ findingId: "f1", assignee: "BBB", status: "in_progress" }],
    shows: (_p, a, m) => String(a.findingWorkflowControls("f1")).includes(m),
  },
  {
    name: "playbook",
    file: "dashboard-playbook.js",
    preload: ESC,
    extra: { VHS_SEV_RANK: {} },
    loader: "loadPlaybook",
    endpoint: "/playbook",
    answerA: { tasks: [{ id: "t1", title: "AAA", status: "todo" }], stats: null, control: null },
    answerB: { tasks: [{ id: "t1", title: "BBB", status: "todo" }], stats: null, control: null },
    shows: (p, _a, m) => p.el("pbList").innerHTML.includes(m),
  },
  {
    name: "notebook entries",
    file: "dashboard-notebook.js",
    preload: ESC,
    loader: "loadNotebook",
    endpoint: "/notebook",
    answerA: [{ id: "n1", type: "note", text: "AAA" }],
    answerB: [{ id: "n2", type: "note", text: "BBB" }],
    shows: (p, _a, m) => p.el("nbList").innerHTML.includes(m),
  },
];

// #2915: a cancelled (or failed) case load runs DfirPanelDefer.reset(null) — the hook the heavy panels
// use for "Not loaded — the case load was stopped". The light panels listen to it too: the cancelled
// case's content goes, and the next open (the same case included) loads it again. The aborted
// request never settles (runPanelLoaders keeps it pending), so nothing may wait behind it.
describe.each([...PANELS, ...MORE_PANELS])(
  "$name: a cancelled load leaves none of the cancelled case's content (#2915)",
  (panel) => {
    const start = () => {
      const t = open(panel);
      PANEL_ANSWERS.set(t, { a: panel.answerA, b: panel.answerB });
      return t;
    };

    it("A's content goes when the load is cancelled", async () => {
      const t = start();
      await shownForA(t);
      expect(t.p.resetListenerCount()).toBeGreaterThan(0);
      t.p.cancel(t.api);
      expect(t.shows("AAA")).toBe(false);
    });

    it("reopening the same case after a cancel reads it again and shows it", async () => {
      const t = start();
      await shownForA(t);
      t.load("CASE-A"); // a reload on its way when the analyst cancels: it never settles
      t.p.cancel(t.api);
      t.p.switchCase("CASE-A", t.api);
      const before = t.p.requests.length;
      t.load("CASE-A");
      expect(t.p.requests.length, "the reopen sent no request").toBeGreaterThan(before);
      t.req("CASE-A").answer(panel.answerA);
      await drainAll();
      expect(t.shows("AAA")).toBe(true);
    });
  },
);

describe("client baseline: an older render never appends into a newer one (#2904)", () => {
  type BaselineApi = { loadClientBaseline(caseId: string): Promise<void> };
  // The module builds real nodes, so it runs on the richer fake document its own suite uses.
  function baseline() {
    const p = fakePage();
    const doc = new FakeDocument();
    const { caseId, clientBaselinePanel } = doc.add("div", "caseId", "clientBaselinePanel");
    caseId.value = "CASE-A";
    const api = loadDashboardModule<BaselineApi>("dashboard-client-baseline.js", [], {
      document: doc,
      fetch: p.globals.fetch,
    });
    return { p, api, caseId, panel: clientBaselinePanel };
  }
  async function answerUpTo(p: Page, caseId: string, from: number) {
    p.requests[from].answer({ hunt: { id: caseId } });
    await drainAll();
    p.requests[from + 1].answer({ client: null });
    await drainAll();
  }

  it("a render that resumes after a newer one finished adds nothing", async () => {
    const { p, api, panel } = baseline();
    void api.loadClientBaseline("CASE-A");
    await answerUpTo(p, "CASE-A", 0); // the first render now waits on the client list (request 2)
    void api.loadClientBaseline("CASE-A");
    await answerUpTo(p, "CASE-A", 3);
    p.requests[5].answer([]);
    await drainAll();
    const settled = panel.children.length;
    expect(settled).toBeGreaterThan(0);
    p.requests[2].answer([]);
    await drainAll();
    expect(panel.children).toHaveLength(settled);
  });

  it("A's panel is blanked at the switch and A's late render adds nothing to B", async () => {
    const { p, api, caseId, panel } = baseline();
    void api.loadClientBaseline("CASE-A");
    await answerUpTo(p, "CASE-A", 0);
    caseId.value = "CASE-B";
    void api.loadClientBaseline("CASE-B");
    expect(panel.children).toHaveLength(0);
    p.requests[3].fail();
    p.requests[2].answer([]);
    await drainAll();
    expect(panel.children.map((c) => c.textContent)).toEqual([
      "Client baselines apply to threat-hunt cases only.",
    ]);
  });
});

describe("an open editor for case A closes at the switch (#2904)", () => {
  it("comments: an open thread closes, so its post cannot land on case B", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-comments.js", ESC, {
      ...p.globals,
      targetKey,
      ICON_COMMENT: "",
      refreshSuperRows: () => {},
    });
    api.loadComments("CASE-A");
    p.requests[0].answer([]);
    await drainAll();
    api.openCommentModal("event", "e1");
    p.el("commentText").value = "draft for A";
    p.switchCase("CASE-B");
    api.loadComments("CASE-B");
    expect(p.el("commentText").value).toBe("");
    api.postComment();
    expect(p.urls().filter((u) => u.endsWith("/comments") && u.includes("CASE-B"))).toHaveLength(1);
  });

  it("tags: an open editor closes", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-tags.js", ESC, {
      ...p.globals,
      targetKey,
      render: () => {},
    });
    api.loadTags("CASE-A");
    p.requests[0].answer([]);
    await drainAll();
    api.openTagModal("event", "e1");
    p.el("tagInput").value = "draft";
    p.switchCase("CASE-B");
    api.loadTags("CASE-B");
    expect(p.el("tagInput").value).toBe("");
  });
});

describe("report details: no stale answer fills the form or is saved (#2904)", () => {
  function rm() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-report-meta.js", ESC, p.globals);
    return { p, api };
  }

  it("A -> B -> A: the first A answer, landing last, does not fill the form", async () => {
    const { p, api } = rm();
    void api.loadReportMeta("CASE-A");
    p.switchCase("CASE-B");
    void api.loadReportMeta("CASE-B");
    p.switchCase("CASE-A");
    void api.loadReportMeta("CASE-A");
    p.requests[2].answer({ companyName: "A-new", updatedAt: "2" });
    await drainAll();
    p.requests[1].answer({ companyName: "B" });
    p.requests[0].answer({ companyName: "A-old", updatedAt: "1" });
    await drainAll();
    expect(p.el("rm-companyName").value).toBe("A-new");
  });

  it("a save whose pre-load lands after the switch sends nothing", async () => {
    const { p, api } = rm();
    const saving = api.saveReportMeta({}) as Promise<void>;
    p.switchCase("CASE-B");
    p.requests[0].answer({ companyName: "A" });
    await saving;
    expect(p.requests.filter((r) => r.init?.method === "PUT")).toHaveLength(0);
    expect(p.el("rm-companyName").value).toBe("");
  });
});

describe("Codex review of #2904", () => {
  it("Presidio: a hold answer for case A after the switch does not fill B's panel", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-presidio.js", ESC, p.globals);
    p.switchCase("CASE-B", api);
    api.loadPresidioPending("CASE-B");
    p.requests[0].answer({ pending: [] });
    await drainAll();
    api.setPresidioPending([{ value: "AAA", category: "PERSON" }], "CASE-A");
    expect(p.el("presidioPending").innerHTML).not.toContain("AAA");
    api.setPresidioPending([{ value: "BBB", category: "PERSON" }], "CASE-B");
    expect(p.el("presidioPending").innerHTML).toContain("BBB");
  });

  it("2nd opinion: after a cancelled load, its answer and a queued reload are dropped", async () => {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-second-opinion.js", ESC, p.globals);
    api.loadSecondOpinion("CASE-A");
    p.switchCase("");
    p.requests[0].answer({ generatedAt: "2020-01-01T00:00:00Z", modelA: "AAA", modelB: "m", deltas: [] });
    await drainAll();
    expect(p.el("secondOpinionPanel").innerHTML).not.toContain("AAA");
    api.loadSecondOpinion("CASE-A");
    expect(p.requests).toHaveLength(1);
  });
});
