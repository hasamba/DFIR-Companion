// #2940: A -> B -> A where B never runs this panel's loader (a hidden deferred section, a fan-out
// aborted by a quick switch back, a failed load). Each module's action generation used to move only
// in its loader, so the owner stayed A and an answer from the first visit to A still painted. The
// reset hook now retires it at the switch itself — and a reopen of the same case still paints.
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
const click = { stopPropagation: () => {} };

/** A -> B -> A: two full case opens (reset listeners run); B never runs this panel's loader. */
function awayUnloaded(p: Page, api: object) {
  p.open("CASE-B", api);
  p.open("CASE-A", api);
}

describe("custody Verify (#2940)", () => {
  const records = {
    records: [{ artifactPath: "AAA.png", event: "stored", at: "2020-01-01T00:00:00Z", sha256: "x" }],
  };
  async function custody() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-custody.js", ESC, p.globals);
    api.initCustodyButtons();
    api.loadCustody("CASE-A");
    p.requests[0].answer(records);
    await drainAll();
    p.el("custodyVerifyBtn").fire("click");
    return { p, api, verify: last(p) };
  }

  it("B opening frees Verify; the old verify then paints nothing on A", async () => {
    const { p, api, verify } = await custody();
    expect(p.el("custodyVerifyBtn").disabled).toBe(true);
    p.open("CASE-B", api);
    expect(p.el("custodyVerifyBtn").disabled, "B's open left Verify disabled").toBe(false);
    expect(p.el("custodyVerifyMsg").textContent).toBe("");
    p.open("CASE-A", api);
    p.requests[verify].answer({ ok: true, mismatches: [], chainBreaks: [] });
    await drainAll();
    expect(p.el("custodyVerifyMsg").textContent).not.toContain("verified");
  });

  it("a reopen of the same case keeps the verify", async () => {
    const { p, api, verify } = await custody();
    p.open("CASE-A", api);
    api.loadCustody("CASE-A");
    p.requests[verify].answer({ ok: true, mismatches: [], chainBreaks: [] });
    await drainAll();
    expect(p.el("custodyVerifyMsg").textContent).toBe("All artifacts verified, custody log intact.");
  });
});

describe("pinned findings (#2940)", () => {
  async function pins() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-pinned-findings.js", ESC, {
      ...p.globals,
      render: () => {},
      investigatorName: () => "analyst",
      ICON_PIN: "<svg/>",
    });
    api.loadPins("CASE-A");
    p.requests[0].answer({ pins: [], limit: 5 });
    await drainAll();
    return { p, api };
  }
  const pinned = { pins: [{ findingId: "f1" }], limit: 5 };

  it("a pin answer from the first visit to A does not repaint after A -> B -> A", async () => {
    const { p, api } = await pins();
    api.togglePin("f1");
    const old = last(p);
    awayUnloaded(p, api);
    p.requests[old].answer(pinned);
    await drainAll();
    expect(String(api.pinBtn("f1"))).not.toContain(" pinned");
  });

  it("a reopen of A, and a pin made under B then B reopened, still paint", async () => {
    const { p, api } = await pins();
    api.togglePin("f1");
    p.open("CASE-A", api);
    p.requests[last(p)].answer(pinned);
    await drainAll();
    expect(String(api.pinBtn("f1"))).toContain(" pinned");
    p.open("CASE-B", api); // B's pins never load
    api.togglePin("f2");
    const underB = last(p);
    p.open("CASE-B", api);
    p.requests[underB].answer({ pins: [{ findingId: "f2" }], limit: 5 });
    await drainAll();
    expect(String(api.pinBtn("f2"))).toContain(" pinned");
  });
});

describe("finding workflow (#2940)", () => {
  async function workflow() {
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
    return { p, api, old: last(p) };
  }
  const record = { record: { findingId: "f1", assignee: "OLDER", status: "in_progress" } };

  it("a PATCH answer from the first visit to A does not land after A -> B -> A", async () => {
    const { p, api, old } = await workflow();
    awayUnloaded(p, api);
    p.requests[old].answer(record);
    await drainAll();
    expect(String(api.findingWorkflowControls("f1"))).not.toContain("OLDER");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await workflow();
    p.open("CASE-A", api);
    p.requests[old].answer(record);
    await drainAll();
    expect(String(api.findingWorkflowControls("f1"))).toContain("OLDER");
  });
});

describe("Presidio decisions (#2940)", () => {
  async function presidio() {
    const p = fakePage();
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
      refreshAiState: () => {},
      loadAnonEntities: () => Promise.resolve(),
      renderAutoEntities: () => {},
    });
    api.loadPresidioPending("CASE-A");
    p.requests[last(p)].answer({ pending: [{ value: "AAA", category: "PERSON" }] });
    await drainAll();
    clicks["[data-presidio-approve]"]();
    return { p, api, old: last(p) };
  }
  const answer = { pending: [{ value: "OLD-ROW", category: "PERSON" }] };

  it("an approve answer from the first visit to A paints nothing after A -> B -> A", async () => {
    const { p, api, old } = await presidio();
    awayUnloaded(p, api);
    p.requests[old].answer(answer);
    await drainAll();
    expect(p.el("presidioPending").innerHTML).not.toContain("OLD-ROW");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await presidio();
    p.open("CASE-A", api);
    p.requests[old].answer(answer);
    await drainAll();
    expect(p.el("presidioPending").innerHTML).toContain("OLD-ROW");
  });
});

describe("playbook hunt suggestions (#2940)", () => {
  async function playbook() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-playbook.js", ESC, { ...p.globals, VHS_SEV_RANK: {} });
    api.loadPlaybook("CASE-A");
    p.requests[last(p)].answer({ tasks: [], stats: null, control: null });
    await drainAll();
    api.doSuggestPlaybookHunts();
    return { p, api, old: last(p) };
  }
  const answer = { suggestions: [{ taskId: "t", title: "OLD-HUNT", vql: "x" }], generated: 1 };

  it("B opening frees Suggest; the old answer then paints nothing on A", async () => {
    const { p, api, old } = await playbook();
    p.open("CASE-B", api);
    expect(p.el("pbHuntBtn").disabled, "B's open left Suggest disabled").toBe(false);
    p.open("CASE-A", api);
    p.requests[old].answer(answer);
    await drainAll();
    expect(p.el("pbHuntMsg").textContent).not.toContain("1 new");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await playbook();
    p.open("CASE-A", api);
    p.requests[old].answer(answer);
    await drainAll();
    expect(p.el("pbHuntMsg").textContent).toContain("1 new");
  });
});

describe("report details Save (#2940)", () => {
  async function saved() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-report-meta.js", ESC, p.globals);
    void api.loadReportMeta("CASE-A");
    p.requests[0].answer({ companyName: "FIRST" });
    await drainAll();
    void api.saveReportMeta({ "rm-companyName": "SAVED" });
    return { p, api, put: last(p) };
  }

  it("a Save answering after A -> B -> A says nothing", async () => {
    const { p, api, put } = await saved();
    awayUnloaded(p, api);
    p.requests[put].answer({ companyName: "SAVED" });
    await drainAll();
    expect(p.el("rmStatus").textContent).not.toContain("saved");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, put } = await saved();
    p.open("CASE-A", api);
    p.requests[put].answer({ companyName: "SAVED" });
    await drainAll();
    expect(p.el("rmStatus").textContent).toContain("saved");
  });
});

describe("correlation profile Apply (#2940)", () => {
  async function applied() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-correlation-profile.js", ESC, p.globals);
    api.loadCorrProfile("CASE-A");
    p.requests[last(p)].answer({ profileName: "moderate" });
    await drainAll();
    p.el("corrProfileSel").value = "strict";
    api.applyCorrProfile();
    return { p, api, old: last(p) };
  }

  it("an answer after A -> B -> A writes no status", async () => {
    const { p, api, old } = await applied();
    awayUnloaded(p, api);
    p.requests[old].answer({ profileName: "strict" });
    await drainAll();
    expect(p.el("status").textContent).not.toContain("saved");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await applied();
    p.open("CASE-A", api);
    p.requests[old].answer({ profileName: "strict" });
    await drainAll();
    expect(p.el("status").textContent).toContain("saved");
  });
});

describe("notebook and comments (#2940)", () => {
  async function notebook() {
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
    p.el("nbText").value = "first";
    (p.el("nbAddBtn") as unknown as { onclick: () => void }).onclick();
    return { p, api, old: last(p) };
  }

  it("notebook: a refused add from the first visit to A says nothing after A -> B -> A", async () => {
    const { p, api, old } = await notebook();
    awayUnloaded(p, api);
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("nbMsg").textContent).not.toContain("OLD-REFUSAL");
  });

  it("notebook: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await notebook();
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("nbMsg").textContent).toContain("OLD-REFUSAL");
  });

  async function comments() {
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
    return { p, api, old: last(p) };
  }

  it("comments: a refused post from the first visit to A says nothing after A -> B -> A", async () => {
    const { p, api, old } = await comments();
    awayUnloaded(p, api);
    api.openCommentModal("event", "e1");
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("commentMsg").textContent).not.toContain("OLD-REFUSAL");
  });

  it("comments: a reopen of the same case keeps it", async () => {
    const { p, api, old } = await comments();
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-REFUSAL" }, false, 423);
    await drainAll();
    expect(p.el("commentMsg").textContent).toContain("OLD-REFUSAL");
  });
});

describe("tags bulk add (#2940)", () => {
  async function bulk() {
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
    api.setBulkTagTarget(["e1", "e2", "e3"], "event");
    api.addTag("suspicious");
    await drainAll();
    return { p, api, first: last(p) };
  }
  const posts = (p: Page) => p.requests.filter((r) => r.init?.method === "POST").length;

  it("stops issuing requests after A -> B -> A", async () => {
    const { p, api, first } = await bulk();
    awayUnloaded(p, api);
    p.requests[first].answer({});
    await drainAll();
    expect(posts(p)).toBe(1);
  });

  it("goes on across a reopen of the same case", async () => {
    const { p, api, first } = await bulk();
    p.open("CASE-A", api);
    p.requests[first].answer({});
    await drainAll();
    expect(posts(p)).toBe(2);
  });
});

describe("AI status Skip held screenshots (#2940)", () => {
  async function skipped() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-ai-status.js", ESC, {
      ...p.globals,
      setAi: () => {},
      paintIngest: () => {},
      hideImportProgress: () => {},
      loadPresidioPending: () => {},
      loadHostDuplicates: () => {},
      loadAnonToggle: () => {},
      resynthesize: () => {},
      ws: null,
    });
    void api.refreshAiState("CASE-A");
    p.requests[last(p)].answer({ state: "idle", screenshotHold: { count: 2, token: "tok" } });
    await drainAll();
    (p.el("heldSkipBtn") as unknown as { onclick: () => void }).onclick();
    return { p, api, old: last(p) };
  }

  it("an answer after A -> B -> A writes no status line", async () => {
    const { p, api, old } = await skipped();
    awayUnloaded(p, api);
    p.el("status").textContent = "connected (live)";
    p.requests[old].answer({ skipped: 2, remaining: 0 });
    await drainAll();
    expect(p.el("status").textContent).toBe("connected (live)");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await skipped();
    p.open("CASE-A", api);
    p.requests[old].answer({ skipped: 2, remaining: 0 });
    await drainAll();
    expect(p.el("status").textContent).toContain("skipped AI analysis of 2");
  });
});

describe("hypotheses Generate (#2940)", () => {
  async function generating() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-hypotheses.js", ESC, {
      ...p.globals,
      investigatorName: () => "analyst",
      render: () => {},
      loadSynthMeta: () => {},
    });
    api.initHypotheses();
    api.loadHypotheses("CASE-A");
    p.requests[last(p)].answer([]);
    await drainAll();
    p.el("hypGenerateBtn").fire("click", click);
    return { p, api, old: last(p) };
  }

  it("B opening frees Generate; the old failure then says nothing on A", async () => {
    const { p, api, old } = await generating();
    expect(p.el("hypGenerateBtn").disabled).toBe(true);
    p.open("CASE-B", api);
    expect(p.el("hypGenerateBtn").disabled, "B's open left Generate disabled").toBe(false);
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("hypGenMsg").textContent).not.toContain("failed");
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, old } = await generating();
    p.open("CASE-A", api);
    p.requests[old].answer({ error: "OLD-FAIL" }, false);
    await drainAll();
    expect(p.el("hypGenMsg").textContent).toContain("failed");
  });
});

describe("duplicate hosts (#2940)", () => {
  const pair = (host: string) => ({ canonical: `${host}.corp.test`, other: host, reason: "shortname-fqdn" });
  async function merging() {
    const p = fakePage();
    const kicked: string[] = [];
    const api = loadDashboardModule<Api>("dashboard-host-duplicates.js", ESC, {
      ...p.globals,
      applySectionsVis: () => {},
      SECTIONS_VIS_KEY: "dfir.sectionsVis",
      confirm: () => true,
      refreshAiState: (c: string) => kicked.push(c),
    });
    void api.loadHostDuplicates("CASE-A");
    p.requests[0].answer({ pending: [pair("ws-a")] });
    p.requests[1].answer({ dismissed: [] });
    await drainAll();
    const button = {
      hasAttribute: (n: string) => n === "data-hd-merge",
      getAttribute: (n: string) => (n === "data-hd-canonical" ? "ws-a.corp.test" : "ws-a"),
    };
    p.el("hostDuplicatesBody").fire("click", { target: { closest: () => button } });
    return { p, api, kicked, old: last(p) };
  }

  it("a merge answer from the first visit to A paints nothing after A -> B -> A", async () => {
    const { p, api, kicked, old } = await merging();
    awayUnloaded(p, api);
    p.requests[old].answer({ pending: [pair("ws-old")] });
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-old");
    expect(kicked).toEqual([]);
  });

  it("a reopen of the same case keeps it", async () => {
    const { p, api, kicked, old } = await merging();
    p.open("CASE-A", api);
    p.requests[old].answer({ pending: [pair("ws-old")] });
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-old");
    expect(kicked).toEqual(["CASE-A"]);
  });
});
