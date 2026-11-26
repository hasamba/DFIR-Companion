// #2900: after a case switch, the login graph, the asset graph and the duplicate-hosts panel must
// never show the previous case's data — not while the new case's answer is on its way, and not
// when an answer for the case the analyst left arrives late.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Pending {
  url: string;
  answer(body: unknown, ok?: boolean): void;
  fail(): void;
}

const drain = () => new Promise((r) => setTimeout(r, 0));
const drainAll = async () => {
  for (let i = 0; i < 4; i++) await drain();
};

interface FakeEl {
  id: string;
  value?: string;
  innerHTML: string;
  textContent: string;
  style: Record<string, string>;
  dataset: Record<string, string>;
  hidden?: boolean;
  addEventListener(): void;
  replaceChildren(): void;
  classList: { add(): void; remove(): void; toggle(): void };
}

// A page with stable elements, a #caseId that names the case on screen, and a fetch the test
// answers by hand, in the order it chooses.
function fakePage(caseId = "CASE-A") {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    let e = els.get(id);
    if (!e) {
      e = {
        id,
        innerHTML: "",
        textContent: "",
        style: {},
        dataset: {},
        addEventListener: () => {},
        replaceChildren: () => {},
        classList: { add: () => {}, remove: () => {}, toggle: () => {} },
      };
      // As in a browser, writing textContent replaces the markup.
      let text = "";
      Object.defineProperty(e, "textContent", {
        get: () => text,
        set: (v: string) => {
          text = v;
          e!.innerHTML = v;
        },
      });
      els.set(id, e);
    }
    return e;
  };
  el("caseId").value = caseId;
  const requests: Pending[] = [];
  const fetch = (url: string) =>
    new Promise((resolve, reject) => {
      requests.push({
        url,
        answer: (body, ok = true) => resolve({ ok, status: ok ? 200 : 500, json: async () => body }),
        fail: () => reject(new Error("offline")),
      });
    });
  const timers: (() => void)[] = [];
  const globals: Record<string, unknown> = {
    document: {
      getElementById: el,
      querySelectorAll: () => [],
      querySelector: () => null,
    },
    fetch,
    // Debounce timers are fired by the test; zero-delay ones run as usual.
    setTimeout: (fn: () => void, ms: number) => {
      if (ms > 0) {
        timers.push(fn);
        return timers.length;
      }
      return globalThis.setTimeout(fn, 0);
    },
    clearTimeout: () => {},
    localStorage: { getItem: () => null, setItem: () => {} },
    applySectionsVis: () => {},
    SECTIONS_VIS_KEY: "dfir.sectionsVis",
    DfirTimelineView: { timeQuery: () => "" },
    DfirState: { lastFt: () => null, lastState: () => null },
    // Icon strings dashboard.html's inline script defines for the finding-card buttons.
    ICON_PIN: "<svg/>",
    ICON_FLOW: "<svg/>",
    ICON_USER: "<svg/>",
  };
  return {
    el,
    requests,
    globals,
    urls: () => requests.map((r) => r.url),
    fireTimers: () => timers.splice(0).forEach((fn) => fn()),
    switchCase: (id: string) => {
      el("caseId").value = id;
    },
  };
}

describe("login graph: a reload for the case left never paints over the next one (#2900)", () => {
  interface LgApi {
    loadLoginGraph(caseId: string): void;
    scheduleLoginGraphReload(caseId: string): void;
  }
  const graph = (host: string) => ({
    nodes: [{ id: `host:${host}`, name: host, type: "host" }],
    edges: [],
    error: `stub-${host}`,
  });
  function lg(p: ReturnType<typeof fakePage>) {
    return loadDashboardModule<LgApi>("dashboard-login-graph.js", ["dashboard-escape.js"], p.globals);
  }

  it("a debounced reload armed for case A that fires after the switch requests nothing", () => {
    const p = fakePage();
    const api = lg(p);
    api.scheduleLoginGraphReload("CASE-A");
    p.switchCase("CASE-B");
    p.fireTimers();
    expect(p.urls()).toEqual([]);
  });

  it("a debounced reload for the case on screen still loads", () => {
    const p = fakePage();
    const api = lg(p);
    api.scheduleLoginGraphReload("CASE-A");
    p.fireTimers();
    expect(p.urls()).toEqual(["/cases/CASE-A/login-graph"]);
  });

  it("case A's answer landing after case B's painted does not repaint A", async () => {
    const p = fakePage();
    const api = lg(p);
    api.loadLoginGraph("CASE-A");
    p.switchCase("CASE-B");
    api.loadLoginGraph("CASE-B");
    p.requests[1].answer(graph("b-host"));
    await drainAll();
    expect(p.el("loginGraphStats").textContent).toContain("stub-b-host");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    expect(p.el("loginGraphStats").textContent).toContain("stub-b-host");
  });

  it("an answer for a case no longer on screen does not paint even with no newer load", async () => {
    const p = fakePage();
    const api = lg(p);
    api.loadLoginGraph("CASE-A");
    p.switchCase("");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    expect(p.el("loginGraphStats").textContent).not.toContain("a-host");
  });
});

describe("asset graph: the previous case's graph is not shown after a switch (#2900)", () => {
  interface AgApi {
    loadAssetGraph(caseId: string): void;
    loadAssetOverrides(caseId: string): void;
    hasAssetGraph(): boolean;
    assetGraphAssets(): { name: string }[];
    assetOverrideMerges(): Record<string, string>;
  }
  const graph = (name: string) => ({
    assets: [{ id: `host:${name}`, name, type: "host", compromised: true }],
    iocs: [],
    edges: [],
  });
  function ag(p: ReturnType<typeof fakePage>) {
    return loadDashboardModule<AgApi>("dashboard-asset-graph.js", ["dashboard-escape.js"], p.globals);
  }

  it("clears case A's graph and list the moment case B's load starts", async () => {
    const p = fakePage();
    const api = ag(p);
    api.loadAssetGraph("CASE-A");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    expect(p.el("assetList").innerHTML).toContain("a-host");
    p.switchCase("CASE-B");
    api.loadAssetGraph("CASE-B");
    expect(api.hasAssetGraph()).toBe(false);
    expect(p.el("assetGraph").innerHTML).toContain("Loading this case");
    expect(p.el("assetGraph").innerHTML).not.toContain("a-host");
    expect(p.el("assetList").innerHTML).not.toContain("a-host");
    p.requests[1].answer(graph("b-host"));
    await drainAll();
    expect(api.assetGraphAssets().map((a) => a.name)).toEqual(["b-host"]);
    expect(p.el("assetList").innerHTML).toContain("b-host");
  });

  it("a same-case reload (time filter, live push) keeps the graph until its answer", async () => {
    const p = fakePage();
    const api = ag(p);
    api.loadAssetGraph("CASE-A");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    api.loadAssetGraph("CASE-A");
    expect(api.hasAssetGraph()).toBe(true);
    expect(p.el("assetList").innerHTML).toContain("a-host");
  });

  it("an answer for a case no longer on screen is dropped", async () => {
    const p = fakePage();
    const api = ag(p);
    api.loadAssetGraph("CASE-A");
    p.switchCase("");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    expect(api.hasAssetGraph()).toBe(false);
  });

  it("a cancel after the switch (aborted load) does not leave 'Loading' in the graph", async () => {
    const p = fakePage();
    const listeners: ((caseId: string | null) => void)[] = [];
    p.globals.DfirPanelDefer = {
      stoppedText: "Not loaded — the case load was stopped. Open a case to load this panel.",
      onReset: (fn: (caseId: string | null) => void) => {
        if (!listeners.includes(fn)) listeners.push(fn);
      },
    };
    const api = ag(p);
    api.loadAssetGraph("CASE-A");
    p.requests[0].answer(graph("a-host"));
    await drainAll();
    p.switchCase("CASE-B");
    api.loadAssetGraph("CASE-B");
    // abandonCaseLoad: the fan-out is aborted — runPanelLoaders hands the loader a promise that
    // never settles, so nothing reaches the module's handlers — and the reloads are retired, which
    // resets the panel deferrals with no case.
    p.switchCase("");
    expect(listeners.length).toBe(1);
    listeners.forEach((fn) => fn(null));
    await drainAll();
    expect(p.el("assetGraph").innerHTML).not.toContain("Loading this case");
    expect(p.el("assetGraph").innerHTML).toContain("stopped");
    expect(p.el("assetGraph").innerHTML).not.toContain("a-host");
    expect(api.hasAssetGraph()).toBe(false);
  });

  it("a late overrides answer for case A does not land in case B", async () => {
    const p = fakePage();
    const api = ag(p);
    api.loadAssetOverrides("CASE-A");
    p.switchCase("CASE-B");
    p.requests[0].answer({ merges: { "host:a1": "host:a2" } });
    await drainAll();
    expect(api.assetOverrideMerges()).toEqual({});
  });
});

describe("duplicate hosts: the previous case's pairs are not shown after a switch (#2900)", () => {
  interface HdApi {
    loadHostDuplicates(caseId: string): Promise<void>;
  }
  const pair = (host: string) => ({ canonical: `${host}.corp.test`, other: host, reason: "shortname-fqdn" });
  function hd(p: ReturnType<typeof fakePage>) {
    return loadDashboardModule<HdApi>(
      "dashboard-host-duplicates.js",
      ["dashboard-escape.js", "dashboard-time.js"],
      p.globals,
    );
  }
  async function answerBoth(p: ReturnType<typeof fakePage>, from: number, host: string | null, ok = true) {
    p.requests[from].answer({ pending: host ? [pair(host)] : [] }, ok);
    p.requests[from + 1].answer({ dismissed: [] }, ok);
    await drainAll();
  }

  it("clears case A's pairs and badge the moment case B's load starts", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-a");
    expect(p.el("hostDuplicatesBadge").style.display).toBe("");
    p.switchCase("CASE-B");
    void api.loadHostDuplicates("CASE-B");
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
    expect(p.el("hostDuplicatesBadge").style.display).toBe("none");
    await answerBoth(p, 2, "ws-b");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-b");
  });

  it("case A's late answer after the switch is dropped", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    p.switchCase("CASE-B");
    void api.loadHostDuplicates("CASE-B");
    await answerBoth(p, 2, "ws-b");
    await answerBoth(p, 0, "ws-a");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-b");
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
  });

  it("a failed load for the new case says so, and the next call retries and paints", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    p.switchCase("CASE-B");
    void api.loadHostDuplicates("CASE-B");
    p.requests[2].fail();
    p.requests[3].fail();
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("hd-load-failed");
    void api.loadHostDuplicates("CASE-B");
    await answerBoth(p, 4, "ws-b");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-b");
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("hd-load-failed");
  });

  it("a cancel after the switch (aborted load) shows no failure notice", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    p.switchCase("CASE-B");
    void api.loadHostDuplicates("CASE-B");
    p.switchCase("");
    p.requests[2].fail();
    p.requests[3].fail();
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("hd-load-failed");
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
    expect(p.el("hostDuplicatesBadge").style.display).toBe("none");
  });

  it("a second load in the window does not repaint the cleared panel", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    p.switchCase("CASE-B");
    void api.loadHostDuplicates("CASE-B");
    p.el("hostDuplicatesBody").innerHTML = "sentinel";
    void api.loadHostDuplicates("CASE-B");
    expect(p.el("hostDuplicatesBody").innerHTML).toBe("sentinel");
  });

  it("a same-case reload keeps the pairs until its answer", async () => {
    const p = fakePage();
    const api = hd(p);
    void api.loadHostDuplicates("CASE-A");
    await answerBoth(p, 0, "ws-a");
    void api.loadHostDuplicates("CASE-A");
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-a");
  });
});

describe("light case-open loaders: the previous case's content is not kept (#2900)", () => {
  it("activity log: A's rows are blanked at the switch and A's late answer is dropped", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadActivityLog(c: string): void }>(
      "dashboard-activity-log.js",
      ["dashboard-escape.js", "dashboard-time.js"],
      p.globals,
    );
    const row = (detail: string) => [{ ts: "2026-01-01T00:00:00Z", category: "import", actor: "x", detail }];
    api.loadActivityLog("CASE-A");
    p.requests[0].answer(row("a-import"));
    await drainAll();
    expect(p.el("activityLogPanel").innerHTML).toContain("a-import");
    api.loadActivityLog("CASE-A"); // a push for A still in flight across the switch
    p.switchCase("CASE-B");
    api.loadActivityLog("CASE-B");
    expect(p.el("activityLogPanel").innerHTML).toBe("");
    p.requests[2].answer(row("b-import"));
    p.requests[1].answer(row("a-late"));
    await drainAll();
    expect(p.el("activityLogPanel").innerHTML).toContain("b-import");
    expect(p.el("activityLogPanel").innerHTML).not.toContain("a-late");
  });

  it("pins: A's pins are dropped at the switch, so B's same-id finding is not shown pinned", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadPins(c: string): void; pinBtn(fid: string): string }>(
      "dashboard-pinned-findings.js",
      ["dashboard-escape.js", "dashboard-glyphs.js"],
      p.globals,
    );
    api.loadPins("CASE-A");
    p.requests[0].answer({ pins: [{ findingId: "f1" }], limit: 5 });
    await drainAll();
    expect(api.pinBtn("f1")).toContain("pinned");
    p.switchCase("CASE-B");
    api.loadPins("CASE-B");
    expect(api.pinBtn("f1")).not.toContain(" pinned");
    p.requests[1].answer({ pins: [], limit: 5 });
    await drainAll();
    expect(api.pinBtn("f1")).not.toContain(" pinned");
  });

  it("pins: A's late answer after the switch is dropped", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadPins(c: string): void; pinBtn(fid: string): string }>(
      "dashboard-pinned-findings.js",
      ["dashboard-escape.js", "dashboard-glyphs.js"],
      p.globals,
    );
    api.loadPins("CASE-A");
    p.switchCase("CASE-B");
    api.loadPins("CASE-B");
    p.requests[1].answer({ pins: [], limit: 5 });
    p.requests[0].answer({ pins: [{ findingId: "f1" }], limit: 5 });
    await drainAll();
    expect(api.pinBtn("f1")).not.toContain(" pinned");
  });

  it("finding workflow: A's assignee is dropped at the switch and A's late answer ignored", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{
      loadFindingWorkflow(c: string): void;
      findingWorkflowControls(fid: string): string;
    }>("dashboard-finding-workflow.js", ["dashboard-escape.js", "dashboard-values.js"], p.globals);
    api.loadFindingWorkflow("CASE-A");
    p.requests[0].answer([{ findingId: "f1", assignee: "alice-a", status: "in_progress" }]);
    await drainAll();
    expect(api.findingWorkflowControls("f1")).toContain("alice-a");
    api.loadFindingWorkflow("CASE-A");
    p.switchCase("CASE-B");
    api.loadFindingWorkflow("CASE-B");
    expect(api.findingWorkflowControls("f1")).not.toContain("alice-a");
    p.requests[2].answer([]);
    p.requests[1].answer([{ findingId: "f1", assignee: "alice-a", status: "in_progress" }]);
    await drainAll();
    expect(api.findingWorkflowControls("f1")).not.toContain("alice-a");
  });

  it("playbook: A's tasks are cleared at the switch and A's late answer is dropped", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadPlaybook(c: string): void }>(
      "dashboard-playbook.js",
      ["dashboard-escape.js", "dashboard-values.js"],
      { ...p.globals, VHS_SEV_RANK: {} },
    );
    const tasks = (title: string) => ({
      tasks: [{ id: "t1", title, status: "todo" }],
      stats: null,
      control: null,
    });
    api.loadPlaybook("CASE-A");
    p.requests[0].answer(tasks("a-task"));
    await drainAll();
    expect(p.el("pbList").innerHTML).toContain("a-task");
    api.loadPlaybook("CASE-A");
    p.switchCase("CASE-B");
    api.loadPlaybook("CASE-B");
    expect(p.el("pbList").innerHTML).not.toContain("a-task");
    p.requests[2].answer(tasks("b-task"));
    p.requests[1].answer(tasks("a-late"));
    await drainAll();
    expect(p.el("pbList").innerHTML).toContain("b-task");
    expect(p.el("pbList").innerHTML).not.toContain("a-late");
  });
});

describe("a late caller for the case left does not clear the case on screen (#2900 review)", () => {
  it("asset graph: an A edit's callback after the switch neither clears B nor fetches", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadAssetGraph(c: string): void; hasAssetGraph(): boolean }>(
      "dashboard-asset-graph.js",
      ["dashboard-escape.js"],
      p.globals,
    );
    p.switchCase("CASE-B");
    api.loadAssetGraph("CASE-B");
    p.requests[0].answer({ assets: [{ id: "host:b", name: "b", type: "host" }], iocs: [], edges: [] });
    await drainAll();
    api.loadAssetGraph("CASE-A");
    expect(p.urls()).toEqual(["/cases/CASE-B/asset-graph"]);
    expect(api.hasAssetGraph()).toBe(true);
  });

  it("asset overrides: the newest load wins across A -> B -> A", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{
      loadAssetOverrides(c: string): void;
      assetOverrideMerges(): Record<string, string>;
    }>("dashboard-asset-graph.js", ["dashboard-escape.js"], p.globals);
    api.loadAssetOverrides("CASE-A");
    p.switchCase("CASE-B");
    api.loadAssetOverrides("CASE-B");
    p.switchCase("CASE-A");
    api.loadAssetOverrides("CASE-A");
    p.requests[2].answer({ merges: { "host:new": "host:x" } });
    p.requests[0].answer({ merges: { "host:old": "host:x" } });
    await drainAll();
    expect(api.assetOverrideMerges()).toEqual({ "host:new": "host:x" });
  });

  it("playbook: an A add/sync callback after the switch does not clear B's tasks", async () => {
    const p = fakePage();
    const api = loadDashboardModule<{ loadPlaybook(c: string): void }>(
      "dashboard-playbook.js",
      ["dashboard-escape.js", "dashboard-values.js"],
      { ...p.globals, VHS_SEV_RANK: {} },
    );
    p.switchCase("CASE-B");
    api.loadPlaybook("CASE-B");
    p.requests[0].answer({
      tasks: [{ id: "t1", title: "b-task", status: "todo" }],
      stats: null,
      control: null,
    });
    await drainAll();
    api.loadPlaybook("CASE-A");
    expect(p.el("pbList").innerHTML).toContain("b-task");
    expect(p.urls()).toEqual(["/cases/CASE-B/playbook"]);
  });
});
