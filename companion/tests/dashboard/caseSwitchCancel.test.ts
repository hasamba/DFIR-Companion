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

// #2929: an action's answer (a click's request) must not paint after a cancel and a reopen of the same
// case — or A -> B -> A — even though the case on screen matches again. Each module keeps an action
// generation that moves only when its owner case changes (a cancel included), never on a same-case
// reload, so a Refresh while an action runs still lets its answer paint.
const away = {
  cancel: (p: ReturnType<typeof fakePage>, api: object) => p.cancel(api),
  "switch to B": (p: ReturnType<typeof fakePage>, api: Api, load: (c: string) => void) => {
    p.switchCase("CASE-B", api);
    load("CASE-B");
  },
};

describe("custody Verify after a cancel or A -> B -> A (#2929)", () => {
  const records = (path: string) => ({
    records: [{ artifactPath: path, event: "stored", at: "2020-01-01T00:00:00Z", sha256: "x" }],
  });
  function custody() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-custody.js", ESC, p.globals);
    api.initCustodyButtons();
    const verify = () => p.el("custodyVerifyBtn").fire("click");
    const msg = () => p.el("custodyVerifyMsg").textContent;
    return { p, api, verify, msg };
  }

  it.each(Object.keys(away) as (keyof typeof away)[])(
    "%s: the old verify's answer paints nothing and does not free Verify while a newer one runs",
    async (how) => {
      const { p, api, verify, msg } = custody();
      api.loadCustody("CASE-A");
      p.requests[0].answer(records("AAA.png"));
      await drainAll();
      verify(); // requests[1], on its way when the analyst leaves
      away[how](p, api, (c) => api.loadCustody(c));
      p.switchCase("CASE-A", api);
      api.loadCustody("CASE-A");
      const reload = p.requests.length - 1;
      p.requests[reload].answer(records("AAA.png"));
      await drainAll();
      verify();
      const second = p.requests.length - 1;
      expect(p.el("custodyVerifyBtn").disabled).toBe(true);
      p.requests[1].answer({ ok: false, mismatches: [{ artifactPath: "AAA.png" }], chainBreaks: [] });
      await drainAll();
      expect(msg()).toBe("Re-hashing evidence…");
      expect(p.el("custodyVerifyBtn").disabled, "an older verify freed the button").toBe(true);
      p.requests[second].answer({ ok: true, mismatches: [], chainBreaks: [] });
      await drainAll();
      expect(msg()).toBe("All artifacts verified, custody log intact.");
      expect(p.el("custodyVerifyBtn").disabled).toBe(false);
    },
  );

  it("an old verify failing after the reopen says nothing", async () => {
    const { p, api, verify, msg } = custody();
    api.loadCustody("CASE-A");
    verify();
    p.cancel(api);
    p.switchCase("CASE-A", api);
    api.loadCustody("CASE-A");
    p.requests[1].fail();
    await drainAll();
    expect(msg()).not.toContain("failed to run");
  });

  it("a Refresh while Verify runs still lets the verify answer paint and free the button", async () => {
    const { p, api, verify, msg } = custody();
    api.loadCustody("CASE-A");
    p.requests[0].answer(records("AAA.png"));
    await drainAll();
    verify();
    api.loadCustody("CASE-A"); // the Refresh button, or a live reload of the same case
    p.requests[2].answer(records("AAA.png"));
    p.requests[1].answer({ ok: true, mismatches: [], chainBreaks: [] });
    await drainAll();
    expect(msg()).toBe("All artifacts verified, custody log intact.");
    expect(p.el("custodyVerifyBtn").disabled).toBe(false);
  });
});

describe("duplicate-host merge / dismiss / undo after a cancel or A -> B -> A (#2929)", () => {
  const pair = (host: string) => ({ canonical: `${host}.corp.test`, other: host, reason: "shortname-fqdn" });
  function hd() {
    const p = fakePage();
    const kicked: string[] = [];
    const api = loadDashboardModule<Api>("dashboard-host-duplicates.js", ESC, {
      ...p.globals,
      applySectionsVis: () => {},
      SECTIONS_VIS_KEY: "dfir.sectionsVis",
      confirm: () => true,
      refreshAiState: (c: string) => kicked.push(c),
    });
    const click = (attr: "data-hd-merge" | "data-hd-dismiss" | "data-hd-undo") => {
      const button = {
        hasAttribute: (n: string) => n === attr,
        getAttribute: (n: string) => (n === "data-hd-canonical" ? "ws-a.corp.test" : "ws-a"),
      };
      p.el("hostDuplicatesBody").fire("click", { target: { closest: () => button } });
    };
    const loadAnswered = async (caseId: string, host: string) => {
      void api.loadHostDuplicates(caseId);
      const n = p.requests.length;
      p.requests[n - 2].answer({ pending: [pair(host)] });
      p.requests[n - 1].answer({ dismissed: [] });
      await drainAll();
    };
    return { p, api, kicked, click, loadAnswered };
  }

  it.each([
    ["merge", "cancel"],
    ["undo", "cancel"],
    ["dismiss", "switch to B"],
    ["undo", "switch to B"],
  ] as const)("%s, then %s and back to A: the old answer paints nothing", async (action, how) => {
    const { p, api, kicked, click, loadAnswered } = hd();
    await loadAnswered("CASE-A", "ws-a");
    click(`data-hd-${action}`);
    const old = p.requests.length - 1;
    expect(p.requests[old].init?.method).toBe(action === "undo" ? "DELETE" : "POST");
    away[how](p, api, (c) => void api.loadHostDuplicates(c));
    p.switchCase("CASE-A", api);
    await loadAnswered("CASE-A", "ws-new");
    p.requests[old].answer({ pending: [pair("ws-old")], dismissed: [] });
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).toContain("ws-new");
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-old");
    expect(kicked).toEqual([]);
  });

  it("a reload of the same case while a merge runs still lets the merge answer paint", async () => {
    const { p, kicked, click, loadAnswered } = hd();
    await loadAnswered("CASE-A", "ws-a");
    click("data-hd-merge");
    const merge = p.requests.length - 1;
    await loadAnswered("CASE-A", "ws-a");
    p.requests[merge].answer({ pending: [] });
    await drainAll();
    expect(p.el("hostDuplicatesBody").innerHTML).not.toContain("ws-a");
    expect(kicked).toEqual(["CASE-A"]);
  });
});

describe("tagger tags asked for a row, after a cancel and a reopen (#2929)", () => {
  it("the old answer does not replace the tags the reopened case's page carried", async () => {
    const p = fakePage();
    const pageListeners: ((s: unknown) => void)[] = [];
    const api = loadDashboardModule<Api>("dashboard-tags.js", ESC, {
      ...p.globals,
      targetKey: (t: string, i: string) => `${t}:${i}`,
      render: () => {},
      deriveStarred: () => {},
      migrateLocalStars: () => {},
      DfirState: {
        lastState: () => null,
        lastSuperData: () => null,
        onLastStateChange: (fn: (s: unknown) => void) => pageListeners.push(fn),
        onLastSuperDataChange: () => {},
      },
    });
    const page = (s: unknown) => pageListeners.forEach((fn) => fn(s));
    api.loadTags("CASE-A");
    p.requests[0].answer([]);
    await drainAll();
    page({ caseId: "CASE-A", forensicTimeline: [{ id: "e1" }] }); // a push: no page tags, so ask
    await drainAll();
    const ask = p.requests.length - 1;
    expect(p.requests[ask].url).toContain("/tags/tagger-for");
    p.cancel(api);
    p.switchCase("CASE-A", api);
    api.loadTags("CASE-A");
    p.requests[p.requests.length - 1].answer([]);
    await drainAll();
    const fresh = [{ id: "t1", label: "fresh-label", author: "tagger:x" }];
    page({ caseId: "CASE-A", forensicTimeline: [{ id: "e1" }], eventTaggerTags: { e1: fresh } });
    expect(api.tagPills("event", "e1")).toContain("fresh-label");
    p.requests[ask].answer({
      eventTaggerTags: { e1: [{ id: "t0", label: "old-label", author: "tagger:x" }] },
    });
    await drainAll();
    expect(api.tagPills("event", "e1")).toContain("fresh-label");
    expect(api.tagPills("event", "e1")).not.toContain("old-label");
  });
});
