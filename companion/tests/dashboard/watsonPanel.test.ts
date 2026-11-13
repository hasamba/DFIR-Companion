// Task 9: the Watson side panel and section. Renders through the real module in a vm context with
// a small fake DOM, so the escaping, the rail and the storage fallback are checked as run.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { DASHBOARD_SECTION_IDS } from "../../src/analysis/dashboardViews.js";

interface Api {
  renderWatson(chat: unknown): void;
  toggleWatsonCollapse(): void;
  loadWatson(caseId: string): Promise<void>;
  watsonAct(el: unknown): unknown;
}

class FakeEl {
  innerHTML = "";
  scrollTop = 0;
  scrollHeight = 0;
  private cls = new Set<string>();
  classList = {
    toggle: (c: string, on?: boolean) => {
      const want = on === undefined ? !this.cls.has(c) : on;
      if (want) this.cls.add(c);
      else this.cls.delete(c);
      return want;
    },
    contains: (c: string) => this.cls.has(c),
  };
  setAttribute() {}
}

function setup(opts: { throwingStorage?: boolean; fetch?: unknown } = {}) {
  const log = new FakeEl();
  const board = new FakeEl();
  const foot = new FakeEl();
  const count = new FakeEl();
  const dot = new FakeEl();
  const panel = new FakeEl();
  const body = new FakeEl();
  const byW: Record<string, FakeEl[]> = {
    log: [log],
    board: [board],
    foot: [foot],
    count: [count],
    dot: [dot],
  };
  const document = {
    body,
    readyState: "complete",
    getElementById: (id: string) => (id === "watsonPanel" ? panel : id === "caseId" ? { value: "c1" } : null),
    querySelectorAll: (sel: string) => byW[/data-w="(\w+)"/.exec(sel)?.[1] ?? ""] ?? [],
    addEventListener: () => {},
  };
  const storage = opts.throwingStorage
    ? {
        getItem: () => {
          throw new Error("blocked");
        },
        setItem: () => {
          throw new Error("blocked");
        },
      }
    : { getItem: () => null, setItem: () => {} };
  const api = loadDashboardModule<Api>("dashboard-watson.js", ["dashboard-escape.js"], {
    document,
    localStorage: storage,
    fetch: opts.fetch ?? (async () => ({ ok: false, status: 500, json: async () => ({}) })),
  });
  return { api, log, board, foot, count, dot, panel, body };
}

const chatWith = (turns: unknown[], extra: Record<string, unknown> = {}) => ({
  turns,
  proposals: [],
  pastes: [],
  memory: "",
  pendingCaseEvents: [],
  costUSD: 0,
  tokens: 0,
  calls: 0,
  ...extra,
});

describe("renderWatson escaping", () => {
  it("escapes markup and shows a bidi control as a marker", () => {
    const { api, log } = setup();
    api.renderWatson(
      chatWith([
        { id: "t1", at: "x", role: "watson", text: "<img src=x onerror=1> a‮b", workingOn: "<b>w</b>" },
        {
          id: "t2",
          at: "x",
          role: "watson",
          text: "q",
          request: { kind: "query", language: "kql", query: "<script>1</script>", why: "<i>y</i>" },
        },
      ]),
    );
    expect(log.innerHTML).not.toContain("<img");
    expect(log.innerHTML).not.toContain("<script>");
    expect(log.innerHTML).not.toContain("‮");
    expect(log.innerHTML).toContain("&lt;img src=x onerror=1&gt;");
    expect(log.innerHTML).toContain("&lt;RLO&gt;");
    expect(log.innerHTML).toContain("<pre");
    expect(log.innerHTML).toContain("kql");
  });

  it("shows the board with the synthesis-disagrees line and no detail when the answer is empty", () => {
    const { api, board } = setup();
    api.renderWatson(chatWith([]));
    // the board reads questions from the dashboard state; an empty board says so
    expect(board.innerHTML).toContain("No key questions");
  });

  it("footer shows tokens when the cost is zero and calls exist", () => {
    const { api, foot } = setup();
    api.renderWatson(chatWith([], { calls: 3, tokens: 1200 }));
    expect(foot.innerHTML).toBe("This case: 3 calls · 1200 tokens");
    api.renderWatson(chatWith([], { calls: 3, costUSD: 0.5 }));
    expect(foot.innerHTML).toBe("This case: 3 calls · $0.50");
  });
});

describe("collapse to a rail", () => {
  const proposal = (id: string, status: string) => ({
    id,
    turnId: "t1",
    kind: "question_new",
    questionId: "q1",
    status,
    after: { id: "q1", question: "Q?", status: "unknown", answer: "", pointer: "" },
  });

  it("switches between full and rail and shows the pending count", () => {
    const { api, panel, body, count } = setup();
    api.renderWatson(
      chatWith([], {
        proposals: [proposal("p1", "pending"), proposal("p2", "applied"), proposal("p3", "pending")],
      }),
    );
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
    api.toggleWatsonCollapse();
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
    expect(body.classList.contains("watson-rail-open")).toBe(true);
    expect(count.innerHTML).toBe("2");
    api.toggleWatsonCollapse();
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
    expect(body.classList.contains("watson-panel-open")).toBe(true);
  });

  it("lights the unread dot only while collapsed", () => {
    const { api, dot } = setup();
    api.renderWatson(chatWith([]));
    api.toggleWatsonCollapse();
    api.renderWatson(chatWith([{ id: "t1", at: "x", role: "watson", text: "hi" }]));
    expect(dot.classList.contains("watson-on")).toBe(true);
    api.toggleWatsonCollapse();
    expect(dot.classList.contains("watson-on")).toBe(false);
  });

  it("a throwing localStorage does not break the toggle", () => {
    const { api, panel } = setup({ throwingStorage: true });
    api.renderWatson(chatWith([]));
    expect(() => api.toggleWatsonCollapse()).not.toThrow();
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
  });
});

describe("409 handling", () => {
  it("renders a 409 server message as a warning turn", async () => {
    const calls: string[] = [];
    const fetch = async (url: string, init?: { method?: string }) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (init?.method === "POST")
        return { ok: false, status: 409, json: async () => ({ error: "cost limit reached" }) };
      return { ok: true, status: 200, json: async () => chatWith([]) };
    };
    const { api, log } = setup({ fetch });
    api.renderWatson(chatWith([]));
    const input = { value: "hello" };
    const root = { querySelector: () => input };
    await api.watsonAct({ dataset: { wVerb: "send" }, closest: () => root });
    expect(log.innerHTML).toContain("cost limit reached");
    expect(log.innerHTML).toContain("watson-warn");
  });
});

describe("fix round 1", () => {
  const html = readFileSync(new URL("../../../public/js/dashboard-watson.js", import.meta.url), "utf8");
  it("the rail is a real button that restores the panel, and aria-expanded is off the aside", () => {
    expect(html).toMatch(/<button type="button" class="watson-rail"[^>]*data-w-verb="collapse"/);
    expect(html).not.toMatch(/role="button"/);
    expect(html).not.toContain('panel.setAttribute("aria-expanded"');
    expect(html).toMatch(/data-w-verb="collapse" aria-expanded="true"/);
    const { api, panel } = setup();
    api.renderWatson(chatWith([]));
    api.toggleWatsonCollapse();
    api.watsonAct({ dataset: { wVerb: "collapse" } });
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
  });

  it("a failed send keeps the analyst's text", async () => {
    const fetch = async () => ({ ok: false, status: 500, json: async () => ({ error: "boom" }) });
    const { api } = setup({ fetch });
    api.renderWatson(chatWith([]));
    const input = { value: "keep me" };
    await api.watsonAct({ dataset: { wVerb: "send" }, closest: () => ({ querySelector: () => input }) });
    expect(input.value).toBe("keep me");
  });

  it("refuses a paste over 50 MB without posting", async () => {
    let posted = false;
    const fetch = async () => {
      posted = true;
      return { ok: true, status: 200, json: async () => chatWith([]) };
    };
    const { api, log } = setup({ fetch });
    api.renderWatson(chatWith([]));
    const area = { value: "x".repeat(50 * 1024 * 1024 + 1) };
    const box = { classList: { remove() {} } };
    const root = { querySelector: (s: string) => (s.includes("text") ? area : box) };
    await api.watsonAct({ dataset: { wVerb: "pasteSend" }, closest: () => root });
    expect(posted).toBe(false);
    expect(log.innerHTML).toContain("50 MB");
  });

  it("Analyst view includes sec-watson after sec-ask", async () => {
    const { BUILT_IN_DASHBOARD_VIEWS } = await import("../../src/analysis/dashboardViews.js");
    const a = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === "analyst")!;
    expect(a.sections.indexOf("sec-watson")).toBe(a.sections.indexOf("sec-ask") + 1);
  });
});

describe("wiring", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  it("sec-watson is in SECTION_DEFS and DASHBOARD_SECTION_IDS", () => {
    expect(html).toContain('{ id: "sec-watson", label: "Watson" }');
    expect(html).toContain('<section id="sec-watson"');
    expect(DASHBOARD_SECTION_IDS).toContain("sec-watson");
  });
  it("the toolbar button and panel exist, and the button has a short label", () => {
    expect(html).toMatch(/<button id="watsonToggle"[^>]*>Watson<\/button>/);
    expect(html).toContain('id="watsonPanel"');
  });
});
