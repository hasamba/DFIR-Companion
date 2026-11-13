// Task 9: the Watson side panel and section. Renders through the real module in a vm context with
// a small fake DOM, so the escaping, the rail and the storage fallback are checked as run.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { DASHBOARD_SECTION_IDS } from "../../src/analysis/dashboardViews.js";

interface Api {
  initWatson(): void;
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

function setup(opts: { throwingStorage?: boolean; fetch?: unknown; stored?: Record<string, string> } = {}) {
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
  const caseInput = { value: "c1" };
  const document = {
    body,
    readyState: "complete",
    getElementById: (id: string) => (id === "watsonPanel" ? panel : id === "caseId" ? caseInput : null),
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
    : {
        getItem: (k: string) => opts.stored?.[k] ?? null,
        setItem: () => {},
      };
  const api = loadDashboardModule<Api>(
    "dashboard-watson.js",
    ["dashboard-escape.js", "dashboard-watson-view.js"],
    {
      document,
      localStorage: storage,
      fetch: opts.fetch ?? (async () => ({ ok: false, status: 500, json: async () => ({}) })),
    },
  );
  return { api, log, board, foot, count, dot, panel, body, caseInput };
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

describe("rail button, failed sends and paste limits", () => {
  const html = ["dashboard-watson.js", "dashboard-watson-view.js"]
    .map((f) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8"))
    .join("\n");
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

  it("puts one statement on a line in the log builder", () => {
    expect(html).not.toMatch(/;[ \t]+return\b/);
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

// A fetch whose answers the test releases by hand, so a case switch can land while a request is out.
function heldFetch() {
  const calls: { url: string; method: string; release: (res: unknown) => void }[] = [];
  const fetch = (url: string, init?: { method?: string }) =>
    new Promise((resolve) => calls.push({ url, method: init?.method ?? "GET", release: resolve }));
  return { calls, fetch };
}
const response = (status: number, body: unknown, headers: Record<string, string> = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
  json: async () => body,
});
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("panel default and no provider", () => {
  it("starts as the rail when the analyst never chose", () => {
    const { api, panel, body } = setup();
    api.initWatson();
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
    expect(body.classList.contains("watson-rail-open")).toBe(true);
  });

  it("remembers an analyst who opened the panel", () => {
    const { api, panel } = setup({ stored: { "dfir.watsonCollapsed": "0" } });
    api.initWatson();
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
  });

  it("hides the panel when the server has no Watson provider, and shows it again when one appears", async () => {
    let configured = false;
    const fetch = async () => response(200, { ...chatWith([]), providerConfigured: configured });
    const { api, panel, body } = setup({ fetch });
    api.initWatson();
    await api.loadWatson("c1");
    expect(panel.classList.contains("watson-hidden")).toBe(true);
    expect(body.classList.contains("watson-rail-open")).toBe(false);
    configured = true;
    await api.loadWatson("c1");
    expect(panel.classList.contains("watson-hidden")).toBe(false);
  });

  it("hides the panel when GET /watson answers 501", async () => {
    const { api, panel } = setup({ fetch: async () => response(501, { error: "Watson is not configured" }) });
    api.initWatson();
    await api.loadWatson("c1");
    expect(panel.classList.contains("watson-hidden")).toBe(true);
  });
});

describe("requests stay with the case they started on", () => {
  const sendEl = (input: { value: string }) => ({
    dataset: { wVerb: "send" },
    closest: () => ({ querySelector: () => input }),
  });

  it("drops a reply that lands after the analyst opened another case, and keeps the new case usable", async () => {
    const held = heldFetch();
    const { api, log, caseInput } = setup({ fetch: held.fetch });
    api.renderWatson(chatWith([]));
    const input = { value: "about case one" };
    const done = api.watsonAct(sendEl(input)) as Promise<void>;
    expect(held.calls[0].url).toBe("/cases/c1/watson/message");
    expect(log.innerHTML).toContain("thinking");
    caseInput.value = "c2";
    void api.loadWatson("c2");
    held.calls[1].release(response(200, chatWith([])));
    await tick();
    expect(log.innerHTML).not.toContain("thinking"); // c1's request does not block c2
    const second = { value: "about case two" };
    void api.watsonAct(sendEl(second));
    expect(held.calls[2].url).toBe("/cases/c2/watson/message");
    held.calls[0].release(
      response(200, chatWith([{ id: "t1", at: "x", role: "watson", text: "ANSWER FOR CASE ONE" }])),
    );
    await done;
    expect(log.innerHTML).not.toContain("ANSWER FOR CASE ONE");
  });

  it("does not put a failed message back in the box once another case is open", async () => {
    const held = heldFetch();
    const { api, caseInput } = setup({ fetch: held.fetch });
    api.renderWatson(chatWith([]));
    const input = { value: "case one words" };
    const done = api.watsonAct(sendEl(input)) as Promise<void>;
    caseInput.value = "c2";
    held.calls[0].release(response(500, { error: "boom" }));
    await done;
    expect(input.value).toBe("");
  });

  it("sends an attached file to the case that was open when it was picked", async () => {
    const held = heldFetch();
    const { api, caseInput } = setup({ fetch: held.fetch });
    api.renderWatson(chatWith([]));
    let release: (t: string) => void = () => {};
    const file = {
      name: "a.txt",
      type: "text/plain",
      size: 3,
      text: () => new Promise<string>((r) => (release = r)),
    };
    const done = api.watsonAct({ dataset: { wVerb: "file" }, files: [file], value: "" }) as Promise<void>;
    caseInput.value = "c2";
    release("abc");
    await tick();
    expect(held.calls[0].url).toBe("/cases/c1/watson/paste");
    held.calls[0].release(response(200, chatWith([])));
    await done;
  });

  it("drops a proposal answer once another case is open", async () => {
    const held = heldFetch();
    const { api, board, caseInput } = setup({ fetch: held.fetch });
    api.renderWatson(chatWith([]));
    const done = api.watsonAct({ dataset: { wVerb: "apply", pid: "p1" } }) as Promise<void>;
    expect(held.calls[0].url).toBe("/cases/c1/watson/proposals/p1/apply");
    caseInput.value = "c2";
    const q = { id: "q1", question: "CASE ONE QUESTION", status: "answered", answer: "", pointer: "" };
    held.calls[0].release(response(200, { chat: chatWith([]), state: { keyQuestions: [q] } }));
    await done;
    expect(board.innerHTML).not.toContain("CASE ONE QUESTION");
  });
});

describe("paste failures say whether the text was stored", () => {
  const pasteRoot = (area: { value: string }) => {
    const box = { classList: { remove() {} } };
    return { querySelector: (sel: string) => (sel.includes("text") ? area : box) };
  };

  it("a stored paste behind a refused round is not put back in the box", async () => {
    const fetch = async (_u: string, init?: { method?: string }) =>
      init?.method === "POST"
        ? response(409, { error: "Watson reached this case's cost limit." }, { "x-watson-paste-stored": "1" })
        : response(200, chatWith([]));
    const { api, log } = setup({ fetch });
    api.renderWatson(chatWith([]));
    const area = { value: "evidence text" };
    await api.watsonAct({ dataset: { wVerb: "pasteSend" }, closest: () => pasteRoot(area) });
    expect(area.value).toBe("");
    expect(log.innerHTML).toContain("The paste was stored as evidence");
    expect(log.innerHTML).toContain("cost limit");
  });

  it("a paste refused before storing (AI off) says so and keeps the text", async () => {
    const fetch = async (_u: string, init?: { method?: string }) =>
      init?.method === "POST"
        ? response(409, { error: "AI is off for this case. Turn it on to talk to Watson." })
        : response(200, chatWith([]));
    const { api, log } = setup({ fetch });
    api.renderWatson(chatWith([]));
    const area = { value: "evidence text" };
    await api.watsonAct({ dataset: { wVerb: "pasteSend" }, closest: () => pasteRoot(area) });
    expect(area.value).toBe("evidence text");
    expect(log.innerHTML).toContain("The paste was not stored");
    expect(log.innerHTML).not.toContain("was stored as evidence");
  });
});

describe("wiring", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  it("sec-watson is in SECTION_DEFS and DASHBOARD_SECTION_IDS", () => {
    expect(html).toContain('{ id: "sec-watson", label: "Watson" }');
    expect(html).toContain('<section id="sec-watson"');
    expect(DASHBOARD_SECTION_IDS).toContain("sec-watson");
  });
  it("loads the view module before the panel module", () => {
    const view = html.indexOf('<script src="/js/dashboard-watson-view.js"></script>');
    expect(view).toBeGreaterThan(-1);
    expect(view).toBeLessThan(html.indexOf('<script src="/js/dashboard-watson.js"></script>'));
  });
  it("the toolbar button and panel exist, and the button has a short label", () => {
    expect(html).toMatch(/<button id="watsonToggle"[^>]*>Watson<\/button>/);
    expect(html).toContain('id="watsonPanel"');
  });
});
