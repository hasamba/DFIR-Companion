// Task 9: the Watson side panel and section. Renders through the real module in a vm context with
// a small fake DOM, so the escaping, the rail and the storage fallback are checked as run.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { DASHBOARD_SECTION_IDS } from "../../src/analysis/dashboardViews.js";

interface Api {
  initWatson(): void;
  renderWatson(chat: unknown): void;
  setWatsonPanelState(state: string): void;
  toggleWatsonPanel(): void;
  loadWatson(caseId: string): Promise<void>;
  watsonAct(el: unknown): unknown;
}

type StateListener = (st: unknown) => void;

class FakeEl {
  innerHTML = "";
  style = { top: "" };
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

const KEY = "dfir.watson.panel";

const headerBox = { bottom: 80 };
const rootVars: Record<string, string> = {};
const observers: (() => void)[] = [];
const resizeFns: (() => void)[] = [];

function setup(
  opts: {
    throwingStorage?: boolean;
    noResizeObserver?: boolean;
    fetch?: unknown;
    stored?: Record<string, string>;
    confirm?: (text: string) => boolean;
    alert?: (text: string) => void;
  } = {},
) {
  const log = new FakeEl();
  const board = new FakeEl();
  const foot = new FakeEl();
  const count = new FakeEl();
  const dot = new FakeEl();
  const panel = new FakeEl();
  const body = new FakeEl();
  const mode = new FakeEl();
  const railMode = new FakeEl();
  const byW: Record<string, FakeEl[]> = {
    log: [log],
    board: [board],
    foot: [foot],
    count: [count],
    dot: [dot],
    mode: [mode],
    railmode: [railMode],
  };
  const caseInput = { value: "c1" };
  const keyListeners: ((e: { key: string; target?: unknown }) => void)[] = [];
  const written: Record<string, string> = { ...opts.stored };
  const document = {
    body,
    documentElement: { style: { setProperty: (k: string, v: string) => (rootVars[k] = v) } },
    querySelector: (sel: string) => (sel === "header" ? { getBoundingClientRect: () => headerBox } : null),
    readyState: "complete",
    createElement: () => {
      const node = { className: "", textContent: "", attrs: {} as Record<string, string> };
      return { ...node, setAttribute: (k: string, v: string) => (node.attrs[k] = v), attrs: node.attrs };
    },
    getElementById: (id: string) => (id === "watsonPanel" ? panel : id === "caseId" ? caseInput : null),
    querySelectorAll: (sel: string) => byW[/data-w="(\w+)"/.exec(sel)?.[1] ?? ""] ?? [],
    addEventListener: (t: string, cb: (e: { key: string }) => void) => {
      if (t === "keydown") keyListeners.push(cb);
    },
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
        getItem: (k: string) => written[k] ?? null,
        setItem: (k: string, v: string) => {
          written[k] = v;
        },
      };
  const stateListeners: StateListener[] = [];
  const api = loadDashboardModule<Api>(
    "dashboard-watson.js",
    [
      "dashboard-escape.js",
      "dashboard-watson-marks.js",
      "dashboard-watson-cards.js",
      "dashboard-watson-view.js",
      "dashboard-watson-mode.js",
    ],
    {
      document,
      confirm: opts.confirm ?? (() => true),
      alert: opts.alert ?? (() => {}),
      DfirState: { onLastStateChange: (cb: StateListener) => stateListeners.push(cb) },
      // the real one links to the timeline; here a marker per id shows which ids reached it
      citeEvents: (ids: string[]) => (ids || []).map((id) => `[cited ${id}]`).join(" "),
      localStorage: storage,
      ...(opts.noResizeObserver
        ? {}
        : {
            ResizeObserver: class {
              constructor(cb: () => void) {
                observers.push(cb);
              }
              observe() {}
            },
          }),
      addEventListener: (_t: string, cb: () => void) => resizeFns.push(cb),
      fetch: opts.fetch ?? (async () => ({ ok: false, status: 500, json: async () => ({}) })),
    },
  );
  const fireState = (st: unknown) => stateListeners.forEach((cb) => cb(st));
  const press = (key: string, defaultPrevented = false) =>
    keyListeners.forEach((cb) => cb({ key, target: {}, defaultPrevented } as never));
  return {
    api,
    log,
    board,
    foot,
    count,
    dot,
    panel,
    body,
    mode,
    railMode,
    caseInput,
    fireState,
    press,
    written,
  };
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

describe("rail, open and full", () => {
  const proposal = (id: string, status: string) => ({
    id,
    turnId: "t1",
    kind: "question_new",
    questionId: "q1",
    status,
    after: { id: "q1", question: "Q?", status: "unknown", answer: "", pointer: "" },
  });
  const states = (p: FakeEl, b: FakeEl) => ({
    rail: p.classList.contains("watson-collapsed"),
    full: p.classList.contains("watson-fullscreen"),
    bodyRail: b.classList.contains("watson-rail-open"),
    bodyOpen: b.classList.contains("watson-panel-open"),
    bodyFull: b.classList.contains("watson-full-open"),
  });

  it("moves between the three states and persists each", () => {
    const { api, panel, body, written } = setup();
    api.initWatson();
    expect(states(panel, body)).toMatchObject({ rail: true, full: false, bodyRail: true });
    api.setWatsonPanelState("open");
    expect(states(panel, body)).toMatchObject({ rail: false, full: false, bodyOpen: true, bodyRail: false });
    expect(written[KEY]).toBe("open");
    api.setWatsonPanelState("full");
    expect(states(panel, body)).toMatchObject({ rail: false, full: true, bodyFull: true, bodyOpen: false });
    expect(written[KEY]).toBe("full");
    api.setWatsonPanelState("rail");
    expect(states(panel, body)).toMatchObject({ rail: true, full: false, bodyRail: true, bodyFull: false });
    expect(written[KEY]).toBe("rail");
    api.setWatsonPanelState("bogus");
    expect(written[KEY]).toBe("rail");
  });

  it("restores the stored state, and falls back to the rail for an unknown value", () => {
    const full = setup({ stored: { [KEY]: "full" } });
    full.api.initWatson();
    expect(full.panel.classList.contains("watson-fullscreen")).toBe(true);
    const odd = setup({ stored: { [KEY]: "sideways" } });
    odd.api.initWatson();
    expect(odd.panel.classList.contains("watson-collapsed")).toBe(true);
  });

  it("toggleWatsonPanel flips open and rail, and shows the pending count", () => {
    const { api, panel, count } = setup();
    api.initWatson();
    api.renderWatson(
      // p4's turn left the chat: it is not counted (F11)
      chatWith([{ id: "t1", at: "x", role: "watson", text: "hi" }], {
        proposals: [
          proposal("p1", "pending"),
          proposal("p2", "applied"),
          proposal("p3", "pending"),
          { ...proposal("p4", "pending"), turnId: "t-gone" },
        ],
      }),
    );
    api.toggleWatsonPanel();
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
    api.toggleWatsonPanel();
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
    expect(count.innerHTML).toBe("2");
  });

  it("Esc leaves full for open, and does nothing in the other states", () => {
    const { api, panel, press } = setup();
    api.initWatson();
    press("Escape");
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
    api.setWatsonPanelState("open");
    press("Escape");
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
    api.setWatsonPanelState("full");
    press("Escape");
    expect(panel.classList.contains("watson-fullscreen")).toBe(false);
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
  });

  it("Esc is ignored when another dialog already handled it, and while the panel is hidden", async () => {
    const a = setup();
    a.api.initWatson();
    a.api.setWatsonPanelState("full");
    a.press("Escape", true);
    expect(a.panel.classList.contains("watson-fullscreen")).toBe(true);
    const b = setup({ fetch: async () => response(200, { ...chatWith([]), providerConfigured: false }) });
    b.api.initWatson();
    b.api.setWatsonPanelState("full");
    await b.api.loadWatson("c1");
    b.press("Escape");
    expect(b.panel.classList.contains("watson-fullscreen")).toBe(true);
  });

  it("the full-screen offset follows the header height (ResizeObserver)", () => {
    const { api } = setup();
    headerBox.bottom = 80;
    api.initWatson();
    api.setWatsonPanelState("full");
    expect(rootVars["--watson-top"]).toBe("80px");
    headerBox.bottom = 132.4;
    observers.forEach((cb) => cb());
    expect(rootVars["--watson-top"]).toBe("132px");
  });

  it("falls back to the window resize event without ResizeObserver", () => {
    const { api } = setup({ noResizeObserver: true });
    headerBox.bottom = 60;
    api.initWatson();
    expect(rootVars["--watson-top"]).toBe("60px");
    headerBox.bottom = 90;
    resizeFns.forEach((cb) => cb());
    expect(rootVars["--watson-top"]).toBe("90px");
  });

  it("the header and rail verbs drive the states", () => {
    const { api, panel } = setup();
    api.initWatson();
    const verb = (wVerb: string) => api.watsonAct({ dataset: { wVerb } });
    verb("open");
    expect(panel.classList.contains("watson-collapsed")).toBe(false);
    verb("fullScreen");
    expect(panel.classList.contains("watson-fullscreen")).toBe(true);
    verb("exitFullScreen");
    expect(panel.classList.contains("watson-fullscreen")).toBe(false);
    verb("collapse");
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
  });

  it("lights the unread dot only while on the rail", () => {
    const { api, dot } = setup();
    api.initWatson();
    api.renderWatson(chatWith([]));
    api.renderWatson(chatWith([{ id: "t1", at: "x", role: "watson", text: "hi" }]));
    expect(dot.classList.contains("watson-on")).toBe(true);
    api.setWatsonPanelState("full");
    expect(dot.classList.contains("watson-on")).toBe(false);
  });

  it("a throwing localStorage still switches states, and the default is the rail", () => {
    const { api, panel } = setup({ throwingStorage: true });
    api.initWatson();
    expect(panel.classList.contains("watson-collapsed")).toBe(true);
    expect(() => api.setWatsonPanelState("full")).not.toThrow();
    expect(panel.classList.contains("watson-fullscreen")).toBe(true);
    api.toggleWatsonPanel();
    expect(panel.classList.contains("watson-fullscreen")).toBe(false);
  });

  it("every state is hidden when the server has no provider", async () => {
    const { api, panel, body } = setup({
      fetch: async () => response(200, { ...chatWith([]), providerConfigured: false }),
    });
    api.initWatson();
    await api.loadWatson("c1");
    for (const st of ["rail", "open", "full"]) {
      api.setWatsonPanelState(st);
      expect(panel.classList.contains("watson-hidden")).toBe(true);
      expect(body.classList.contains("watson-full-open")).toBe(false);
      expect(body.classList.contains("watson-panel-open")).toBe(false);
      expect(body.classList.contains("watson-rail-open")).toBe(false);
    }
  });

  it("full state shows the board (escaped) beside the chat", () => {
    const { api, board, fireState } = setup();
    api.initWatson();
    api.setWatsonPanelState("full");
    fireState({
      keyQuestions: [
        {
          id: "q1",
          question: "<img src=x onerror=1>",
          status: "partial",
          answer: "<b>a</b>",
          pointer: "",
          synthesisDisagrees: { status: "answered", answer: "<i>x</i>" },
        },
      ],
    });
    expect(board.innerHTML).toContain("&lt;img src=x onerror=1&gt;");
    expect(board.innerHTML).not.toContain("<img");
    expect(board.innerHTML).toContain("Synthesis disagrees");
    expect(board.innerHTML).toContain("q-status-partial");
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

describe("a refused Undo pressed in a section (F6)", () => {
  const refused = async (url: string, init?: { method?: string }) =>
    init?.method === "POST"
      ? {
          ok: false,
          status: 409,
          json: async () => ({ error: "Finding f-watson-1 changed since this proposal" }),
        }
      : { ok: true, status: 200, json: async () => chatWith([]) };

  function sectionUndo() {
    const inserted: { className: string; textContent: string; attrs: Record<string, string> }[] = [];
    const host = { querySelector: () => inserted[0] ?? null };
    const el = {
      dataset: { wVerb: "undo", pid: "wp-1" },
      closest: () => null, // not inside the Watson panel
      parentElement: host,
      insertAdjacentElement: (_where: string, node: (typeof inserted)[number]) => inserted.push(node),
    };
    return { el, inserted };
  }

  it("shows the server message in the panel notice and beside the section's Undo button", async () => {
    const { api, log } = setup({ fetch: refused });
    api.renderWatson(chatWith([]));
    const { el, inserted } = sectionUndo();
    await api.watsonAct(el);
    expect(log.innerHTML).toContain("Finding f-watson-1 changed since this proposal");
    expect(log.innerHTML).toContain("watson-warn");
    expect(inserted).toHaveLength(1);
    expect(inserted[0].className).toBe("watson-undo-msg");
    expect(inserted[0].textContent).toBe("Finding f-watson-1 changed since this proposal");
    expect(inserted[0].attrs.role).toBe("alert");
    await api.watsonAct(el); // a second refusal reuses the same message element
    expect(inserted).toHaveLength(1);
  });

  it("a refused Undo on a card in the panel keeps its message on the card only", async () => {
    const { api, log } = setup({ fetch: refused });
    api.renderWatson(chatWith([]));
    await api.watsonAct({ dataset: { wVerb: "undo", pid: "wp-1" }, closest: () => ({}) });
    expect(log.innerHTML).not.toContain("watson-warn");
  });
});

describe("rail button, failed sends and paste limits", () => {
  const html = ["dashboard-watson.js", "dashboard-watson-view.js", "dashboard-watson-mode.js"]
    .map((f) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8"))
    .join("\n");
  it("the rail is a real button that opens the panel; the header buttons are labelled", () => {
    expect(html).toMatch(
      /<button type="button" class="watson-rail"[^>]*data-w-verb="open" aria-expanded="false"/,
    );
    expect(html).not.toMatch(/role="button"/);
    expect(html).not.toContain('panel.setAttribute("aria-expanded"');
    expect(html).toMatch(/data-w-verb="collapse" aria-expanded="true" aria-label="Collapse Watson"/);
    expect(html).toMatch(/data-w-verb="fullScreen" aria-expanded="false" aria-label="Full screen"/);
    expect(html).toMatch(/data-w-verb="exitFullScreen" aria-expanded="true" aria-label="Exit full screen"/);
    expect(html).toContain('data-w="board"');
    expect(html).toContain('data-w="log"');
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

  it("no built-in view lists sec-watson or sec-ask, and a saved view that lists them loses them", async () => {
    const { BUILT_IN_DASHBOARD_VIEWS, DASHBOARD_SECTION_IDS, normalizeDashboardView } =
      await import("../../src/analysis/dashboardViews.js");
    expect(BUILT_IN_DASHBOARD_VIEWS.some((v) => v.sections.includes("sec-watson"))).toBe(false);
    expect(BUILT_IN_DASHBOARD_VIEWS.some((v) => v.sections.includes("sec-ask"))).toBe(false);
    expect(DASHBOARD_SECTION_IDS).not.toContain("sec-ask");
    expect(DASHBOARD_SECTION_IDS).not.toContain("sec-watson");
    const saved = normalizeDashboardView({
      id: "mine",
      name: "Mine",
      sections: ["sec-ask", "sec-watson", "sec-now"],
    });
    expect(saved.sections).toEqual(["sec-now"]);
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
    const { api, panel } = setup({ stored: { [KEY]: "open" } });
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
  it("sec-watson is gone from the markup, SECTION_DEFS and DASHBOARD_SECTION_IDS", () => {
    expect(html).not.toContain('id="sec-watson"');
    expect(html).not.toContain("sec-watson");
    expect(html).not.toContain('id="watsonSection"');
    expect(DASHBOARD_SECTION_IDS).not.toContain("sec-watson");
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

describe("a free-form answer in the Watson log", () => {
  const answerTurn = (extra: Record<string, unknown> = {}) => ({
    id: "wt-9",
    at: "x",
    role: "watson",
    text: "Here is what the case shows.",
    answer: {
      question: "Which <b>host</b>?",
      status: "partial",
      answer: "<img src=x onerror=1> HOST-A",
      pointer: "<script>1</script> the PowerShell log",
      relatedEventIds: ["e1", "e2"],
    },
    ...extra,
  });

  it("shows the badge, the answer, the pointer and the cited events, all escaped", () => {
    const { api, log } = setup();
    api.renderWatson(chatWith([answerTurn()]));
    expect(log.innerHTML).toContain("q-status-partial");
    expect(log.innerHTML).toContain("&lt;img src=x onerror=1&gt; HOST-A");
    expect(log.innerHTML).toContain("where to look: &lt;script&gt;1&lt;/script&gt; the PowerShell log");
    expect(log.innerHTML).toContain("Which &lt;b&gt;host&lt;/b&gt;?");
    expect(log.innerHTML).not.toContain("<img");
    expect(log.innerHTML).not.toContain("<script>");
    expect(log.innerHTML).toContain("[cited e1] [cited e2]");
    expect(log.innerHTML).toContain('data-w-verb="addQuestion"');
    expect(log.innerHTML).toContain('data-tid="wt-9"');
    expect(log.innerHTML).not.toContain(" disabled");
  });

  it("disables Add to open questions once the answer was added", () => {
    const { api, log } = setup();
    api.renderWatson(chatWith([answerTurn({ answerProposalId: "wp-1" })]));
    expect(log.innerHTML).toMatch(/data-w-verb="addQuestion"[^>]* disabled/);
  });

  it("shows no answer card on a turn without an answer", () => {
    const { api, log } = setup();
    api.renderWatson(chatWith([{ id: "t", at: "x", role: "watson", text: "hi" }]));
    expect(log.innerHTML).not.toContain("addQuestion");
  });

  it("shows the coverage line only when the timeline was trimmed", () => {
    const { api, log } = setup();
    api.renderWatson(chatWith([answerTurn({ coverage: { usedEvents: 120, eventCount: 5000 } })]));
    expect(log.innerHTML).toContain(
      "answered from 120 of 5000 in-scope events — the timeline was trimmed to fit the model",
    );
    api.renderWatson(chatWith([answerTurn()]));
    expect(log.innerHTML).not.toContain("in-scope events");
    api.renderWatson(
      chatWith([answerTurn({ coverage: { usedEvents: 50, eventCount: 50, headTrimmed: true } })]),
    );
    expect(log.innerHTML).not.toContain("in-scope events");
  });

  it("discloses trimmed case decisions and a trimmed case summary on their own lines", () => {
    const { api, log } = setup();
    api.renderWatson(
      chatWith([answerTurn({ coverage: { usedEvents: 9, eventCount: 9, decisionsTrimmed: true } })]),
    );
    expect(log.innerHTML).toContain(
      "some of your case decisions — hypotheses, scope, marks, notebook — were trimmed to fit the model",
    );
    expect(log.innerHTML).not.toContain("case summary was trimmed");
    api.renderWatson(
      chatWith([answerTurn({ coverage: { usedEvents: 9, eventCount: 9, headTrimmed: true } })]),
    );
    expect(log.innerHTML).toContain("part of the case summary was trimmed to fit the model");
    expect(log.innerHTML).not.toContain("case decisions");
  });

  it("Add to open questions posts to the turn, then refreshes the chat and the board", async () => {
    const calls: string[] = [];
    const q = { id: "wq-1", question: "ADDED QUESTION", status: "partial", answer: "", pointer: "" };
    const fetch = async (url: string, init?: { method?: string }) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      return response(200, {
        chat: chatWith([answerTurn({ answerProposalId: "wp-1" })]),
        state: { keyQuestions: [q] },
      });
    };
    const { api, log, board } = setup({ fetch });
    api.renderWatson(chatWith([answerTurn()]));
    await api.watsonAct({ dataset: { wVerb: "addQuestion", tid: "wt-9" } });
    expect(calls).toEqual(["POST /cases/c1/watson/turns/wt-9/add-question"]);
    expect(board.innerHTML).toContain("ADDED QUESTION");
    expect(log.innerHTML).toMatch(/data-w-verb="addQuestion"[^>]* disabled/);
  });

  it("New thread posts and shows the system turn", async () => {
    const calls: string[] = [];
    const fetch = async (url: string, init?: { method?: string }) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      return response(
        200,
        chatWith([
          { id: "s", at: "x", role: "system", text: "New thread — Watson starts from its case memory" },
        ]),
      );
    };
    const { api, log } = setup({ fetch });
    api.renderWatson(chatWith([]));
    await api.watsonAct({ dataset: { wVerb: "newThread" } });
    expect(calls).toEqual(["POST /cases/c1/watson/new-thread"]);
    expect(log.innerHTML).toContain("New thread — Watson starts");
  });

  it("has a New thread button in the composer", () => {
    const html = readFileSync(
      new URL("../../../public/js/dashboard-watson-view.js", import.meta.url),
      "utf8",
    );
    expect(html).toContain('data-w-verb="newThread"');
  });
});

describe("the empty-case hint in the Watson log", () => {
  it("shows when the log is empty and the case has no forensic events and no findings", () => {
    const { api, log, fireState } = setup();
    api.initWatson();
    api.renderWatson(chatWith([]));
    fireState({ forensicTimelineTotal: 0, findings: [] });
    expect(log.innerHTML).toContain("No forensic-timeline events or findings yet");
    fireState({ forensicTimelineTotal: 12, findings: [] });
    expect(log.innerHTML).not.toContain("No forensic-timeline events or findings yet");
    fireState({ forensicTimeline: [], findings: [{ id: "f1" }] });
    expect(log.innerHTML).not.toContain("No forensic-timeline events or findings yet");
    fireState({ forensicTimelineTotalIsLowerBound: true, forensicTimelineTotal: 0, findings: [] });
    expect(log.innerHTML).not.toContain("No forensic-timeline events or findings yet");
  });

  it("is not shown once the log has turns", () => {
    const { api, log, fireState } = setup();
    api.initWatson();
    api.renderWatson(chatWith([{ id: "t", at: "x", role: "watson", text: "hi" }]));
    fireState({ forensicTimelineTotal: 0, findings: [] });
    expect(log.innerHTML).not.toContain("No forensic-timeline events or findings yet");
  });
});

describe("Load earlier messages", () => {
  const t = (id: string, text: string, extra: Record<string, unknown> = {}) => ({
    id,
    at: "x",
    role: "watson",
    text,
    ...extra,
  });

  it("shows the button only when the chat is at its cap or the server said more remain", () => {
    const { api, log } = setup();
    api.renderWatson(chatWith([t("t1", "hi")]));
    expect(log.innerHTML).not.toContain("Load earlier messages");
    api.renderWatson(chatWith(Array.from({ length: 400 }, (_, i) => t(`t${i}`, "m"))));
    expect(log.innerHTML).toContain("Load earlier messages");
    expect(log.innerHTML).toContain('data-w-verb="loadEarlier"');
  });

  it("asks for the page before the oldest turn and renders it read-only, escaped, with no buttons", async () => {
    const calls: string[] = [];
    const page = {
      turns: [
        t("o1", "<b>old</b>", {
          answer: { question: "q", status: "answered", answer: "a", pointer: "", relatedEventIds: [] },
          proposalIds: ["p1"],
        }),
      ],
      more: false,
    };
    const { api, log } = setup({
      fetch: async (url: string) => {
        calls.push(url);
        return response(200, page);
      },
    });
    api.renderWatson(chatWith(Array.from({ length: 400 }, (_, i) => t(`t${i}`, "m"))));
    await (api.watsonAct({ dataset: { wVerb: "loadEarlier" } }) as Promise<void>);
    expect(calls).toEqual(["/cases/c1/watson/history?before=t0&limit=100"]);
    expect(log.innerHTML).toContain("&lt;b&gt;old&lt;/b&gt;");
    expect(log.innerHTML).not.toContain("<b>old</b>");
    expect(log.innerHTML).not.toContain("Add to open questions");
    expect(log.innerHTML).not.toContain("Load earlier messages"); // more: false
  });
});

describe("the Watson reaction delay setting (F15)", () => {
  it("says in the dashboard and the manual that each reaction is a full round that counts toward the limits", () => {
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const field =
      /<div class="sfield"><label for="env-DFIR_AI_WATSON_REACT_DELAY_SEC">[\s\S]*?<\/div>/.exec(html)?.[0] ??
      "";
    expect(field).toContain("Each reaction is a full Watson round with the case context");
    expect(field).toContain("counts toward the Watson cost and token limits");
    const manual = readFileSync(
      new URL("../../../mkdocs-docs/reference/settings.md", import.meta.url),
      "utf8",
    );
    expect(manual).toContain("Each reaction is a full Watson round with the case context");
    expect(manual).toContain("counts toward the Watson cost and token limits");
  });
});

describe("run mode switch", () => {
  const modeFetch =
    (calls: string[], mode: string, ok = true) =>
    async (url: string, init?: { method?: string; body?: string }) => {
      calls.push(`${init?.method ?? "GET"} ${url} ${init?.body ?? ""}`.trim());
      return init?.method === "POST"
        ? response(ok ? 200 : 423, ok ? { mode } : { error: "case is closed" })
        : response(200, chatWith([], { runMode: "approve" }));
    };
  const press = (api: Api, mode: string) => api.watsonAct({ dataset: { wVerb: "setMode", mode } });

  it("renders Approve and Auto in the header, Approve on, and no 'A' on the rail", () => {
    const { api, mode, railMode } = setup();
    api.initWatson();
    expect(mode.innerHTML).toContain('data-w-verb="setMode" data-mode="approve" aria-pressed="true"');
    expect(mode.innerHTML).toContain('data-mode="auto" aria-pressed="false"');
    expect(mode.innerHTML).not.toMatch(/ on[a-z]+=|style=/);
    expect(railMode.innerHTML).toBe("");
  });

  it("follows the case's runMode from the server and shows 'A' on the rail for Auto", () => {
    const { api, mode, railMode } = setup();
    api.initWatson();
    api.renderWatson(chatWith([], { runMode: "auto" }));
    expect(mode.innerHTML).toContain('data-mode="auto" aria-pressed="true"');
    expect(railMode.innerHTML).toContain(">A<");
    api.renderWatson(chatWith([])); // a POST reply carries no runMode: the mode stays
    expect(railMode.innerHTML).toContain(">A<");
    api.renderWatson(chatWith([], { runMode: "junk" }));
    expect(railMode.innerHTML).toContain(">A<");
    api.renderWatson(chatWith([], { runMode: "approve" }));
    expect(railMode.innerHTML).toBe("");
  });

  it("asks in plain words before Auto and does nothing when declined", async () => {
    const asked: string[] = [];
    const calls: string[] = [];
    const { api, railMode } = setup({
      fetch: modeFetch(calls, "auto"),
      confirm: (t) => (asked.push(t), false),
    });
    api.initWatson();
    await press(api, "auto");
    expect(asked).toEqual([
      "Watson will run single-host collections and write to the case without asking. Fleet-wide hunts still ask.",
    ]);
    expect(calls).toEqual([]);
    expect(railMode.innerHTML).toBe("");
  });

  it("switches to Auto after a yes, and back to Approve without asking", async () => {
    const asked: string[] = [];
    const calls: string[] = [];
    let next = "auto";
    const fetch = async (url: string, init?: { method?: string; body?: string }) => {
      calls.push(`${init?.method} ${url} ${init?.body}`);
      return response(200, { mode: next });
    };
    const { api, mode, railMode } = setup({ fetch, confirm: (t) => (asked.push(t), true) });
    api.initWatson();
    await press(api, "auto");
    expect(calls).toEqual(['POST /cases/c1/watson/mode {"mode":"auto"}']);
    expect(railMode.innerHTML).toContain(">A<");
    expect(mode.innerHTML).toContain('data-mode="auto" aria-pressed="true"');
    next = "approve";
    await press(api, "approve");
    expect(asked).toHaveLength(1);
    expect(railMode.innerHTML).toBe("");
  });

  it("tells the analyst when the server refuses and keeps the old mode", async () => {
    const alerts: string[] = [];
    const { api, railMode } = setup({ fetch: modeFetch([], "auto", false), alert: (t) => alerts.push(t) });
    api.initWatson();
    await press(api, "auto");
    expect(alerts).toEqual(["Could not switch Watson's mode: case is closed"]);
    expect(railMode.innerHTML).toBe("");
  });

  it("ignores a mode it does not know", async () => {
    const calls: string[] = [];
    const { api } = setup({ fetch: modeFetch(calls, "auto") });
    api.initWatson();
    await press(api, "fleet");
    expect(calls).toEqual([]);
  });
});
