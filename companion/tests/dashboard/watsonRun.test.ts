// Task 7: Watson's running state in the dashboard: the working line for every viewer, the stop icon,
// and the per-send Idempotency-Key. Runs the real modules in a vm context with a small fake DOM.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderWatson(chat: unknown): void;
  watsonAct(el: unknown): unknown;
  watsonSendKey(caseId: string, text: string): string;
}

class FakeEl {
  innerHTML = "";
  hidden = true;
  classList = { toggle: () => true, contains: () => false };
  setAttribute() {}
}

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
}
type Answer = unknown;

const chatWith = (turns: unknown[] = [], extra: Record<string, unknown> = {}) => ({
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
const okChat = { ok: true, status: 200, json: async () => chatWith() };
const httpAnswer = (status: number, error = "x") => ({ ok: false, status, json: async () => ({ error }) });

function setup(answers: (call: Call) => Answer | Promise<Answer>) {
  const log = new FakeEl();
  const stop = new FakeEl();
  const byW: Record<string, FakeEl[]> = { log: [log], stop: [stop] };
  const caseInput = { value: "c1" };
  const calls: Call[] = [];
  const document = {
    body: new FakeEl(),
    documentElement: { style: { setProperty: () => {} } },
    querySelector: () => null,
    getElementById: (id: string) => (id === "caseId" ? caseInput : null),
    querySelectorAll: (sel: string) => byW[/data-w="(\w+)"/.exec(sel)?.[1] ?? ""] ?? [],
    addEventListener: () => {},
  };
  const fetchSpy = async (url: string, init: { method?: string; headers?: Record<string, string> } = {}) => {
    const call = { url, method: init.method ?? "GET", headers: init.headers ?? {} };
    calls.push(call);
    const a = await answers(call);
    if (a instanceof Error) throw a;
    return a;
  };
  const api = loadDashboardModule<Api>(
    "dashboard-watson.js",
    [
      "dashboard-escape.js",
      "dashboard-watson-marks.js",
      "dashboard-watson-cards.js",
      "dashboard-watson-view.js",
      "dashboard-watson-mode.js",
      "dashboard-watson-run.js",
      "dashboard-watson-velo.js",
    ],
    {
      document,
      confirm: () => true,
      alert: () => {},
      DfirState: { onLastStateChange: () => {} },
      citeEvents: () => "",
      localStorage: { getItem: () => null, setItem: () => {} },
      addEventListener: () => {},
      fetch: fetchSpy,
    },
  );
  const input = { value: "" };
  const sendEl = { dataset: { wVerb: "send" }, closest: () => ({ querySelector: () => input }) };
  const send = async (text: string) => {
    input.value = text;
    await api.watsonAct(sendEl);
  };
  const messageCalls = () => calls.filter((c) => c.url.endsWith("/message"));
  const keys = () => messageCalls().map((c) => c.headers["Idempotency-Key"]);
  return { api, log, stop, caseInput, calls, input, send, keys };
}

const running = (extra: Record<string, unknown> = {}) => ({
  since: "2026-11-15T10:00:00Z",
  kind: "analyst",
  queued: 0,
  ...extra,
});

describe("the working line and the stop icon", () => {
  it("another viewer's running round shows the working line with the escaped actor, and the stop icon", () => {
    const { api, log, stop } = setup(() => okChat);
    api.renderWatson(chatWith([], { running: running({ actor: "<b>fake.user</b>" }) }));
    expect(log.innerHTML).toContain("Watson is working on a message from &lt;b&gt;fake.user&lt;/b&gt;.");
    expect(log.innerHTML).not.toContain("<b>fake.user");
    expect(stop.hidden).toBe(false);
  });

  it("no run and no local send: no working line and the stop icon is hidden", () => {
    const { api, log, stop } = setup(() => okChat);
    api.renderWatson(chatWith([], { running: null }));
    expect(log.innerHTML).not.toContain("watson-working");
    expect(stop.hidden).toBe(true);
  });

  it("names a reaction round, the plain case and the queue", () => {
    const { api, log } = setup(() => okChat);
    api.renderWatson(chatWith([], { running: running({ kind: "reaction" }) }));
    expect(log.innerHTML).toContain("Watson is working on the new case events.");
    api.renderWatson(chatWith([], { running: running({ queued: 2 }) }));
    expect(log.innerHTML).toContain("Watson is working on an answer. 2 more messages wait.");
  });

  it("the stop verb POSTs /cancel even while this tab's send is in flight", async () => {
    const { api, send, calls } = setup((c) =>
      c.url.endsWith("/message") ? new Promise(() => {}) : { ok: true, status: 200 },
    );
    void send("hello");
    await new Promise((r) => setTimeout(r, 0));
    await api.watsonAct({ dataset: { wVerb: "stop" } });
    const cancel = calls.find((c) => c.url === "/cases/c1/watson/cancel");
    expect(cancel?.method).toBe("POST");
  });

  it("a refused stop shows the server's text in the log", async () => {
    const { api, log } = setup(() => httpAnswer(423, "The case is closed."));
    api.renderWatson(chatWith());
    await api.watsonAct({ dataset: { wVerb: "stop" } });
    expect(log.innerHTML).toContain("The case is closed.");
  });
});

describe("the Idempotency-Key", () => {
  const SHAPE = /^[A-Za-z0-9_-]{8,64}$/;

  it("a resend after a network failure reuses the key; after an HTTP answer the key is new", async () => {
    let n = 0; // counts /message calls only: a failed send also triggers a GET refresh
    const { send, keys } = setup((c) => {
      if (!c.url.endsWith("/message")) return okChat;
      return ++n <= 2 ? new TypeError("fetch failed") : httpAnswer(500);
    });
    await send("same text");
    await send("same text");
    await send("same text");
    await send("same text");
    const k = keys();
    expect(k[0]).toMatch(SHAPE);
    expect(k[1]).toBe(k[0]); // lost response: same request
    expect(k[2]).toBe(k[0]); // the 2nd was also lost
    expect(k[3]).not.toBe(k[2]); // the 3rd got a readable 500, so the next send is new
  });

  it("different text gets a new key", async () => {
    const { send, keys } = setup(() => new TypeError("fetch failed"));
    await send("a");
    await send("b");
    expect(keys()[1]).not.toBe(keys()[0]);
  });

  it("an OK response whose body cannot be read keeps the key for the resend", async () => {
    const { send, keys, input } = setup(() => ({
      ok: true,
      status: 200,
      json: () => Promise.reject(new SyntaxError("bad")),
    }));
    await send("same text");
    expect(input.value).toBe("same text"); // put back for the resend
    await send("same text");
    expect(keys()[1]).toBe(keys()[0]);
  });

  it("a completion in case c2 does not clear case c1's pending key", async () => {
    let fail = true;
    const { send, keys, caseInput } = setup(() => (fail ? new TypeError("fetch failed") : okChat));
    await send("hello");
    caseInput.value = "c2";
    fail = false;
    await send("other");
    caseInput.value = "c1";
    fail = true;
    await send("hello");
    const k = keys();
    expect(k[2]).toBe(k[0]);
    expect(k[1]).not.toBe(k[0]);
  });

  it("a 429 answer drops the key and puts the text back", async () => {
    const { send, keys, input } = setup(() => httpAnswer(429, "Watson has too many messages."));
    await send("hello");
    expect(input.value).toBe("hello");
    await send("hello");
    expect(keys()[1]).not.toBe(keys()[0]);
  });

  it("a 409 Presidio hold is a readable answer: the next send gets a new key", async () => {
    const { send, keys } = setup(() => ({
      ok: false,
      status: 409,
      json: async () => ({ error: "presidio_approval_required", findings: [] }),
    }));
    await send("hello");
    await send("hello");
    expect(keys()[1]).not.toBe(keys()[0]);
  });

  it("the fallback key (no crypto.randomUUID) matches the server's pattern", () => {
    const { api } = setup(() => okChat);
    expect(api.watsonSendKey("c9", "t")).toMatch(SHAPE);
  });
});

describe("source text", () => {
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8").replace(/\r\n/g, "\n");

  it("the stop icon is an icon button with a label", () => {
    const src = read("../../../public/js/dashboard-watson-view.js");
    expect(src).toMatch(
      /class="watson-icon-btn watson-stop" data-w="stop"[^>]*aria-label="Stop Watson"[^>]*hidden>/,
    );
  });

  it("the CSS hides a hidden icon button", () => {
    expect(read("../../../public/css/dashboard-watson.css")).toMatch(
      /\.watson-icon-btn\[hidden\]\s*\{\s*display:\s*none/,
    );
  });

  it("dashboard-watson.js stays within 400 lines", () => {
    expect(read("../../../public/js/dashboard-watson.js").split("\n").length - 1).toBeLessThanOrEqual(400);
  });
});
