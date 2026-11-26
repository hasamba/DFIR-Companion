// #2943: Watson's dashboard answers follow the #2940 owner-change pattern. A -> B where B never runs
// Watson's loader (a cancelled, failed or quickly-abandoned open), then back to A — or a cancel and a
// reopen of A — must not paint an answer from the first visit to A. A reload of the same case while a
// request runs still paints it. The reset hook (DfirPanelDefer.onReset) moves the owner at the switch.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderWatson(chat?: unknown): void;
  watsonAct(el: unknown): unknown;
  loadWatson(caseId: string | null, onlyIfNew?: boolean): Promise<void>;
  initWatson(): void;
}

interface Req {
  url: string;
  method: string;
  headers: Record<string, string>;
  answer(status: number, body: unknown, extraHeaders?: Record<string, string>): void;
  fail(): void;
}

class FakeEl {
  innerHTML = "";
  hidden = false;
  disabled = false;
  textContent = "";
  classList = { toggle: () => true, contains: () => false, remove: () => {} };
  setAttribute() {}
}

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
const turn = (id: string, text: string) => ({ id, role: "watson", text, at: "2026-01-01T00:00:00Z" });
const drain = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

function setup() {
  const log = new FakeEl();
  const stop = new FakeEl();
  const mirrors = new FakeEl();
  const byW: Record<string, FakeEl[]> = { log: [log], stop: [stop], mirrors: [mirrors] };
  const caseInput = { value: "CASE-A" };
  const requests: Req[] = [];
  const resets: Array<(c: string | null) => void> = [];
  const alerts: string[] = [];
  const panelClasses = new Set<string>();
  const panel = Object.assign(new FakeEl(), {
    classList: {
      toggle: (c: string, on: boolean) => (on ? panelClasses.add(c) : panelClasses.delete(c), on),
    },
    querySelector: () => null,
  });
  const document = {
    body: new FakeEl(),
    documentElement: { style: { setProperty: () => {} } },
    querySelector: () => null,
    getElementById: (id: string) => (id === "caseId" ? caseInput : id === "watsonPanel" ? panel : null),
    querySelectorAll: (sel: string) => byW[/data-w="(\w+)"/.exec(sel)?.[1] ?? ""] ?? [],
    addEventListener: () => {},
  };
  const fetchSpy = (url: string, init: { method?: string; headers?: Record<string, string> } = {}) =>
    new Promise((resolve, reject) => {
      requests.push({
        url,
        method: init.method ?? "GET",
        headers: init.headers ?? {},
        answer: (status, body, extraHeaders = {}) =>
          resolve({
            ok: status >= 200 && status < 300,
            status,
            headers: { get: (k: string) => extraHeaders[k] ?? null },
            json: async () => body,
          }),
        fail: () => reject(new Error("network down")),
      });
    });
  const api = loadDashboardModule<Api>(
    "dashboard-watson.js",
    [
      "dashboard-escape.js",
      "dashboard-watson-marks.js",
      "dashboard-watson-cards.js",
      "dashboard-watson-qchange.js",
      "dashboard-watson-view.js",
      "dashboard-watson-mode.js",
      "dashboard-watson-run.js",
      "dashboard-watson-status.js",
      "dashboard-watson-velo.js",
      "dashboard-watson-mirror.js",
      "dashboard-watson-layout.js",
    ],
    {
      document,
      confirm: () => true,
      alert: (t: string) => alerts.push(t),
      DfirState: { onLastStateChange: () => {} },
      DfirPanelDefer: { onReset: (fn: (c: string | null) => void) => resets.push(fn) },
      citeEvents: () => "",
      localStorage: { getItem: () => null, setItem: () => {} },
      addEventListener: () => {},
      fetch: fetchSpy,
      setInterval: () => 0,
      clearInterval: () => {},
      crypto: {
        randomUUID: (() => {
          let n = 0;
          return () => `key-${++n}-0000-0000`;
        })(),
      },
    },
  );
  api.initWatson();
  /** A full case open: the reset listeners run, the case input changes. Watson's loader does not run. */
  const open = (c: string | null) => {
    caseInput.value = c ?? "";
    for (const fn of resets) fn(c);
  };
  const input = { value: "" };
  const root = { querySelector: () => input };
  const sendEl = { dataset: { wVerb: "send" }, closest: () => root };
  const send = (text: string) => {
    input.value = text;
    return api.watsonAct(sendEl) as Promise<void> | undefined;
  };
  const pending = (path: string) => requests.filter((r) => r.url.endsWith(path));
  const lastReq = (path: string) => pending(path)[pending(path).length - 1];
  /** Load A's chat (owner A). */
  async function loadA() {
    const p = api.loadWatson("CASE-A");
    lastReq("/cases/CASE-A/watson").answer(200, chatWith([turn("t0", "hello")]));
    await p;
  }
  return {
    api,
    log,
    stop,
    mirrors,
    panelClasses,
    caseInput,
    requests,
    resets,
    open,
    send,
    input,
    pending,
    lastReq,
    loadA,
    alerts,
  };
}

describe("Watson answers after a case switch (#2943)", () => {
  it("registers its reset hook with DfirPanelDefer", () => {
    expect(setup().resets.length).toBeGreaterThan(0);
  });

  it("A -> B (no Watson load) -> A: the first visit's answer paints nothing and the busy mark is freed at B", async () => {
    const s = setup();
    await s.loadA();
    const sent = s.send("first visit question");
    expect(s.stop.hidden).toBe(false); // busy on A
    s.open("CASE-B");
    expect(s.stop.hidden, "B's open left A's request showing as busy").toBe(true);
    s.open("CASE-A");
    s.lastReq("/message").answer(200, chatWith([turn("old", "STALE ANSWER")]));
    await sent;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE ANSWER");
  });

  it("a send before A's chat has loaded: B opening still hides the stop icon", async () => {
    const s = setup();
    s.open("CASE-A");
    void s.send("early question");
    expect(s.stop.hidden).toBe(false);
    s.open("CASE-B");
    expect(s.stop.hidden, "the stop icon stayed for A's request").toBe(true);
  });

  it("A -> B -> A: a new send works at once, and the old request ending does not clear its busy mark", async () => {
    const s = setup();
    await s.loadA();
    const first = s.send("first visit");
    s.open("CASE-B");
    s.open("CASE-A");
    const second = s.send("second visit");
    expect(s.pending("/message").length, "the old request blocked the new send").toBe(2);
    s.pending("/message")[0].answer(200, chatWith([turn("old", "STALE")]));
    await first;
    await drain();
    expect(s.stop.hidden, "the old request's end cleared the new request's busy mark").toBe(false);
    s.pending("/message")[1].answer(200, chatWith([turn("new", "FRESH ANSWER")]));
    await second;
    await drain();
    expect(s.log.innerHTML).toContain("FRESH ANSWER");
    expect(s.log.innerHTML).not.toContain("STALE");
  });

  it("the old send settling does not drop the new send's retry key", async () => {
    const s = setup();
    await s.loadA();
    const first = s.send("first question");
    s.open("CASE-B");
    s.open("CASE-A");
    const second = s.send("question");
    const newKey = s.pending("/message")[1].headers["Idempotency-Key"];
    s.pending("/message")[0].answer(200, chatWith());
    await first;
    s.pending("/message")[1].fail(); // the new send's answer is lost
    await second;
    await drain();
    const third = s.send("question");
    expect(s.pending("/message")[2].headers["Idempotency-Key"]).toBe(newKey);
    s.pending("/message")[2].answer(200, chatWith());
    await third;
  });

  it("a cancel and a reopen of the same case drop the first visit's answer", async () => {
    const s = setup();
    await s.loadA();
    const sent = s.send("before the cancel");
    s.open(null);
    s.open("CASE-A");
    s.lastReq("/message").answer(200, chatWith([turn("old", "STALE ANSWER")]));
    await sent;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE ANSWER");
  });

  it("a reload of the same case while a request runs still paints its answer", async () => {
    const s = setup();
    await s.loadA();
    const sent = s.send("same case");
    s.open("CASE-A");
    void s.api.loadWatson("CASE-A", true);
    s.lastReq("/message").answer(200, chatWith([turn("new", "FRESH ANSWER")]));
    await sent;
    await drain();
    expect(s.log.innerHTML).toContain("FRESH ANSWER");
  });

  it("after the reset hook opens B, B's first load still reads its chat", async () => {
    const s = setup();
    await s.loadA();
    s.open("CASE-B");
    const before = s.pending("/cases/CASE-B/watson").length;
    void s.api.loadWatson("CASE-B", true);
    expect(s.pending("/cases/CASE-B/watson").length).toBe(before + 1);
    s.lastReq("/cases/CASE-B/watson").answer(200, chatWith([turn("b1", "B CHAT")]));
    await drain();
    expect(s.log.innerHTML).toContain("B CHAT");
  });

  it("a first-visit chat read answering after A -> B -> A paints nothing (a 501 too)", async () => {
    const s = setup();
    const old = s.api.loadWatson("CASE-A");
    s.open("CASE-B");
    s.open("CASE-A");
    s.pending("/cases/CASE-A/watson")[0].answer(200, chatWith([turn("old", "STALE CHAT")]));
    await old;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE CHAT");
    const old2 = s.api.loadWatson("CASE-A");
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/cases/CASE-A/watson").answer(501, {});
    await old2;
    await drain();
    expect(s.panelClasses.has("watson-hidden"), "a first-visit 501 hid the panel").toBe(false);
  });

  it("a proposal decision from the first visit paints nothing after A -> B -> A", async () => {
    const s = setup();
    await s.loadA();
    const el = { dataset: { wVerb: "apply", pid: "p1" }, closest: () => null };
    const done = s.api.watsonAct(el) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/proposals/p1/apply").answer(200, { chat: chatWith([turn("old", "STALE DECISION")]) });
    await done;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE DECISION");
  });

  it("a launch resolve from the first visit paints nothing after A -> B -> A, nor its error", async () => {
    const s = setup();
    await s.loadA();
    let shown = "";
    const host = {
      querySelector: () => ({
        set textContent(t: string) {
          shown = t;
        },
      }),
    };
    const el = { dataset: { wVerb: "resolveLaunch", pid: "p1", outcome: "launched" }, parentElement: host };
    const done = s.api.watsonAct(el) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/proposals/p1/resolve").answer(200, { chat: chatWith([turn("old", "STALE RESOLVE")]) });
    await done;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE RESOLVE");
    const failed = s.api.watsonAct(el) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/proposals/p1/resolve").answer(500, { error: "boom" });
    await failed;
    await drain();
    expect(shown).toBe("");
  });

  it("a risky launch from the first visit does not release the new visit's launch lock", async () => {
    const s = setup();
    await s.loadA();
    const el = () => ({ dataset: { wVerb: "applyRisk", pid: "p1" }, disabled: false, parentElement: null });
    const first = s.api.watsonAct(el()) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    const second = s.api.watsonAct(el()) as Promise<void>;
    expect(s.pending("/proposals/p1/apply").length).toBe(2);
    s.pending("/proposals/p1/apply")[0].answer(200, { chat: chatWith() });
    await first;
    await drain();
    void s.api.watsonAct(el()); // the lock of the second, still running, holds
    expect(s.pending("/proposals/p1/apply").length, "the old launch's end released the new lock").toBe(2);
    s.pending("/proposals/p1/apply")[1].answer(200, { chat: chatWith() });
    await second;
  });

  it("a stop from the first visit neither blocks a new stop nor shows its message", async () => {
    const s = setup();
    await s.loadA();
    const stopEl = { dataset: { wVerb: "stop" } };
    const first = s.api.watsonAct(stopEl) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    const second = s.api.watsonAct(stopEl) as Promise<void>;
    expect(s.pending("/watson/cancel").length, "the old stop blocked a new one").toBe(2);
    s.pending("/watson/cancel")[0].answer(500, { error: "STALE STOP TEXT" });
    await first;
    await drain();
    expect(s.log.innerHTML).not.toContain("STALE STOP TEXT");
    s.pending("/watson/cancel")[1].answer(200, {});
    await second;
  });

  it("a mirror list read from the first visit paints nothing after A -> B -> A", async () => {
    const s = setup();
    await s.loadA(); // the chat read starts the mirror list read
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/watson/mirrors").answer(200, { mirrors: [{ chatId: 4242, chatType: "group" }] });
    await drain();
    expect(s.mirrors.innerHTML).not.toContain("4242");
  });

  it("a mode switch from the first visit shows no alert after A -> B -> A", async () => {
    const s = setup();
    await s.loadA();
    const el = { dataset: { wVerb: "setMode", mode: "auto" } };
    const done = s.api.watsonAct(el) as Promise<void>;
    s.open("CASE-B");
    s.open("CASE-A");
    s.lastReq("/watson/mode").answer(500, { error: "STALE MODE" });
    await done;
    await drain();
    expect(s.alerts.join(" ")).not.toContain("STALE MODE");
  });
});
