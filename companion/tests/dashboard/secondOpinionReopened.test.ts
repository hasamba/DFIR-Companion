import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1972 — an accepted decision the primary model's new call contradicts is shown like the
// "not applied" marker: a count in the head, a block with Keep / Drop, and a row status.

interface Api {
  initSecondOpinion(): void;
  renderSecondOpinion(rec: unknown): void;
  loadSecondOpinion(caseId: string): void;
  scheduleSecondOpinionReload(caseId: string): void;
}

interface FakeEl {
  value: string;
  textContent: string;
  innerHTML: string;
  disabled: boolean;
  style: Record<string, string>;
  onclick: unknown;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelectorAll(): FakeEl[];
}

function makeEl(): FakeEl {
  const handlers: Record<string, ((e: unknown) => void)[]> = {};
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    disabled: false,
    style: {},
    onclick: null,
    addEventListener: (type, fn) => {
      (handlers[type] ||= []).push(fn);
    },
    fire: (type, ev) => (handlers[type] || []).forEach((f) => f(ev ?? {})),
    querySelectorAll: () => [],
  };
}

function harness() {
  const calls: { url: string; body: string }[] = [];
  const replies: unknown[] = [];
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id)) els.set(id, makeEl());
    return els.get(id) as FakeEl;
  };
  const timers: (() => void)[] = [];
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: () => true,
    render: () => {},
    setTimeout: (fn: () => void) => timers.push(fn),
    clearTimeout: () => timers.splice(0),
    fetch: (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body || "" });
      const body = replies.shift() ?? null;
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    globals,
  );
  el("caseId").value = "case-1";
  api.initSecondOpinion();
  const panel = () => el("secondOpinionPanel");
  const press = (dataset: Record<string, string>) =>
    panel().fire("click", { target: { closest: () => ({ dataset }) } });
  const runTimers = () => timers.splice(0).forEach((f) => f());
  return { api, calls, replies, el, panel, press, runTimers };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => {
  for (let i = 0; i < 5; i++) await tick();
};

const REC = {
  generatedAt: "2026-06-01T14:00:00.000Z",
  modelA: "model-a",
  modelB: "model-b",
  referee: "",
  agreementCount: 2,
  deltas: [
    {
      id: "sev",
      kind: "severity",
      title: "Advanced <i>IP</i> Scanner executed",
      aSeverity: "High",
      bSeverity: "Medium",
      status: "accepted",
      recommendation: "review",
      reopened: "Critical",
    },
    {
      id: "dis",
      kind: "a_only",
      title: "Outbound connections",
      aSeverity: "Medium",
      status: "accepted",
      recommendation: "review",
      reopened: "High",
    },
    {
      id: "held",
      kind: "severity",
      title: "Steady decision",
      aSeverity: "High",
      bSeverity: "Low",
      status: "accepted",
      recommendation: "review",
    },
  ],
};

describe("2nd opinion — reopened decisions (#1972)", () => {
  it("lists each reopened decision with the primary's new call and Keep / Drop, escaped", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain("so-reopened");
    expect(html).toContain("2 accepted decisions reopened");
    expect(html).toContain("primary now says Critical; you accepted Medium");
    expect(html).toContain("primary now says High; you dismissed it");
    expect(html).toContain('data-so-keep="sev"');
    expect(html).toContain('data-so-drop="sev"');
    expect(html).toContain("Advanced &lt;i&gt;IP&lt;/i&gt; Scanner executed");
    expect(html).not.toContain("<i>IP</i>");
  });

  it("gives the row its own status, and leaves a steady decision as accepted", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain("accepted · reopened (primary now says Critical)");
    expect(html.match(/accepted · reopened \(/g)).toHaveLength(2);
    expect(html).toContain("✓ accepted");
  });

  it("says so in the collapsed head too", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.press({ soToggle: "" });
    expect(h.panel().innerHTML).toContain("↻ 2 reopened");
    expect(h.panel().innerHTML).not.toContain("data-so-keep");
  });

  it("shows no block when nothing is reopened", () => {
    const h = harness();
    h.api.renderSecondOpinion({ ...REC, deltas: [REC.deltas[2]] });
    expect(h.panel().innerHTML).not.toContain("so-reopened");
    expect(h.panel().innerHTML).not.toContain("reopened");
  });

  it("Keep and Drop post to the reopened route and repaint", async () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.replies.push({ ...REC, deltas: [REC.deltas[2]] });
    h.press({ soKeep: "sev" });
    await settle();
    expect(h.calls[0].url).toBe("/cases/case-1/second-opinion/reopened");
    expect(JSON.parse(h.calls[0].body)).toEqual({ deltaId: "sev", keep: true });
    expect(h.panel().innerHTML).not.toContain("so-reopened");

    h.press({ soDrop: "dis" });
    await settle();
    const drops = h.calls.filter((c) => c.url.endsWith("/reopened"));
    expect(JSON.parse(drops[1]?.body ?? "{}")).toEqual({ deltaId: "dis", keep: false });
  });
});
