import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1590 — an accepted second-opinion decision that no longer matches a finding must be SHOWN, in
// the 2nd-opinion panel, with a way to drop it. Decisions carried in from an earlier run are
// labelled and do not count as this run's disagreements.

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
    { id: "fresh", kind: "b_only", title: "New from this run", status: "pending", recommendation: "review" },
    {
      id: "gone",
      kind: "a_only",
      title: "Outbound <b>connections</b>",
      status: "accepted",
      recommendation: "review",
      carriedFrom: "2026-06-01T13:26:00.000Z",
      unapplied: "missing",
    },
    {
      id: "held",
      kind: "severity",
      title: "Advanced IP Scanner executed",
      status: "accepted",
      recommendation: "review",
      carriedFrom: "2026-06-01T13:26:00.000Z",
    },
  ],
};

describe("2nd opinion — accepted decisions that no longer apply (#1590)", () => {
  it("lists each one with the reason and a drop button, escaped", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain("so-unapplied");
    expect(html).toContain("1 accepted decision no longer applies");
    expect(html).toContain("its finding is gone");
    expect(html).toContain('data-so-reject="gone"');
    expect(html).toContain("Outbound &lt;b&gt;connections&lt;/b&gt;");
    expect(html).not.toContain("<b>connections");
  });

  it("says so in the collapsed head too", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.press({ soToggle: "" });
    expect(h.panel().innerHTML).toContain("⚠ 1 not applied");
    expect(h.panel().innerHTML).not.toContain("no longer applies");
  });

  it("drop rejects the decision through the existing apply call", async () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.press({ soReject: "gone" });
    await settle();
    expect(h.calls[0].url).toBe("/cases/case-1/second-opinion/apply");
    expect(JSON.parse(h.calls[0].body)).toEqual({ deltaId: "gone", accept: false });
  });

  it("labels a carried decision and lists this run's disagreements first", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain("· earlier run");
    expect(html.indexOf("New from this run")).toBeLessThan(html.indexOf("Advanced IP Scanner executed"));
  });

  it("shows no block when every accepted decision still applies", () => {
    const h = harness();
    h.api.renderSecondOpinion({ ...REC, deltas: [REC.deltas[0], REC.deltas[2]] });
    expect(h.panel().innerHTML).not.toContain("so-unapplied");
  });
});

describe("2nd opinion — the list refreshes after a synthesis (#1590)", () => {
  it("re-fetches on a state push only when an accepted dismissal or severity change exists", async () => {
    const h = harness();
    h.api.renderSecondOpinion({ ...REC, deltas: [REC.deltas[0]] });
    h.api.scheduleSecondOpinionReload("case-1");
    h.runTimers();
    expect(h.calls).toHaveLength(0);

    h.api.renderSecondOpinion(REC);
    h.api.scheduleSecondOpinionReload("case-1");
    h.api.scheduleSecondOpinionReload("case-1"); // debounced: one fetch
    h.runTimers();
    await settle();
    expect(h.calls.map((c) => c.url)).toEqual(["/cases/case-1/second-opinion"]);
  });

  it("drops a drop/apply answer for a case the analyst has since left", async () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.replies.push({ ...REC, deltas: [] });
    h.press({ soReject: "gone" });
    h.el("caseId").value = "case-2";
    await settle();
    expect(h.panel().innerHTML).toContain("so-unapplied");
    expect(h.calls.map((c) => c.url)).toEqual(["/cases/case-1/second-opinion/apply"]);
  });

  it("drops an answer for a case the analyst has since left", async () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.replies.push({ ...REC, deltas: [] });
    h.api.loadSecondOpinion("case-1");
    h.el("caseId").value = "case-2";
    await settle();
    expect(h.panel().innerHTML).toContain("so-unapplied");
  });
});
