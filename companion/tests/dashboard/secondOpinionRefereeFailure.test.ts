import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// A failed referee pass must not look like a referee that had nothing to say (#1587).
//
// The 2nd-opinion panel hides every empty referee field, so before this change a referee that
// crashed (CLI missing, timeout, bad JSON) left the panel looking exactly like one that ran and
// made no call. The server now records the failure on the record; this suite pins that the panel
// SAYS so, in the head (so the collapsed panel says it too), that the "follow referee" bulk action
// is withheld while the referee has failed, and that the re-run button settles on every path.

interface Api {
  initSecondOpinion(): void;
  renderSecondOpinion(rec: unknown): void;
  rerunSecondOpinionReferee(caseId: string): void;
}

interface Deferred {
  url: string;
  method: string;
  body: string;
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
}

interface FakeEl {
  id: string;
  value: string;
  textContent: string;
  innerHTML: string;
  disabled: boolean;
  style: Record<string, string>;
  onclick: unknown;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelectorAll(sel: string): FakeEl[];
}

function makeEl(id: string): FakeEl {
  const handlers: Record<string, ((e: unknown) => void)[]> = {};
  const el: FakeEl = {
    id,
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
  return el;
}

function harness() {
  const pending: Deferred[] = [];
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id)) els.set(id, makeEl(id));
    return els.get(id) as FakeEl;
  };
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: () => true,
    render: () => {},
    fetch: (url: string, init?: { method?: string; body?: string }) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          method: init?.method || "GET",
          body: init?.body || "",
          resolve: (body, i = {}) =>
            res({
              ok: i.ok ?? (i.status ?? 200) < 400,
              status: i.status ?? 200,
              json: () => Promise.resolve(body),
            }),
          reject: rej,
        });
      }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    globals,
  );
  el("caseId").value = "case-1";
  api.initSecondOpinion();
  const panel = () => el("secondOpinionPanel");
  /** Press a delegated panel button carrying this dataset. */
  const press = (dataset: Record<string, string>) =>
    panel().fire("click", { target: { closest: () => ({ dataset }) } });
  return { api, pending, el, panel, press };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => {
  for (let i = 0; i < 5; i++) await tick();
};

const DELTAS = [
  {
    id: "d1",
    kind: "b_only",
    title: "Lateral movement",
    status: "pending",
    bSeverity: "High",
    recommendation: "accept_b",
  },
  { id: "d2", kind: "a_only", title: "Old finding", status: "pending" },
];

const OK_REC = {
  generatedAt: new Date().toISOString(),
  modelA: "model-a",
  modelB: "model-b",
  referee: "codex",
  agreementCount: 3,
  deltas: DELTAS.map((d) => ({ ...d, rationale: "because" })),
};

const FAILED_REC = (message = "Codex CLI not found", referee = "codex") => ({
  ...OK_REC,
  referee: "",
  refereeError: { referee, message, at: new Date().toISOString() },
});

describe("2nd opinion — a failed referee is visible (#1587)", () => {
  it("names the referee and the failure, with a re-run button", () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    const html = h.panel().innerHTML;
    expect(html).toContain("so-referee-error");
    expect(html).toContain("referee (codex) failed: Codex CLI not found");
    expect(html).toContain("data-so-referee-rerun");
    expect(html).toContain("re-run referee");
  });

  it("HTML-escapes the failure message and the referee name", () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC("<img src=x onerror=alert(1)>", "<b>r</b>"));
    const html = h.panel().innerHTML;
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>r</b>");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("says 'referee failed:' when the failed referee has no name", () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC("boom", ""));
    expect(h.panel().innerHTML).toContain("referee failed: boom");
  });

  it("still shows the failure line when the panel is collapsed", () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soToggle: "" });
    const html = h.panel().innerHTML;
    expect(html).not.toContain("so-delta");
    expect(html).toContain("referee (codex) failed: Codex CLI not found");
    expect(html).toContain("data-so-referee-rerun");
  });

  it("withholds 'follow referee' while the referee has failed, even with a stale call", () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    expect(h.panel().innerHTML).not.toContain('data-so-all="referee"');
  });

  it("shows no failure line and no re-run button for a successful referee", () => {
    const h = harness();
    h.api.renderSecondOpinion(OK_REC);
    const html = h.panel().innerHTML;
    expect(html).not.toContain("so-referee-error");
    expect(html).not.toContain("data-so-referee-rerun");
    expect(html).toContain('data-so-all="referee"');
  });
});

describe("2nd opinion — re-running the referee (#1587)", () => {
  it("POSTs the referee route and repaints without the failure on 200", async () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);
    const req = h.pending.shift()!;
    expect(req.url).toBe("/cases/case-1/second-opinion/referee");
    expect(req.method).toBe("POST");
    expect(h.el("status").textContent).toContain("re-running the referee");
    req.resolve(OK_REC);
    await settle();
    const html = h.panel().innerHTML;
    expect(html).not.toContain("so-referee-error");
    expect(html).toContain("referee: codex");
    expect(h.el("status").textContent).toMatch(/referee: \d+ verdict/);
  });

  it("renders the returned record's failure and the error on 502", async () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    h.pending
      .shift()!
      .resolve({ error: "referee timed out", record: FAILED_REC("timed out after 120s") }, { status: 502 });
    await settle();
    expect(h.panel().innerHTML).toContain("referee (codex) failed: timed out after 120s");
    expect(h.el("status").textContent).toContain("referee timed out");
  });

  it("drops the answer when the analyst switched case while the referee ran", async () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    const req = h.pending.shift()!;
    h.el("caseId").value = "case-2";
    h.api.renderSecondOpinion({ ...OK_REC, modelA: "case-two-model" });
    h.el("status").textContent = "case-2 loaded";
    req.resolve(OK_REC);
    await settle();
    expect(h.panel().innerHTML).toContain("case-two-model");
    expect(h.el("status").textContent).toBe("case-2 loaded");
    // The in-flight flag still clears, so case-2's own re-run is not blocked.
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);
    expect(h.pending[0].url).toBe("/cases/case-2/second-opinion/referee");
  });

  it("hands a Presidio hold to the anonymization flow", async () => {
    const h = harness();
    const held: unknown[] = [];
    (h.api as unknown as Record<string, unknown>).setPresidioPending = (f: unknown) => held.push(f);
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    h.pending.shift()!.resolve({ error: "presidio_approval_required", findings: ["x"] }, { status: 409 });
    await settle();
    expect(held).toEqual([["x"]]);
    expect(h.el("status").textContent).toContain("Presidio");
    expect(h.panel().innerHTML).toContain("so-referee-error");
  });

  it("ignores a second press while one is in flight, and clears the flag on every path", async () => {
    const h = harness();
    h.api.renderSecondOpinion(FAILED_REC());
    h.press({ soRefereeRerun: "" });
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);

    // Network error path.
    h.pending.shift()!.reject(new Error("offline"));
    await settle();
    expect(h.el("status").textContent).toContain("offline");
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);

    // Plain 409 path.
    h.pending.shift()!.resolve({ error: "second opinion busy" }, { status: 409 });
    await settle();
    expect(h.el("status").textContent).toContain("second opinion busy");
    expect(h.panel().innerHTML).toContain("so-referee-error");
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);

    // 502 path.
    h.pending.shift()!.resolve({ error: "failed", record: FAILED_REC() }, { status: 502 });
    await settle();
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);

    // 200 path.
    h.pending.shift()!.resolve(OK_REC);
    await settle();
    h.press({ soRefereeRerun: "" });
    expect(h.pending).toHaveLength(1);
  });

  it("is published on window", () => {
    const h = harness();
    expect(typeof h.api.rerunSecondOpinionReferee).toBe("function");
  });
});
