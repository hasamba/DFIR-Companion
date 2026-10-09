import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2081 — "follow the referee" applies the calls the referee made and leaves every delta it made
// no call on ("review") pending. Afterwards the panel must say so and list those deltas, each with
// its own accept/reject, and each such row carries a lasting "referee: no call" line.

interface Api {
  initSecondOpinion(): void;
  renderSecondOpinion(rec: unknown): void;
  applyAllSecondOpinion(caseId: string, accept: boolean | "referee"): void;
  runSecondOpinion(): void;
}

interface FakeEl {
  value: string;
  innerHTML: string;
  textContent: string;
  style: Record<string, string>;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelectorAll(sel: string): FakeEl[];
}

type Delta = Record<string, unknown>;
interface Rec {
  generatedAt: string;
  modelA: string;
  modelB: string;
  referee?: string;
  refereeError?: unknown;
  agreementCount: number;
  deltas: Delta[];
}

function harness() {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id)) {
      const handlers: Record<string, ((e: unknown) => void)[]> = {};
      els.set(id, {
        value: "",
        innerHTML: "",
        textContent: "",
        style: {},
        addEventListener: (type, fn) => {
          (handlers[type] ||= []).push(fn);
        },
        fire: (type, ev) => (handlers[type] || []).forEach((f) => f(ev ?? {})),
        querySelectorAll: () => [],
      });
    }
    return els.get(id) as FakeEl;
  };
  // What the server answers to the next apply-all POST.
  let reply: unknown = null;
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: () => true,
    render: () => {},
    fetch: (url: string) => {
      if (url.endsWith("/second-opinion/apply-all"))
        return Promise.resolve({ status: 200, json: async () => reply });
      if (url.endsWith("/state")) return Promise.resolve({ status: 200, json: async () => ({}) });
      return new Promise(() => {});
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
  const follow = async (after: Rec) => {
    reply = after;
    api.applyAllSecondOpinion("case-1", "referee");
    for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  };
  return { api, panel, press, follow, el };
}

const delta = (id: string, recommendation: string, extra: Delta = {}): Delta => ({
  id,
  kind: "a_only",
  title: `finding ${id}`,
  status: "pending",
  recommendation,
  rationale: "r",
  ...extra,
});

const BEFORE: Rec = {
  generatedAt: new Date().toISOString(),
  modelA: "model-a",
  modelB: "model-b",
  referee: "codex",
  agreementCount: 3,
  deltas: [
    delta("d1", "accept_b"),
    delta("d2", "keep_a"),
    delta("d3", "review", { title: "WinRM configuration change" }),
    delta("d4", "review", { kind: "severity", title: "Kerberoasting" }),
  ],
};

// The server's answer: the two calls applied, the two no-call deltas left pending.
const AFTER: Rec = {
  ...BEFORE,
  deltas: BEFORE.deltas.map((d) =>
    d.recommendation === "accept_b"
      ? { ...d, status: "accepted" }
      : d.recommendation === "keep_a"
        ? { ...d, status: "rejected" }
        : d,
  ),
};

describe("2nd opinion — deltas the referee made no call on (#2081)", () => {
  it("after follow-the-referee, lists the no-call deltas with their own accept/reject", async () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(AFTER);
    const html = h.panel().innerHTML;
    expect(html).toContain("2 deltas had no referee call — review them");
    expect(html).toContain("WinRM configuration change");
    expect(html).toContain("Kerberoasting");
    for (const id of ["d3", "d4"]) {
      expect(html).toContain(`data-so-accept="${id}"`);
      expect(html).toContain(`data-so-reject="${id}"`);
    }
    // Both ids appear once in the block and once on their own row.
    expect(html.split('data-so-accept="d3"').length - 1).toBe(2);
    expect(h.el("status").textContent).toBe(
      "followed the referee: 1 accepted, 1 rejected — 2 with no referee call left for you",
    );
  });

  it("shows no block before follow-the-referee, only the per-row no-call line", () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    const html = h.panel().innerHTML;
    expect(html).not.toContain("had no referee call");
    expect(html.split("referee: no call").length - 1).toBe(2);
  });

  it("keeps the per-row no-call line after the run, and not on decided rows", async () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(AFTER);
    expect(h.panel().innerHTML.split("referee: no call").length - 1).toBe(2);
    const decided = {
      ...AFTER,
      deltas: AFTER.deltas.map((d) => (d.id === "d3" ? { ...d, status: "rejected" } : d)),
    };
    h.api.renderSecondOpinion(decided);
    const html = h.panel().innerHTML;
    expect(html.split("referee: no call").length - 1).toBe(1);
    expect(html).toContain("1 delta had no referee call — review it");
  });

  it("does not count a no-call delta held for the analyst — it has its own ⚠ line", async () => {
    const h = harness();
    const held = { refereeFlags: [{ kind: "unquoted_reason" }] };
    const after = {
      ...AFTER,
      deltas: AFTER.deltas.map((d) => (d.id === "d4" ? { ...d, ...held } : d)),
    };
    h.api.renderSecondOpinion({ ...BEFORE, deltas: after.deltas });
    await h.follow(after);
    const html = h.panel().innerHTML;
    expect(html).toContain("1 delta had no referee call — review it");
    expect(html.split("referee: no call").length - 1).toBe(1);
  });

  it("shows neither the block nor the row line when the referee failed", async () => {
    const h = harness();
    const failed = { ...AFTER, refereeError: { message: "timeout", referee: "codex" } };
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(failed);
    const html = h.panel().innerHTML;
    expect(html).not.toContain("had no referee call");
    expect(html).not.toContain("referee: no call");
  });

  it("shows no row line when no referee ran at all", () => {
    const h = harness();
    const { referee: _r, ...noReferee } = BEFORE;
    h.api.renderSecondOpinion(noReferee);
    expect(h.panel().innerHTML).not.toContain("referee: no call");
  });

  it("shows no block when the referee made a call on every delta", async () => {
    const h = harness();
    const allCalled = { ...AFTER, deltas: AFTER.deltas.slice(0, 2) };
    h.api.renderSecondOpinion({ ...BEFORE, deltas: BEFORE.deltas.slice(0, 2) });
    await h.follow(allCalled);
    expect(h.panel().innerHTML).not.toContain("had no referee call");
    expect(h.el("status").textContent).toBe("followed the referee: 1 accepted, 1 rejected");
  });

  it("the dismiss button clears the block but not the row lines", async () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(AFTER);
    h.press({ soNocallDismiss: "" });
    const html = h.panel().innerHTML;
    expect(html).not.toContain("had no referee call");
    expect(html.split("referee: no call").length - 1).toBe(2);
  });

  it("clears the block when the analyst switches case", async () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(AFTER);
    h.el("caseId").value = "case-2";
    h.api.renderSecondOpinion(AFTER);
    h.el("caseId").value = "case-1";
    h.api.renderSecondOpinion(AFTER);
    expect(h.panel().innerHTML).not.toContain("had no referee call");
  });

  it("clears the block when a new second-opinion run starts", async () => {
    const h = harness();
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(AFTER);
    h.api.runSecondOpinion();
    h.api.renderSecondOpinion(AFTER);
    expect(h.panel().innerHTML).not.toContain("had no referee call");
  });

  it("escapes adversary-controlled titles in the block", async () => {
    const h = harness();
    const evil = {
      ...AFTER,
      deltas: AFTER.deltas.map((d) => (d.id === "d3" ? { ...d, title: "<img src=x onerror=alert(1)>" } : d)),
    };
    h.api.renderSecondOpinion(BEFORE);
    await h.follow(evil);
    const html = h.panel().innerHTML;
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
  });
});
