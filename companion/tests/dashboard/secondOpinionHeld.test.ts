import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1596 — a referee dismissal the server held back from the bulk actions (it may remove the last
// evidence for an open question, or its reason quotes nothing) says so on its row, is not counted by
// "follow referee" or "accept all", and the confirm dialogs say it stays pending.

interface Api {
  initSecondOpinion(): void;
  renderSecondOpinion(rec: unknown): void;
}

interface FakeEl {
  value: string;
  innerHTML: string;
  style: Record<string, string>;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelectorAll(sel: string): FakeEl[];
}

function harness() {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id)) {
      const handlers: Record<string, ((e: unknown) => void)[]> = {};
      els.set(id, {
        value: "",
        innerHTML: "",
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
  const confirms: string[] = [];
  const posts: string[] = [];
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: (msg: string) => {
      confirms.push(msg);
      return false;
    },
    render: () => {},
    fetch: (url: string) => {
      posts.push(url);
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
  return { api, panel, press, confirms };
}

const REC = {
  generatedAt: new Date().toISOString(),
  modelA: "model-a",
  modelB: "model-b",
  referee: "codex",
  agreementCount: 3,
  deltas: [
    {
      id: "d1",
      kind: "b_only",
      title: "Lateral movement",
      status: "pending",
      recommendation: "accept_b",
      rationale: "r",
    },
    {
      id: "d2",
      kind: "a_only",
      title: "Mimikatz on mk64",
      status: "pending",
      recommendation: "accept_b",
      rationale: "r",
    },
    {
      id: "d3",
      kind: "a_only",
      title: "Script Block Auditing (EID 4104)",
      status: "pending",
      recommendation: "accept_b",
      rationale: "PowerShell content already covered under f1/f5",
      refereeFlags: [
        {
          kind: "answers_open_item",
          itemId: "q_impact",
          itemKind: "negative",
          text: "What was the <impact>?",
        },
        { kind: "unquoted_reason" },
      ],
    },
  ],
};

describe("2nd opinion — dismissals held for the analyst (#1596)", () => {
  it("says on the row why the dismissal is held, HTML-escaped", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain(
      "may be the only evidence for q_impact (negative answer): What was the &lt;impact&gt;?",
    );
    expect(html).toContain("the referee's reason quotes nothing from the cited events");
    expect(html).not.toContain("<impact>");
  });

  it("does not count the held dismissal in 'follow referee' or 'accept all'", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    const html = h.panel().innerHTML;
    expect(html).toContain("⚖ follow referee (2)");
    expect(html).toContain("✓ accept all (2)");
  });

  it("the confirm dialogs say the held dismissal stays pending", () => {
    const h = harness();
    h.api.renderSecondOpinion(REC);
    h.press({ soAll: "referee" });
    h.press({ soAll: "accept" });
    expect(h.confirms).toHaveLength(2);
    for (const msg of h.confirms) expect(msg).toContain("1 dismissal(s) marked ⚠ stay pending");
  });

  it("shows no held line once the analyst decided the delta", () => {
    const h = harness();
    const decided = {
      ...REC,
      deltas: REC.deltas.map((d) => (d.id === "d3" ? { ...d, status: "rejected" } : d)),
    };
    h.api.renderSecondOpinion(decided);
    expect(h.panel().innerHTML).not.toContain("so-held");
  });
});
