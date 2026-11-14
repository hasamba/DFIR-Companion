// Task 9: Watson marks, proposal cards and the "Wrote:" line. Runs the real modules in a vm context.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Marks {
  watsonMarksSet(proposals: unknown[]): void;
  watsonMarkHtml(kind: string, id: string, item?: unknown): string;
  watsonUndoTarget(kind: string, id: string): string;
}
interface Cards {
  watsonCardHtml(p: unknown): string;
  watsonWroteHtml(proposals: unknown[]): string;
  watsonPausedHtml(reason: string): string;
}
interface View {
  watsonTurnHtml(t: unknown, proposals: unknown[], readOnly?: boolean): string;
}

const HOSTILE = "<img src=x onerror=1> a‮b\n## Forged";
const baseDeps = ["dashboard-escape.js", "dashboard-watson-cards.js", "dashboard-watson-marks.js"];
const globals = {
  citeEvents: (ids: string[]) => (ids || []).map((id) => `[cited ${id}]`).join(" "),
  document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
};

const finding = (over: Record<string, unknown> = {}) => ({
  id: "f-watson-1a2b3c4d",
  severity: "High",
  title: "Staged archive on host-a.example.com",
  description: "An archive was written before the transfer.",
  relatedEventIds: ["e1", "e2"],
  ...over,
});
const prop = (kind: string, status: string, over: Record<string, unknown> = {}) => ({
  id: `wp-${kind}-${status}`,
  turnId: "t1",
  kind,
  status,
  targetId: "target-1",
  appliedBy: "Dana",
  ...over,
});
const fprop = (status: string, over: Record<string, unknown> = {}) =>
  prop("finding_new", status, {
    targetId: "f-watson-1a2b3c4d",
    after: finding(),
    pasteLineEvents: [],
    ...over,
  });

const marks = () => loadDashboardModule<Marks>("dashboard-watson-marks.js", ["dashboard-escape.js"], globals);

describe("watsonMarkHtml", () => {
  it("is empty unless an applied Watson proposal targets the item", () => {
    const api = marks();
    expect(api.watsonMarkHtml("finding", "f-watson-1a2b3c4d")).toBe("");
    for (const status of ["pending", "rejected", "undone"]) {
      api.watsonMarksSet([fprop(status)]);
      expect(api.watsonMarkHtml("finding", "f-watson-1a2b3c4d")).toBe("");
    }
    api.watsonMarksSet([fprop("applied")]);
    const html = api.watsonMarkHtml("finding", "f-watson-1a2b3c4d");
    expect(html).toContain("Watson");
    expect(html).toContain("Added by Watson, approved by Dana");
    expect(html).toContain('data-w-verb="undo"');
    expect(html).toContain('data-pid="wp-finding_new-applied"');
    expect(html).not.toContain("style=");
    expect(api.watsonMarkHtml("finding", "f-other")).toBe("");
    expect(api.watsonUndoTarget("finding", "f-watson-1a2b3c4d")).toBe("wp-finding_new-applied");
    expect(api.watsonUndoTarget("finding", "f-other")).toBe("");
  });

  it("marks next steps, report fields and every row a promotion actually added", () => {
    const api = marks();
    api.watsonMarksSet([
      prop("next_step_new", "applied", { targetId: "s-watson-1" }),
      prop("report_text", "applied", { targetId: "conclusions", field: "conclusions" }),
      // ev3 was requested but the case already held it: not Watson's, not marked (F8).
      prop("event_promote", "applied", {
        targetId: "ev1",
        events: [{ id: "ev1" }, { id: "ev2" }, { id: "ev3" }],
        createdEventIds: ["ev1", "ev2"],
      }),
    ]);
    expect(api.watsonMarkHtml("next_step", "s-watson-1")).toContain("watson-mark");
    expect(api.watsonMarkHtml("report", "conclusions")).toContain("watson-mark");
    expect(api.watsonMarkHtml("report", "investigationLimitations")).toBe("");
    expect(api.watsonMarkHtml("event", "ev1")).toContain("watson-mark");
    expect(api.watsonMarkHtml("event", "ev2")).toContain("watson-mark");
    expect(api.watsonMarkHtml("event", "ev3")).toBe("");
  });

  it("an event that went undone and was applied again is marked again", () => {
    const api = marks();
    const p = prop("event_promote", "undone", {
      targetId: "ev1",
      events: [{ id: "ev1" }],
      createdEventIds: ["ev1"],
    });
    api.watsonMarksSet([p]);
    expect(api.watsonMarkHtml("event", "ev1")).toBe("");
    api.watsonMarksSet([{ ...p, status: "applied" }]);
    expect(api.watsonMarkHtml("event", "ev1")).toContain("watson-mark");
  });

  it("escapes the approver and the synthesis notes of a finding", () => {
    const api = marks();
    api.watsonMarksSet([fprop("applied", { appliedBy: HOSTILE })]);
    const html = api.watsonMarkHtml("finding", "f-watson-1a2b3c4d", {
      author: "watson",
      synthesisDisagrees: { severity: "Low", title: HOSTILE, description: HOSTILE },
      similarSynthesisId: HOSTILE,
      citationsChanged: true,
    });
    expect(html).not.toContain("<img");
    expect(html).not.toContain("‮");
    expect(html).toContain("&lt;img src=x onerror=1&gt;");
    expect(html).toContain("Synthesis disagrees: Low");
    expect(html).toContain("Synthesis has a similar finding");
    expect(html).toContain("cited evidence changed");
    expect(html).not.toContain("onclick");
    expect(html).not.toContain("style=");
  });

  it("shows the badge for a Watson-authored item whose proposal fell out of the chat, with no Undo", () => {
    const api = marks();
    const html = api.watsonMarkHtml("next_step", "s1", { author: "watson" });
    expect(html).toContain("watson-mark");
    expect(html).not.toContain('data-w-verb="undo"');
    expect(api.watsonMarkHtml("event", "e9", { provenance: ["[watson]"] })).toContain("watson-mark");
    expect(api.watsonMarkHtml("event", "e9", { provenance: ["[second-look: h2]"] })).toBe("");
  });

  it("a promoted row's Undo says it removes every row the promotion added (F9)", () => {
    const api = marks();
    api.watsonMarksSet([
      prop("event_promote", "applied", { events: [{ id: "a" }], createdEventIds: ["a", "b", "c"] }),
      prop("finding_new", "applied", { id: "wp-f", targetId: "f-watson-1" }),
    ]);
    expect(api.watsonMarkHtml("event", "b")).toContain('title="Undo — removes all 3 rows Watson promoted"');
    expect(api.watsonMarkHtml("event", "b")).toContain(
      'aria-label="Undo — removes all 3 rows Watson promoted"',
    );
    expect(api.watsonMarkHtml("finding", "f-watson-1")).toContain('title="Undo what Watson wrote"');
  });

  it("a report field marked by Watson keeps its badge, without Undo, once the proposal left the chat (F10)", () => {
    const slot = { dataset: { watsonSlot: "conclusions" }, innerHTML: "" };
    const other = { dataset: { watsonSlot: "investigationLimitations" }, innerHTML: "" };
    const api = loadDashboardModule<Marks & { watsonMarkReportSlots(meta: unknown): void }>(
      "dashboard-watson-marks.js",
      ["dashboard-escape.js"],
      { ...globals, document: { ...globals.document, querySelectorAll: () => [slot, other] } },
    );
    api.watsonMarksSet([]);
    api.watsonMarkReportSlots({ watsonFields: { conclusions: { proposalId: "wp-gone", at: "x" } } });
    expect(slot.innerHTML).toContain("watson-mark");
    expect(slot.innerHTML).not.toContain('data-w-verb="undo"');
    expect(other.innerHTML).toBe("");
  });
});

describe("proposal cards", () => {
  const cards = () =>
    loadDashboardModule<Cards>("dashboard-watson-cards.js", ["dashboard-escape.js"], globals);

  it("renders a finding with its severity, citations and paste lines verbatim in a pre, escaped", () => {
    const html = cards().watsonCardHtml(
      fprop("pending", {
        after: finding({ title: HOSTILE, description: HOSTILE }),
        pasteLineEvents: [{ id: "p1", description: HOSTILE }],
      }),
    );
    expect(html).not.toContain("<img");
    expect(html).not.toContain("‮");
    expect(html).toContain("&lt;img src=x onerror=1&gt;");
    expect(html).toContain("High");
    expect(html).toContain("[cited e1] [cited e2]");
    expect(html).toMatch(/<pre[^>]*>[^]*&lt;img src=x onerror=1&gt;[^]*<\/pre>/);
    expect(html).toContain('data-w-verb="apply"');
    expect(html).toContain('data-w-verb="reject"');
    expect(html).not.toContain("style=");
  });

  it("renders a next step, a report text and held events", () => {
    const c = cards();
    const step = c.watsonCardHtml(
      prop("next_step_new", "applied", {
        after: { id: "s1", priority: "high", action: HOSTILE, rationale: "why", pointer: "where" },
      }),
    );
    expect(step).toContain("Next step");
    expect(step).not.toContain("<img");
    expect(step).toContain('data-w-verb="undo"');
    const rep = c.watsonCardHtml(
      prop("report_text", "pending", { field: "conclusions", before: "old", after: HOSTILE }),
    );
    expect(rep).toContain("Conclusions");
    expect(rep).not.toContain("<img");
    const events = Array.from({ length: 8 }, (_, i) => ({
      id: `ev${i}`,
      description: `row ${i}`,
      severity: "High",
    }));
    const held = c.watsonCardHtml(prop("event_promote", "pending", { events, pasteId: "pp1" }));
    expect(held).toContain("8 rows");
    expect(held).toContain("row 4");
    expect(held).not.toContain("row 5");
    expect(held).toContain("and 3 more");
    const undone = c.watsonCardHtml(prop("event_promote", "undone", { events, pasteId: "pp1" }));
    expect(undone).toContain('data-w-verb="apply"');
  });

  it("shows the server message of a refused undo on the card", () => {
    const html = cards().watsonCardHtml({ ...fprop("applied"), uiError: "Finding changed since; <b>x</b>" });
    expect(html).toContain("Finding changed since; &lt;b&gt;x&lt;/b&gt;");
  });

  it("shows why reactions are paused, in one line", () => {
    const c = cards();
    for (const reason of ["presidio", "limit", "errors"]) {
      const html = c.watsonPausedHtml(reason);
      expect(html).toContain("Send a message to resume");
      expect(html).not.toContain("\n");
    }
    expect(c.watsonPausedHtml("bogus<")).toBe("");
    expect(c.watsonPausedHtml("")).toBe("");
  });
});

describe("the Wrote: line", () => {
  const cards = () =>
    loadDashboardModule<Cards>("dashboard-watson-cards.js", ["dashboard-escape.js"], globals);
  it("counts each kind that was applied", () => {
    const html = cards().watsonWroteHtml([
      fprop("applied"),
      { ...fprop("applied"), id: "wp2", kind: "finding_update", targetId: "f-watson-ffff0000" },
      prop("next_step_new", "applied", { targetId: "s1" }),
      // four rows requested, three landed: the count is the rows Watson actually added (F8)
      prop("event_promote", "applied", {
        events: [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }],
        createdEventIds: ["a", "b", "c"],
      }),
      prop("report_text", "applied", { field: "conclusions", targetId: "conclusions" }),
      prop("report_text", "applied", {
        id: "wp9",
        field: "investigationLimitations",
        targetId: "investigationLimitations",
      }),
      fprop("pending", { id: "wp-pending" }),
      prop("next_step_new", "rejected", { id: "wp-rej" }),
    ]);
    expect(html).toContain("Wrote:");
    expect(html).toContain("2 findings");
    expect(html).toContain("1 next step<");
    expect(html).toContain("3 events");
    expect(html).toContain("Report § Conclusions");
    expect(html).toContain("Report § Investigation limitations");
    expect(html).toContain('data-act="watsonAct"');
    expect(html).toContain('data-w-verb="jump"');
    expect(html).toContain('data-w-kind="finding"');
    expect(html).not.toContain("onclick");
    expect(html).not.toContain("style=");
  });

  it("uses the singular for one and the plural for more (F7)", () => {
    const c = cards();
    const one = c.watsonWroteHtml([
      fprop("applied"),
      prop("event_promote", "applied", { createdEventIds: ["a"] }),
    ]);
    expect(one).toContain(">1 finding<");
    expect(one).toContain(">1 event<");
    const many = c.watsonWroteHtml([
      prop("next_step_new", "applied", { targetId: "s1" }),
      prop("next_step_new", "applied", { id: "wp-s2", targetId: "s2" }),
    ]);
    expect(many).toContain(">2 next steps<");
  });

  it("leaves out the events part when a promotion added no rows", () => {
    const html = cards().watsonWroteHtml([
      fprop("applied"),
      prop("event_promote", "applied", { events: [{ id: "a" }], createdEventIds: [] }),
    ]);
    expect(html).not.toContain("event");
  });

  it("is empty when nothing was applied, and ignores question proposals", () => {
    const c = cards();
    expect(c.watsonWroteHtml([fprop("pending")])).toBe("");
    expect(c.watsonWroteHtml([prop("question_new", "applied")])).toBe("");
    expect(c.watsonWroteHtml([])).toBe("");
  });

  it("ends a Watson turn that has applied proposals", () => {
    const view = loadDashboardModule<View>("dashboard-watson-view.js", baseDeps, globals);
    const turn = {
      id: "t1",
      at: "x",
      role: "watson",
      text: "Done.",
      proposalIds: ["wp-finding_new-applied"],
    };
    const html = view.watsonTurnHtml(turn, [fprop("applied")]);
    expect(html).toContain("New finding");
    expect(html.indexOf("Wrote:")).toBeGreaterThan(html.indexOf("watson-prop"));
    const sys = view.watsonTurnHtml(
      { id: "t2", at: "x", role: "system", text: "Watson reacted to: an import" },
      [],
    );
    expect(sys).toContain("System");
    expect(sys).toContain("Watson reacted to: an import");
  });
});
