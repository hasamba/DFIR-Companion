// Watson's question-change highlight in the chat: a question update Watson applied on its own stays
// marked until the analyst clicks it, and every question-update card marks what changed and says what
// the question was before. Runs the real modules in a vm context.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface QChange {
  watsonQChangeSync(caseId: string, proposals: unknown[]): void;
  watsonQChangeIsNew(p: unknown): boolean;
  watsonQChangeSeen(el: unknown): boolean;
}
interface View extends QChange {
  watsonTurnHtml(t: unknown, proposals: unknown[], readOnly?: boolean): string;
}

const AUTO = "Watson (Auto)";
const question = (over: Record<string, unknown> = {}) => ({
  id: "q1",
  question: "Was data taken out of the network?",
  status: "unknown",
  answer: "unknown",
  pointer: "",
  ...over,
});
const update = (over: Record<string, unknown> = {}) => ({
  id: "wp-1",
  turnId: "t1",
  kind: "question_update",
  status: "applied",
  appliedBy: AUTO,
  questionId: "q1",
  before: question(),
  after: question({
    status: "answered",
    answer: "Yes. 2.3 GB went to an rclone remote.",
    pointer: "proxy log 11:52",
  }),
  ...over,
});
const turn = (ids: string[]) => ({ id: "t1", at: "x", role: "watson", text: "Done.", proposalIds: ids });

function memoryStore(seed: Record<string, string> = {}) {
  const data: Record<string, string> = { ...seed };
  return {
    data,
    getItem: (k: string) => (k in data ? data[k] : null),
    setItem: (k: string, v: string) => {
      data[k] = String(v);
    },
  };
}
const throwingStore = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
};

function load(storage: unknown = memoryStore()) {
  return loadDashboardModule<View>(
    "dashboard-watson-view.js",
    ["dashboard-escape.js", "dashboard-watson-cards.js", "dashboard-watson-qchange.js"],
    { localStorage: storage, citeEvents: () => "" },
  );
}
const pidEl = (pid: string) => ({ dataset: { pid } });

describe("question-update card: what changed", () => {
  it("marks the changed status, answer and pointer, and shows the old value on one line", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    const html = v.watsonTurnHtml(turn(["wp-1"]), [update({ appliedBy: "Dana" })]);
    expect(html.match(/watson-chg/g)?.length).toBe(3);
    expect(html).toContain('class="watson-was"');
    expect(html).toMatch(/was: <s>.*Unknown.*unknown<\/s>/);
  });

  it("does not mark a part that stayed the same", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    const same = update({
      before: question({ pointer: "proxy log 11:52" }),
      after: question({ status: "partial", answer: "unknown", pointer: "proxy log 11:52" }),
    });
    const html = v.watsonTurnHtml(turn(["wp-1"]), [same]);
    expect(html.match(/watson-chg/g)?.length).toBe(1);
  });

  it("escapes the old and new text", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    const evil = update({
      before: question({ answer: "<img src=x onerror=1>" }),
      after: question({ status: "answered", answer: "<script>x</script>" }),
    });
    const html = v.watsonTurnHtml(turn(["wp-1"]), [evil]);
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("shows no was-line when the card has no old value", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    const html = v.watsonTurnHtml(turn(["wp-1"]), [update({ before: undefined })]);
    expect(html).not.toContain("watson-was");
    expect(html).not.toContain("watson-chg");
  });
});

describe("question-update card: stays marked until seen", () => {
  it("does not light up updates already in the chat the first time a case is opened here", () => {
    const v = load();
    v.watsonQChangeSync("c1", [update()]);
    expect(v.watsonQChangeIsNew(update())).toBe(false);
    expect(v.watsonTurnHtml(turn(["wp-1"]), [update()])).not.toContain("watson-qnew");
  });

  it("marks an update Watson applied by itself after the case was opened", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    v.watsonQChangeSync("c1", [update()]);
    const html = v.watsonTurnHtml(turn(["wp-1"]), [update()]);
    expect(html).toContain("watson-qnew");
    expect(html).toContain("New change");
    expect(html).toContain('data-w-verb="qSeen"');
  });

  it("does not mark an update the analyst applied, or one still waiting for approval", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    expect(v.watsonQChangeIsNew(update({ appliedBy: "Dana" }))).toBe(false);
    expect(v.watsonQChangeIsNew(update({ status: "pending", appliedBy: undefined }))).toBe(false);
    expect(v.watsonQChangeIsNew(update({ kind: "question_new" }))).toBe(false);
  });

  it("clears the mark on click and remembers it after a reload", () => {
    const store = memoryStore();
    const v = load(store);
    v.watsonQChangeSync("c1", []);
    v.watsonQChangeSync("c1", [update()]);
    expect(v.watsonQChangeSeen(pidEl("wp-1"))).toBe(true);
    expect(v.watsonQChangeIsNew(update())).toBe(false);

    const again = load(store);
    again.watsonQChangeSync("c1", [update(), update({ id: "wp-2" })]);
    expect(again.watsonQChangeIsNew(update())).toBe(false);
    expect(again.watsonQChangeIsNew(update({ id: "wp-2" }))).toBe(true);
  });

  it("keeps seen marks per case", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    v.watsonQChangeSync("c2", []);
    v.watsonQChangeSync("c2", [update()]);
    expect(v.watsonQChangeIsNew(update())).toBe(true);
  });

  it("still works in memory when browser storage is blocked", () => {
    const v = load(throwingStore);
    v.watsonQChangeSync("c1", []);
    v.watsonQChangeSync("c1", [update()]);
    expect(v.watsonQChangeIsNew(update())).toBe(true);
    expect(v.watsonQChangeSeen(pidEl("wp-1"))).toBe(true);
    expect(v.watsonQChangeIsNew(update())).toBe(false);
  });

  it("ignores a click without a card id", () => {
    const v = load();
    v.watsonQChangeSync("c1", []);
    expect(v.watsonQChangeSeen({ dataset: {} })).toBe(false);
  });
});
