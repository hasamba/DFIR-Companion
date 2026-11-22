// #2843 — the Hypotheses panel drew its list only when a list request answered, so after a case
// switch the previous case's cards (and its Falsification review box) stayed on screen until the
// new case's list arrived — and came back when an action of the old case answered late. Every
// button on them reads the case from #caseId, so a click wrote to the NEW case; an AI-generated
// hypothesis has the same id in every case with the same title, so the write could land.
//
// A load for another case now empties the list and the review box at once (an empty area — never
// "No hypotheses yet", which is a statement about the case), a reload asked for by a case that is
// no longer on screen is dropped, and a late Review answer is not drawn.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const EMPTY = "No hypotheses yet";
const FAILED = "The hypotheses could not be loaded (";
const CLOSED = "The case is closed — reopen it before changing it";

interface Answer {
  status: number;
  /** The JSON body, or `undefined` for an answer with none (a delete's 204). */
  body?: unknown;
}

type Handler = (e: { stopPropagation: () => void }) => void;

interface El {
  value: string;
  textContent: string;
  innerHTML: string;
  disabled: boolean;
  onclick: null | (() => void);
  addEventListener: (type: string, fn: Handler) => void;
  click: () => void;
}

interface Api {
  loadHypotheses: (caseId: string) => void;
  hypPatch: (id: string, patch: Record<string, unknown>) => void;
  hypDelete: (id: string) => void;
  hypApplyReview: (id: string, status: string) => void;
  hypAcknowledgeReview: (id: string) => void;
  initHypotheses: () => void;
}

// An AI-generated hypothesis's id is a hash of its title, so two cases can hold the same id.
const SAME_ID = "synth:1a2b";
const CARD_1 = { id: SAME_ID, title: "RDP was the way in", status: "open", source: "synthesis" };
const CARD_2 = { id: SAME_ID, title: "A phishing mail was the way in", status: "open", source: "synthesis" };
const LIST_1: Answer = { status: 200, body: [CARD_1] };
const LIST_2: Answer = { status: 200, body: [CARD_2] };
const REVIEW_1 = {
  reviews: [
    {
      hypothesisId: SAME_ID,
      title: "RDP was the way in",
      recommendedStatus: "refuted",
      supportingEvidence: ["a logon from outside"],
      refutingEvidence: ["the port was closed"],
      rationale: "the firewall log disagrees",
    },
  ],
};

const settle = () => new Promise((r) => setTimeout(r, 10));

function response(answer: Answer) {
  return {
    ok: answer.status >= 200 && answer.status < 300,
    status: answer.status,
    json: () =>
      answer.body === undefined
        ? Promise.reject(new SyntaxError("Unexpected end of JSON input"))
        : Promise.resolve(answer.body),
  };
}

/** A request the test answers later. */
function held() {
  let answer: (a: Answer) => void = () => {};
  const pending = new Promise<Answer>((resolve) => {
    answer = resolve;
  }).then(response);
  return { pending, answer };
}
type Held = ReturnType<typeof held>;
type Queued = Answer | Held;

const send = (next: Queued) => ("pending" in next ? next.pending : Promise.resolve(response(next)));

/** A page with the Hypotheses panel, whose requests are answered by what the test queued. */
function openPage() {
  const els = new Map<string, El>();
  const el = (id: string): El => {
    const have = els.get(id);
    if (have) return have;
    const handlers: Handler[] = [];
    const made: El = {
      value: "",
      textContent: "",
      innerHTML: "",
      disabled: false,
      onclick: null,
      addEventListener: (type, fn) => {
        if (type === "click") handlers.push(fn);
      },
      click: () => handlers.forEach((fn) => fn({ stopPropagation: () => {} })),
    };
    els.set(id, made);
    return made;
  };
  const page = {
    lists: [] as Queued[],
    listUrls: [] as string[],
    reviews: [] as Queued[],
    /** What the next card write (edit, delete) is answered with. */
    write: { status: 204 } as Queued,
    writes: [] as string[],
  };
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: (): null => null,
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    CSS: { escape: (s: string) => s },
    fetch: (url: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      if (method === "GET") {
        page.listUrls.push(url);
        const next = page.lists.shift();
        if (next === undefined) throw new Error(`no list answer queued for ${url}`);
        return send(next);
      }
      if (url.endsWith("/hypothesis-review")) {
        const next = page.reviews.shift();
        if (next === undefined) throw new Error(`no review answer queued for ${url}`);
        return send(next);
      }
      page.writes.push(`${method} ${url}`);
      return send(page.write);
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  api.initHypotheses();
  const list = el("hypList");
  const badge = el("hypBadge");
  const reviewBox = el("hypReviewResults");
  const message = el("hypGenMsg");

  /** The analyst switches case: #caseId changes and the list is asked for, in the same task. */
  const switchTo = (caseId: string, answer: Queued) => {
    el("caseId").value = caseId;
    page.lists.push(answer);
    api.loadHypotheses(caseId);
  };
  /** Open a case and wait for its list to be drawn. */
  const open = async (caseId: string, answer: Queued) => {
    switchTo(caseId, answer);
    await settle();
  };
  /** Press Review in the open case, answered by `answer`. */
  const pressReview = (answer: Queued) => {
    page.reviews.push(answer);
    el("hypReviewBtn").click();
  };
  /**
   * Press every button the panel shows — each card's delete, status and "reviewed" controls and
   * each review's Apply — the way dashboard-data-act.js does: with nothing but the id on the
   * control. Returns how many controls the panel shows, pressed or not.
   */
  const pressEverything = () => {
    const markup = list.innerHTML + reviewBox.innerHTML;
    const controls = [...markup.matchAll(/data-act="(\w+)"[^>]*?data-id="([^"]*)"/g)];
    for (const [, act, id] of controls) {
      if (act === "hypDelete") api.hypDelete(id);
      else if (act === "hypPatchStatus") api.hypPatch(id, { status: "refuted" });
      else if (act === "hypAcknowledgeReview") api.hypAcknowledgeReview(id);
      else if (act === "hypApplyReview") api.hypApplyReview(id, "refuted");
    }
    return controls.length;
  };
  return { api, page, list, badge, reviewBox, message, switchTo, open, pressReview, pressEverything };
}

describe("a case switch empties the Hypotheses list at once (#2843)", () => {
  it("the previous case's cards, badge and every other line are gone while the new list is held", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.badge.textContent).toBe(" — 1 open");

    p.switchTo("case-2", held());
    // Checked before anything can answer: the area is empty — no card, no "No hypotheses yet",
    // no "could not be loaded", no loading line.
    expect(p.list.innerHTML).toBe("");
    expect(p.badge.textContent).toBe("");
    await settle();
    expect(p.list.innerHTML).toBe("");
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("the held answer then draws the new case's cards", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slow = held();
    p.switchTo("case-2", slow);
    slow.answer(LIST_2);
    await settle();
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain("RDP was the way in");
    expect(p.badge.textContent).toBe(" — 1 open");
  });

  it("a new case with no hypotheses still reads 'No hypotheses yet' once its list answers", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slow = held();
    p.switchTo("case-2", slow);
    expect(p.list.innerHTML).toBe("");
    slow.answer({ status: 200, body: [] });
    await settle();
    expect(p.list.innerHTML).toContain(EMPTY);
  });

  it("the previous case's 'could not be loaded' line is gone at once", async () => {
    const p = openPage();
    await p.open("case-1", { status: 503, body: { error: "server busy — retry shortly" } });
    expect(p.list.innerHTML).toContain(FAILED);

    p.switchTo("case-2", held());
    expect(p.list.innerHTML).toBe("");
  });

  it("the new case's list fails: its line alone, never the previous case's cards", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slow = held();
    p.switchTo("case-2", slow);
    slow.answer({ status: 503, body: { error: "server busy — retry shortly" } });
    await settle();
    expect(p.list.innerHTML).toContain(`${FAILED}server busy — retry shortly)`);
    expect(p.list.innerHTML).not.toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("a reload of the SAME case keeps its cards on screen while the answer is held", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.switchTo("case-1", held());
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.badge.textContent).toBe(" — 1 open");
  });

  it("the Falsification review box of the previous case is emptied", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    expect(p.reviewBox.innerHTML).toContain("Apply → Refuted");

    p.switchTo("case-2", held());
    expect(p.reviewBox.innerHTML).toBe("");
  });

  it("a review drawn before its own case's list answered is emptied by the next switch", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.switchTo("case-2", held());
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    expect(p.reviewBox.innerHTML).toContain("Apply → Refuted");

    p.switchTo("case-3", held());
    expect(p.reviewBox.innerHTML).toBe("");
    expect(p.pressEverything()).toBe(0);
  });

  it("a review drawn in the first case, before any list answered, is emptied by a switch", async () => {
    const p = openPage();
    p.switchTo("case-1", held());
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    expect(p.reviewBox.innerHTML).toContain("Apply → Refuted");

    p.switchTo("case-2", held());
    expect(p.reviewBox.innerHTML).toBe("");
    expect(p.pressEverything()).toBe(0);
  });

  it("a reload of the SAME case keeps its review box", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    await p.open("case-1", LIST_1);
    expect(p.reviewBox.innerHTML).toContain("Apply → Refuted");
  });
});

describe("no leftover button can write to the new case (#2843)", () => {
  it("the buttons work in their own case — the press helper is not vacuous", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    p.page.lists.push(LIST_1, LIST_1, LIST_1);
    // Status, test-via-hunt, delete, assignee, notes — and the review's Apply.
    expect(p.pressEverything()).toBe(6);
    await settle();
    expect(p.page.writes).toEqual([
      `PATCH /cases/case-1/hypotheses/${encodeURIComponent(SAME_ID)}`,
      `DELETE /cases/case-1/hypotheses/${encodeURIComponent(SAME_ID)}`,
      `PATCH /cases/case-1/hypotheses/${encodeURIComponent(SAME_ID)}`,
    ]);
  });

  it("while the new case's list is held there is no card button and no Apply button to press", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();

    p.switchTo("case-2", held());
    expect(p.pressEverything()).toBe(0);
    await settle();
    expect(p.page.writes).toEqual([]);
  });

  it("an edit of the old case that answers after the switch does not bring its cards back", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slowEdit = held();
    p.page.write = slowEdit;
    p.api.hypPatch(SAME_ID, { notes: "checked the RDP logs" });
    await p.open("case-2", LIST_2);
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");

    slowEdit.answer({ status: 200, body: CARD_1 });
    await settle();
    // No list request for case 1 was sent, and case 2's cards stay.
    expect(p.page.listUrls).toEqual(["/cases/case-1/hypotheses", "/cases/case-2/hypotheses"]);
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain("RDP was the way in");
  });

  it("a refused edit of the old case that answers after the switch puts no line on the new case's card", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slowEdit = held();
    p.page.write = slowEdit;
    p.api.hypPatch(SAME_ID, { status: "refuted" });
    await p.open("case-2", LIST_2);

    slowEdit.answer({ status: 423, body: { error: CLOSED } });
    await settle();
    expect(p.page.listUrls).toEqual(["/cases/case-1/hypotheses", "/cases/case-2/hypotheses"]);
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain("not saved: ");
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("a late reload for the old case does not drop the new case's own refusal line", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    await p.open("case-2", LIST_2);
    p.page.write = { status: 423, body: { error: CLOSED } };
    p.page.lists.push(LIST_2);
    p.api.hypPatch(SAME_ID, { status: "refuted" });
    await settle();
    expect(p.list.innerHTML).toContain(`not saved: ${CLOSED}`);

    // The reload an old case's action asks for: dropped before it can touch case 2's lines.
    p.api.loadHypotheses("case-1");
    await settle();
    await p.open("case-2", LIST_2);
    expect(p.page.listUrls.filter((u) => u.includes("case-1"))).toHaveLength(1);
    expect(p.list.innerHTML).toContain(`not saved: ${CLOSED}`);
  });

  it("a Review of the old case that answers after the switch is not drawn", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slowReview = held();
    p.pressReview(slowReview);
    await p.open("case-2", LIST_2);

    slowReview.answer({ status: 200, body: REVIEW_1 });
    await settle();
    expect(p.reviewBox.innerHTML).toBe("");
    expect(p.message.textContent).toBe("");
    // Case 2's own card buttons write to case 2; nothing carries a review's Apply.
    p.page.lists.push(LIST_2, LIST_2);
    expect(p.pressEverything()).toBe(5);
    await settle();
    expect(p.page.writes).toEqual([
      `PATCH /cases/case-2/hypotheses/${encodeURIComponent(SAME_ID)}`,
      `DELETE /cases/case-2/hypotheses/${encodeURIComponent(SAME_ID)}`,
    ]);
  });

  it("an old Review that found nothing does not say so under the new case", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    const slowReview = held();
    p.pressReview(slowReview);
    await p.open("case-2", LIST_2);

    slowReview.answer({ status: 200, body: { reviews: [] } });
    await settle();
    expect(p.message.textContent).toBe("");
  });

  it("a Review that answers in its own case is still drawn", async () => {
    const p = openPage();
    await p.open("case-1", LIST_1);
    p.pressReview({ status: 200, body: { reviews: [] } });
    await settle();
    expect(p.message.textContent).toBe("no open hypotheses to review");
    p.pressReview({ status: 200, body: REVIEW_1 });
    await settle();
    expect(p.reviewBox.innerHTML).toContain("Apply → Refuted");
    expect(p.message.textContent).toBe("");
  });
});
