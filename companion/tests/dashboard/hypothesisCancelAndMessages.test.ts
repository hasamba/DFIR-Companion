// #2848 — two gaps left by #2843 in the Hypotheses panel's "nothing drawn for another case" rule.
//
// 1. A cancelled case load emptied the case field but left the previous case's cards, badge,
//    review box and lines on screen. Their buttons did nothing (no case is open), but the panel
//    read as if a case were loaded. Cancelling now empties the panel — an empty area, never
//    "No hypotheses yet", which is a statement about a case.
// 2. The Add line and the Generate / Review line were never cleared on a case switch, and a late
//    failure from the old case's Add, Generate, Review (or a notebook Promote) still wrote its text
//    there. They are cleared on every case change, and a late answer for a case that is no longer
//    on screen writes nothing.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const EMPTY = "No hypotheses yet";

interface Answer {
  status: number;
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
  scrollIntoView: () => void;
}

interface Api {
  loadHypotheses: (caseId: string) => void;
  initHypotheses: () => void;
  clearHypothesesPanel: () => void;
  promoteToHypothesis: (id: string) => void;
  linkNextHuntToHypothesis: (id: string, title: string) => void;
  consumePendingHuntHypothesis: (caseId: string) => string | undefined;
}

const CARD = { id: "h-1", title: "RDP was the way in", status: "open", source: "analyst" };
const REVIEW = {
  reviews: [
    {
      hypothesisId: "h-1",
      title: "RDP was the way in",
      recommendedStatus: "refuted",
      supportingEvidence: ["a logon from outside"],
      refutingEvidence: ["the port was closed"],
      rationale: "the firewall log disagrees",
    },
  ],
};
const BUSY: Answer = { status: 503, body: { error: "server busy — retry shortly" } };

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
type Queued = Answer | ReturnType<typeof held>;
const send = (next: Queued) => ("pending" in next ? next.pending : Promise.resolve(response(next)));

/** A page with the Hypotheses panel; each kind of request is answered by what the test queued. */
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
      scrollIntoView: () => {},
    };
    els.set(id, made);
    return made;
  };
  const queues: Record<string, Queued[]> = { list: [], review: [], synth: [], add: [] };
  const take = (kind: string, url: string) => {
    const next = queues[kind].shift();
    if (next === undefined) throw new Error(`no ${kind} answer queued for ${url}`);
    return send(next);
  };
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: (): null => null,
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    CSS: { escape: (s: string) => s },
    investigatorName: () => "analyst",
    notebookEntry: (id: string) => ({ id, text: "the share was mounted from outside" }),
    fetch: (url: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      if (method === "GET") return take("list", url);
      if (url.endsWith("/hypothesis-review")) return take("review", url);
      if (url.endsWith("/synthesize")) return take("synth", url);
      return take("add", url);
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  api.initHypotheses();

  const switchTo = (caseId: string, answer: Queued) => {
    el("caseId").value = caseId;
    queues.list.push(answer);
    api.loadHypotheses(caseId);
  };
  const open = async (caseId: string) => {
    switchTo(caseId, { status: 200, body: [CARD] });
    await settle();
  };
  /** The case load is cancelled: the loaded case is cleared, then the panel is reset. */
  const cancelLoad = () => {
    el("caseId").value = "";
    api.clearHypothesesPanel();
  };
  const pressAdd = (answer: Queued) => {
    el("hypTitle").value = "a new idea";
    queues.add.push(answer);
    const add = el("hypAddBtn").onclick;
    if (!add) throw new Error("Add is not wired");
    add();
  };
  const pressGenerate = (answer: Queued) => {
    queues.synth.push(answer);
    el("hypGenerateBtn").click();
  };
  const pressReview = (answer: Queued) => {
    queues.review.push(answer);
    el("hypReviewBtn").click();
  };
  const pressPromote = (answer: Queued) => {
    queues.add.push(answer);
    api.promoteToHypothesis("nb-1");
  };
  return {
    api,
    el,
    switchTo,
    open,
    cancelLoad,
    pressAdd,
    pressGenerate,
    pressReview,
    pressPromote,
    list: el("hypList"),
    badge: el("hypBadge"),
    reviewBox: el("hypReviewResults"),
    addMsg: el("hypMsg"),
    genMsg: el("hypGenMsg"),
    nbMsg: el("nbMsg"),
  };
}

describe("a cancelled case load empties the Hypotheses panel (#2848)", () => {
  it("the cards, badge, review box and both lines are gone — an empty area, not 'No hypotheses yet'", async () => {
    const p = openPage();
    await p.open("case-1");
    p.pressReview({ status: 200, body: REVIEW });
    await settle();
    p.addMsg.textContent = "title required";
    p.genMsg.textContent = "synthesizing…";
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.reviewBox.innerHTML).toContain("Falsification review");

    p.cancelLoad();
    expect(p.list.innerHTML).toBe("");
    expect(p.list.innerHTML).not.toContain(EMPTY);
    expect(p.badge.textContent).toBe("");
    expect(p.reviewBox.innerHTML).toBe("");
    expect(p.addMsg.textContent).toBe("");
    expect(p.genMsg.textContent).toBe("");
  });

  it("the previous case's 'could not be loaded' line is gone too", async () => {
    const p = openPage();
    p.switchTo("case-1", BUSY);
    await settle();
    expect(p.list.innerHTML).toContain("could not be loaded");
    p.cancelLoad();
    expect(p.list.innerHTML).toBe("");
  });

  it("a list answer still on its way for the cancelled case is not drawn", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.switchTo("case-1", slow);
    p.cancelLoad();
    slow.answer({ status: 200, body: [CARD] });
    await settle();
    expect(p.list.innerHTML).toBe("");
  });

  it("a pending 'test via hunt' link is dropped", async () => {
    const p = openPage();
    await p.open("case-1");
    p.api.linkNextHuntToHypothesis("h-1", "RDP was the way in");
    p.cancelLoad();
    expect(p.api.consumePendingHuntHypothesis("case-1")).toBeUndefined();
  });

  it("the next case loaded draws its own list as usual", async () => {
    const p = openPage();
    await p.open("case-1");
    p.cancelLoad();
    p.switchTo("case-2", { status: 200, body: [] });
    await settle();
    expect(p.list.innerHTML).toContain(EMPTY);
  });
});

describe("the Add and Generate / Review lines belong to the case they were written in (#2848)", () => {
  it("both lines are cleared on a case switch", async () => {
    const p = openPage();
    await p.open("case-1");
    p.addMsg.textContent = "adding…";
    p.genMsg.textContent = "reviewing hypotheses…";
    p.switchTo("case-2", held());
    expect(p.addMsg.textContent).toBe("");
    expect(p.genMsg.textContent).toBe("");
  });

  it("both lines are cleared when a case loads after a cancel, with no list held", async () => {
    const p = openPage();
    await p.open("case-1");
    p.cancelLoad();
    p.addMsg.textContent = "title required";
    p.genMsg.textContent = "open a case first";
    p.switchTo("case-2", held());
    expect(p.addMsg.textContent).toBe("");
    expect(p.genMsg.textContent).toBe("");
  });

  it("a reload of the SAME case keeps its lines", async () => {
    const p = openPage();
    await p.open("case-1");
    p.genMsg.textContent = "no open hypotheses to review";
    p.switchTo("case-1", held());
    expect(p.genMsg.textContent).toBe("no open hypotheses to review");
  });
});

describe("a late failure from a case the analyst has left writes nothing (#2848)", () => {
  it("Add", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.pressAdd(slow);
    p.switchTo("case-2", held());
    slow.answer(BUSY);
    await settle();
    expect(p.addMsg.textContent).toBe("");
  });

  it("Generate refused by the server", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.pressGenerate(slow);
    p.switchTo("case-2", held());
    slow.answer({ status: 500 });
    await settle();
    expect(p.genMsg.textContent).toBe("");
  });

  it("Generate answering with an error", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.pressGenerate(slow);
    p.switchTo("case-2", held());
    slow.answer({ status: 200, body: { error: "no AI provider" } });
    await settle();
    expect(p.genMsg.textContent).toBe("");
  });

  it("Review", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.pressReview(slow);
    p.switchTo("case-2", held());
    slow.answer(BUSY);
    await settle();
    expect(p.genMsg.textContent).toBe("");
  });

  it("a notebook Promote", async () => {
    const p = openPage();
    await p.open("case-1");
    const slow = held();
    p.pressPromote(slow);
    p.switchTo("case-2", held());
    p.nbMsg.textContent = "";
    slow.answer(BUSY);
    await settle();
    expect(p.nbMsg.textContent).toBe("");
  });

  it("the same failures in the case still on screen are still shown", async () => {
    const p = openPage();
    await p.open("case-1");
    p.pressAdd(BUSY);
    p.pressGenerate({ status: 500 });
    await settle();
    expect(p.addMsg.textContent).toBe("failed: server busy — retry shortly");
    expect(p.genMsg.textContent).toBe("failed: HTTP 500 — restart the companion server if this 404s");
    p.pressGenerate({ status: 200, body: { error: "no AI provider" } });
    await settle();
    expect(p.genMsg.textContent).toBe("failed: no AI provider");
    p.pressReview(BUSY);
    await settle();
    expect(p.genMsg.textContent).toBe(
      "failed: server busy — retry shortly — restart the companion server if this 404s",
    );
    p.pressPromote(BUSY);
    await settle();
    expect(p.nbMsg.textContent).toBe("promote failed: server busy — retry shortly");
  });
});

describe("cancelling a case load resets the Hypotheses panel (#2848)", () => {
  it("abandonCaseLoad asks for the reset after the loaded case is cleared", () => {
    const src = readFileSync(
      new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
      "utf8",
    ).replace(/\r\n/g, "\n");
    const start = src.indexOf("function abandonCaseLoad(");
    const body = src.slice(start, src.indexOf("\n  }\n", start));
    const reset = body.indexOf('if (typeof clearHypothesesPanel === "function") clearHypothesesPanel()');
    expect(reset).toBeGreaterThan(body.indexOf("clearLoadedCase(cancelledCaseId)"));
  });
});
