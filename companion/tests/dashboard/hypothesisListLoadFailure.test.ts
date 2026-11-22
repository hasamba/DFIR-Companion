// #2840 — the Hypotheses list load read the answer without checking that the request succeeded,
// turned any non-list answer into an empty list and had an empty catch. A refused load (server
// busy, a damaged case file) therefore drew "No hypotheses yet" on a case that has hypotheses, and
// a lost connection left the old list on screen with no word that it was stale.
//
// A failed load now draws one line first inside the list: the server's own sentence when it sent
// one, the status and the restart advice when it did not. The last good list stays beneath it only
// when it belongs to the same case, only the newest request's outcome is applied, and the "No
// hypotheses yet" text is kept for a real empty-list answer.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const EMPTY = "No hypotheses yet";
const FAILED = "The hypotheses could not be loaded (";
const STALE = "The list below is the last one that loaded.";
const NOT_EMPTY = "Nothing here says the case has no hypotheses.";
const RESTART = "restart the companion server";
const DAMAGED = 'Case "case-1" state file state.json is damaged — repair it before continuing';
// The list is markup, so the sentence is escaped on its way in (esc() in dashboard-escape.js).
const DAMAGED_ESCAPED =
  "Case &quot;case-1&quot; state file state.json is damaged — repair it before continuing";
// The sentence carries the case's own name, so it is adversary-controlled.
const HOSTILE = 'Case <img src=x onerror="alert(1)"> is damaged';

interface Answer {
  status: number;
  /** The JSON body, or `undefined` for an answer with no JSON body (a stale server's 404 page). */
  body?: unknown;
}
/** What a request does: an answer, or `"offline"` for a connection that is gone. */
type Outcome = Answer | "offline";

interface Api {
  loadHypotheses: (caseId: string) => void;
  hypPatch: (id: string, patch: Record<string, unknown>) => void;
}

interface El {
  value: string;
  textContent: string;
  innerHTML: string;
}

const CARD_1 = { id: "h1", title: "RDP was the way in", status: "open", source: "analyst" };
const CARD_2 = { id: "h2", title: "A phishing mail was the way in", status: "open", source: "analyst" };
const GOOD: Answer = { status: 200, body: [CARD_1] };

const settle = () => new Promise((r) => setTimeout(r, 10));

/** A response that is strict about its body being read at most once. */
function response(answer: Answer) {
  let read = false;
  return {
    ok: answer.status >= 200 && answer.status < 300,
    status: answer.status,
    json: () => {
      if (read) return Promise.reject(new TypeError("body stream already read"));
      read = true;
      return answer.body === undefined
        ? Promise.reject(new SyntaxError("Unexpected token < in JSON"))
        : Promise.resolve(answer.body);
    },
  };
}

const settled = (outcome: Outcome) =>
  outcome === "offline"
    ? Promise.reject(new TypeError("Failed to fetch"))
    : Promise.resolve(response(outcome));

/** A list request the test answers later, to stage an answer that arrives out of order. */
function held() {
  let answer: (outcome: Outcome) => void = () => {};
  const pending = new Promise<Outcome>((resolve) => {
    answer = resolve;
  }).then(settled);
  return { pending, answer };
}

/** A page whose list requests are answered, in order, by what the test queued. */
function openPage() {
  const els = new Map<string, El>();
  const el = (id: string): El => {
    const have = els.get(id);
    if (have) return have;
    const made: El = { value: "", textContent: "", innerHTML: "" };
    els.set(id, made);
    return made;
  };
  el("caseId").value = "case-1";
  const page = {
    lists: [] as (Outcome | ReturnType<typeof held>)[],
    listUrls: [] as string[],
    write: { status: 204 } as Outcome,
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
      if ((init?.method ?? "GET") !== "GET") return settled(page.write);
      page.listUrls.push(url);
      const next = page.lists.shift();
      if (next === undefined) throw new Error(`no list answer queued for ${url}`);
      return typeof next === "object" && "pending" in next ? next.pending : settled(next);
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  const list = el("hypList");
  /** Ask for one case's list, answered by `outcome`, and wait for it to be drawn. */
  const load = async (caseId: string, outcome: Outcome) => {
    page.lists.push(outcome);
    api.loadHypotheses(caseId);
    await settle();
  };
  return { api, page, list, load };
}

describe("a Hypotheses list that fails to load says so (#2840)", () => {
  it.each([
    ["a damaged case file (409)", 409],
    ["a damaged hypotheses file (500)", 500],
    ["a busy server (503)", 503],
  ])("%s: the card stays and the server's sentence is shown", async (_name, status) => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", { status, body: { error: DAMAGED } });
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain(
      `<div class="manual-msg" role="status">${FAILED}${DAMAGED_ESCAPED}). ${STALE}</div>`,
    );
    expect(p.list.innerHTML).not.toContain(EMPTY);
    expect(p.list.innerHTML).not.toContain(`HTTP ${status}`);
    expect(p.list.innerHTML).not.toContain(RESTART);
  });

  it("the line is the first thing in the list, above the kept cards", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", { status: 503, body: { error: "server busy — retry shortly" } });
    expect(p.list.innerHTML.startsWith('<div class="manual-msg" role="status">')).toBe(true);
    expect(p.list.innerHTML.indexOf(FAILED)).toBeLessThan(p.list.innerHTML.indexOf("RDP was the way in"));
  });

  it("an error page with no JSON body: the card stays, with the status and the restart advice", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", { status: 404 });
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain(`${FAILED}HTTP 404 — ${RESTART} if this 404s). ${STALE}`);
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("a lost connection: the card stays and the list is marked as not loaded", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", "offline");
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain(`${FAILED}Failed to fetch`);
    expect(p.list.innerHTML).toContain(STALE);
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("a real empty list still reads 'No hypotheses yet', with no message", async () => {
    const p = openPage();
    await p.load("case-1", { status: 200, body: [] });
    expect(p.list.innerHTML).toContain(EMPTY);
    expect(p.list.innerHTML).not.toContain(FAILED);
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("a 200 answer that is not a list is a failed load, not an empty case", async () => {
    const p = openPage();
    await p.load("case-1", { status: 200, body: { hypotheses: [] } });
    expect(p.list.innerHTML).toContain(FAILED);
    expect(p.list.innerHTML).toContain(NOT_EMPTY);
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("the first load of a case fails: the message alone — no card, no 'No hypotheses yet'", async () => {
    const p = openPage();
    await p.load("case-1", { status: 409, body: { error: DAMAGED } });
    expect(p.list.innerHTML).toBe(
      `<div class="manual-msg" role="status">${FAILED}${DAMAGED_ESCAPED}). ${NOT_EMPTY}</div>`,
    );
  });

  it("a failed load after a case switch never shows the previous case's cards", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-2", { status: 503, body: { error: "server busy — retry shortly" } });
    expect(p.page.listUrls).toEqual(["/cases/case-1/hypotheses", "/cases/case-2/hypotheses"]);
    expect(p.list.innerHTML).not.toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain(`${FAILED}server busy — retry shortly). ${NOT_EMPTY}`);
    expect(p.list.innerHTML).not.toContain(EMPTY);
    expect(p.list.innerHTML).not.toContain(STALE);
  });

  it("a failed load of the first case is not carried into the next case's good list", async () => {
    const p = openPage();
    await p.load("case-1", { status: 409, body: { error: DAMAGED } });
    await p.load("case-2", { status: 200, body: [CARD_2] });
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain(FAILED);
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("a good load after a failure removes the message", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", { status: 503, body: { error: "server busy — retry shortly" } });
    expect(p.list.innerHTML).toContain(FAILED);
    await p.load("case-1", GOOD);
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain(FAILED);
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("a hostile sentence lands as text, never as markup", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    await p.load("case-1", { status: 409, body: { error: HOSTILE } });
    expect(p.list.innerHTML).toContain(
      `${FAILED}Case &lt;img src=x onerror=&quot;alert(1)&quot;&gt; is damaged)`,
    );
    expect(p.list.innerHTML).not.toContain("<img");
  });
});

describe("only the newest list request is applied (#2840)", () => {
  it("an older request that fails late does not mark a newer good list as not loaded", async () => {
    const p = openPage();
    const slow = held();
    p.page.lists.push(slow);
    p.api.loadHypotheses("case-1");
    await p.load("case-1", GOOD);
    expect(p.list.innerHTML).toContain("RDP was the way in");

    slow.answer({ status: 503, body: { error: "server busy — retry shortly" } });
    await settle();
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain(FAILED);
    expect(p.list.innerHTML).not.toContain("manual-msg");
  });

  it("an older request that succeeds late does not clear a newer failure", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    const slow = held();
    p.page.lists.push(slow);
    p.api.loadHypotheses("case-1");
    await p.load("case-1", { status: 409, body: { error: DAMAGED } });
    expect(p.list.innerHTML).toContain(FAILED);

    slow.answer({ status: 200, body: [] });
    await settle();
    expect(p.list.innerHTML).toContain(`${FAILED}${DAMAGED_ESCAPED}`);
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });

  it("a late answer for the previous case is not drawn under the new case", async () => {
    const p = openPage();
    const slow = held();
    p.page.lists.push(slow);
    p.api.loadHypotheses("case-1");
    await p.load("case-2", { status: 200, body: [CARD_2] });
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");

    slow.answer(GOOD);
    await settle();
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain("RDP was the way in");
  });

  it("a late failure for the previous case is not drawn under the new case", async () => {
    const p = openPage();
    const slow = held();
    p.page.lists.push(slow);
    p.api.loadHypotheses("case-1");
    await p.load("case-2", { status: 200, body: [CARD_2] });

    slow.answer({ status: 409, body: { error: DAMAGED } });
    await settle();
    expect(p.list.innerHTML).toContain("A phishing mail was the way in");
    expect(p.list.innerHTML).not.toContain(FAILED);
  });
});

describe("a refused edit's line survives a reload that fails too (#2837, #2840)", () => {
  it("a closed case (423), then the reload answers 503: the card, its line and the load line", async () => {
    const p = openPage();
    await p.load("case-1", GOOD);
    p.page.write = { status: 423, body: { error: "The case is closed — reopen it before changing it" } };
    p.page.lists.push({ status: 503, body: { error: "server busy — retry shortly" } });
    p.api.hypPatch("h1", { status: "refuted" });
    await settle();
    expect(p.list.innerHTML).toContain("RDP was the way in");
    expect(p.list.innerHTML).toContain("not saved: The case is closed — reopen it before changing it");
    expect(p.list.innerHTML).toContain(`${FAILED}server busy — retry shortly). ${STALE}`);
    expect(p.list.innerHTML).not.toContain(EMPTY);
  });
});
