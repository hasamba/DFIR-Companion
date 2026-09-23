import { readFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// Promoting what the missed-evidence review found (#1568), driven the way the browser drives it.
//
// The review has always been read-only. This is the half that WRITES: a promoted row enters the
// forensic timeline carrying the model's grade as its severity, and severity is what decides
// whether the analysis AI ever reads it. So the suite pins the things that make that press a real
// decision rather than a bookmark:
//
//   1. SELECT-ALL MEANS WHAT IS ON SCREEN. The tooling filter, the grade floor, the confidence
//      floor and the draw cap each narrow the table, and a row held back by any of them must never
//      reach the post body. A select-all the analyst could not see is the bug this exists to stop.
//   2. THE BODY CARRIES WHAT WAS DISPLAYED — the ids AND the grades, because the grade is the
//      severity being written.
//   3. AN EMPTY SELECTION DOES NOT POST, and a refusal leaves the panel usable and says why.
//   4. NOTHING ESCAPES AS AN UNHANDLED REJECTION. Every path through the promote clears its flag
//      in a `finally`, and a floated promise in a dashboard module fails AFTER the test passes.

interface Api {
  loadJevReview(caseId: string): Promise<void>;
  initJevReview(): void;
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
  checked: boolean;
  disabled: boolean;
  title: string;
  dataset: Record<string, string>;
  classList: { add(c: string): void; remove(c: string): void; contains(c: string): boolean };
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelector(sel: string): FakeEl | null;
  scrollIntoView(): void;
}

/** Does the painted markup really contain this control? A selector that matches nothing is null. */
function present(html: string, sel: string): boolean {
  const name = sel.slice(1);
  if (sel.startsWith("#")) return html.includes(`id="${name}"`);
  return new RegExp(`class="[^"]*\\b${name}\\b[^"]*"`).test(html);
}

function makeEl(id: string): FakeEl {
  const handlers: Record<string, ((e: unknown) => void)[]> = {};
  // Cleared whenever innerHTML is replaced: a repaint makes NEW elements in a browser, and reusing
  // one object across paints would stack a listener per render and fire one click N times.
  let children = new Map<string, FakeEl>();
  let html = "";
  const el: FakeEl = {
    id,
    value: "",
    textContent: "",
    get innerHTML() {
      return html;
    },
    set innerHTML(next: string) {
      html = next;
      children = new Map();
    },
    checked: true,
    disabled: false,
    title: "",
    dataset: {},
    classList: { add: () => {}, remove: () => {}, contains: () => false },
    addEventListener: (type, fn) => {
      (handlers[type] ||= []).push(fn);
    },
    fire: (type, ev) => (handlers[type] || []).forEach((f) => f(ev ?? {})),
    querySelector: (sel) => {
      if (!present(html, sel)) return null;
      let cur = children.get(sel);
      if (!cur) {
        cur = makeEl(sel);
        children.set(sel, cur);
      }
      return cur;
    },
    scrollIntoView: () => {},
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
    fetch: (url: string, init?: { method?: string; body?: string }) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          method: init?.method || "GET",
          body: init?.body || "",
          resolve: (body, i = {}) =>
            res({ ok: i.ok ?? true, status: i.status ?? 200, json: () => Promise.resolve(body) }),
          reject: rej,
        });
      }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-jev-review.js",
    ["dashboard-escape.js", "dashboard-jev-review-format.js"],
    globals,
  );
  const panel = () => el("jevReviewPanel");
  /** Re-read after every paint, exactly as the module does. */
  const inPanel = (sel: string): FakeEl | null => panel().querySelector(sel);
  return { api, pending, el, panel, inPanel };
}

/**
 * Let every queued microtask settle. The module chains .then/.then/.catch/.finally, and the panel
 * repaints in the last of them, so one tick is not enough to see the result of a promote.
 */
const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => {
  await tick();
  await tick();
  await tick();
  await tick();
};

interface Row {
  id: string;
  score: number;
  grade: string;
  confidence: number;
  tooling: number;
  description: string;
  artifactName?: string;
  timestamp: string;
}

const row = (
  id: string,
  grade: string,
  confidence: number,
  tooling = 0.1,
  extra: Partial<Row> = {},
): Row => ({
  id,
  score: GRADE_SCORE[grade] ?? 0,
  grade,
  confidence,
  tooling,
  description: `row ${id}`,
  artifactName: "Windows.Sigma.Base",
  timestamp: "2026-03-01T04:05:06Z",
  ...extra,
});

const GRADE_SCORE: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

// One reading with every shape the filters have to separate: a Critical, a High whose confidence is
// low, a Medium, and a Critical the model read as the investigator's own tooling.
const ROWS: Row[] = [
  row("e-crit", "Critical", 0.95),
  row("e-high", "High", 0.4),
  row("e-med", "Medium", 0.9),
  row("e-tool", "Critical", 0.99, 0.87, { description: "velociraptor rule file" }),
];

const REVIEW = (rows: Row[] = ROWS) => ({
  model: "typesafe/jev-1.13",
  rows,
  matched: rows.length,
  read: rows.length,
  graded: rows.length,
  alreadyAnalyzed: 0,
  capped: false,
  readAll: false,
  usage: { inputTokens: 10, outputTokens: 2, costUSD: 0.0001 },
});

/** A panel with a case connected, Jev configured, and one review already returned. */
async function reviewed(rows: Row[] = ROWS) {
  const h = harness();
  h.api.initJevReview();
  const load = h.api.loadJevReview("case-1");
  h.pending.shift()!.resolve({ configured: true, model: "typesafe/jev-1.13" });
  await load;
  await settle();
  h.el("jevRunBtn").fire("click");
  const req = h.pending.shift()!;
  expect(req.url).toBe("/cases/case-1/jev/review");
  req.resolve(REVIEW(rows));
  await settle();
  return h;
}

/** Tick everything the table currently draws. */
function selectAll(h: ReturnType<typeof harness>): void {
  h.inPanel("#jevSelectAll")!.fire("click");
}

const promotePosts = (h: ReturnType<typeof harness>): Deferred[] =>
  h.pending.filter((p) => p.url.endsWith("/jev/promote"));

/**
 * Open the confirmation and answer it. Returns the POST THIS call made, if it made one — the
 * resolved ones stay in `pending`, so a `find` would hand back the previous promote's request.
 */
function promote(h: ReturnType<typeof harness>): Deferred | undefined {
  const before = promotePosts(h).length;
  h.inPanel("#jevPromoteBtn")!.fire("click");
  const go = h.inPanel("#jevPromoteGo");
  if (go) go.fire("click");
  const after = promotePosts(h);
  return after.length > before ? after[after.length - 1] : undefined;
}

const postedIds = (req: Deferred): string[] =>
  (JSON.parse(req.body).rows as { id: string }[]).map((r) => r.id);

// A floated promise in a dashboard module fails AFTER the test passes, as a process-level warning.
// Collected per test rather than trusted to a global reporter.
const unhandled: unknown[] = [];
const onUnhandled = (e: unknown) => unhandled.push(e);
beforeEach(() => {
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
});
afterEach(async () => {
  await settle();
  process.off("unhandledRejection", onUnhandled);
  expect(unhandled, "a promise rejected with nobody listening").toEqual([]);
});

describe("select all", () => {
  it("ticks only the rows the filters show, never everything graded", async () => {
    const h = await reviewed();
    selectAll(h);
    // Three of four: the tooling row is hidden by the filter that is ticked by default.
    expect(h.panel().innerHTML).toContain("Promote 3 selected rows");
    expect(h.panel().innerHTML).toContain("Select all 3 shown");
  });

  it("never puts a row the tooling filter hid into the posted body", async () => {
    const h = await reviewed();
    selectAll(h);
    const req = promote(h)!;
    expect(postedIds(req).sort()).toEqual(["e-crit", "e-high", "e-med"]);
    expect(postedIds(req), "a hidden row reached the case record").not.toContain("e-tool");
  });

  it("reaches the hidden row only once the analyst unhides it", async () => {
    const h = await reviewed();
    h.el("jevHideTooling").checked = false;
    h.el("jevHideTooling").fire("change");
    selectAll(h);
    expect(postedIds(promote(h)!)).toContain("e-tool");
  });

  it("stops at the draw cap — an undrawn row is one the analyst could not see", async () => {
    const many = Array.from({ length: 350 }, (_, i) => row(`e-${i}`, "High", 0.9));
    const h = await reviewed(many);
    selectAll(h);
    const req = promote(h)!;
    expect(postedIds(req)).toHaveLength(300);
    expect(h.panel().innerHTML).toContain("50 more are not drawn");
  });
});

describe("the grade and confidence filters", () => {
  const setGrade = (h: ReturnType<typeof harness>, v: string) => {
    h.el("jevGradeFilter").value = v;
    h.el("jevGradeFilter").fire("change");
  };
  const setConfidence = (h: ReturnType<typeof harness>, pct: number) => {
    h.el("jevMinConfidence").value = String(pct);
    h.el("jevMinConfidence").fire("input");
  };

  it("narrow what select-all can reach", async () => {
    const h = await reviewed();
    setGrade(h, "High");
    selectAll(h);
    expect(postedIds(promote(h)!).sort()).toEqual(["e-crit", "e-high"]);
  });

  it("drop a row the model was unsure about", async () => {
    const h = await reviewed();
    setConfidence(h, 80);
    selectAll(h);
    // e-high is graded High but the model gave it 40% — below an 80% floor.
    expect(postedIds(promote(h)!).sort()).toEqual(["e-crit", "e-med"]);
  });

  it("compose, and the caption accounts for every row they took out", async () => {
    const h = await reviewed();
    setGrade(h, "High");
    setConfidence(h, 80);
    selectAll(h);
    expect(postedIds(promote(h)!)).toEqual(["e-crit"]);
    expect(h.panel().innerHTML).toContain("are below the grade or confidence filter");
  });

  it("cannot smuggle a ticked row through after the analyst tightens them", async () => {
    const h = await reviewed();
    selectAll(h);
    setGrade(h, "Critical");
    const req = promote(h)!;
    expect(postedIds(req), "a row ticked before the filter narrowed still posted").toEqual(["e-crit"]);
  });
});

describe("what the post says", () => {
  it("carries the id, the grade, the confidence and the score actually displayed", async () => {
    const h = await reviewed();
    setTick(h, "e-crit", true);
    const req = promote(h)!;
    const body = JSON.parse(req.body);
    expect(req.url).toBe("/cases/case-1/jev/promote");
    expect(req.method).toBe("POST");
    expect(body.rows).toEqual([{ id: "e-crit", grade: "Critical", confidence: 0.95, score: 4 }]);
    // The model that made the judgement travels with it.
    expect(body.model).toBe("typesafe/jev-1.13");
  });

  it("does not post an empty selection", async () => {
    const h = await reviewed();
    // Nothing ticked: the press must not even open the question.
    h.inPanel("#jevPromoteBtn")!.fire("click");
    expect(h.inPanel("#jevPromoteGo"), "a confirmation appeared with nothing selected").toBeNull();
    expect(h.pending.some((p) => p.url.endsWith("/jev/promote"))).toBe(false);
  });

  it("does not post when the selection empties between the question and the answer", async () => {
    const h = await reviewed();
    setTick(h, "e-crit", true);
    h.inPanel("#jevPromoteBtn")!.fire("click");
    // The analyst forces the disabled filter while the question is up. The guard is in the code,
    // not in the `disabled` attribute.
    h.el("jevGradeFilter").value = "Critical";
    h.el("jevMinConfidence").value = "100";
    h.el("jevMinConfidence").fire("input");
    h.inPanel("#jevPromoteGo")!.fire("click");
    expect(h.pending.some((p) => p.url.endsWith("/jev/promote"))).toBe(false);
    expect(h.panel().innerHTML).toContain("Nothing is selected, so nothing was sent.");
  });
});

/** Tick or untick one row through the table's delegated listener, as a browser click does. */
function setTick(h: ReturnType<typeof harness>, id: string, checked: boolean): void {
  h.inPanel(".jev-table")!.fire("change", { target: { dataset: { id }, checked } });
}

describe("the confirmation, before anything is written", () => {
  it("says how many rows, whose judgement, and what severity decides", async () => {
    const h = await reviewed();
    selectAll(h);
    h.inPanel("#jevPromoteBtn")!.fire("click");
    const html = h.panel().innerHTML;
    expect(html).toContain("Promote 3 row(s) into the forensic timeline?");
    expect(html).toContain("typesafe/jev-1.13 gave it as its severity");
    expect(html).toContain("decides whether the analysis AI ever reads a row");
    expect(html).toContain("cannot undo it");
    expect(html).toContain("reports anything it skips");
  });

  it("is inline markup — a browser modal blocks the automation harness", async () => {
    const src = await readFile(
      new URL("../../../public/js/dashboard-jev-review.js", import.meta.url),
      "utf8",
    );
    const code = src
      .split("\n")
      .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
      .join("\n");
    expect(code).not.toMatch(/\bconfirm\s*\(/);
    expect(code).not.toMatch(/\balert\s*\(/);
    expect(code).not.toMatch(/\bprompt\s*\(/);
  });

  it("can be cancelled, and nothing is sent", async () => {
    const h = await reviewed();
    selectAll(h);
    h.inPanel("#jevPromoteBtn")!.fire("click");
    h.inPanel("#jevPromoteCancel")!.fire("click");
    expect(h.pending.some((p) => p.url.endsWith("/jev/promote"))).toBe(false);
    expect(h.panel().innerHTML).toContain("Promote 3 selected rows");
  });
});

describe("after a promote", () => {
  async function promoted(answer: Record<string, unknown> = { promoted: 3, skipped: 0, reasons: [] }) {
    const h = await reviewed();
    selectAll(h);
    promote(h)!.resolve(answer);
    await settle();
    return h;
  }

  it("reports the server's own numbers and reasons", async () => {
    const h = await promoted({ promoted: 2, skipped: 1, reasons: ["e-med is already in the timeline"] });
    const html = h.panel().innerHTML;
    expect(html).toContain("2 row(s) are now in the forensic timeline");
    expect(html).toContain("1 were skipped");
    expect(html).toContain("e-med is already in the timeline");
  });

  // `reasons` is NOT a skip list. The route puts an informational line in it when it promotes a row
  // AT Info, and a "why these were skipped" heading would call a promoted row a skipped one.
  it("heads the server's reasons as notes, never as skips", async () => {
    const h = await promoted({ promoted: 3, skipped: 0, reasons: ["1 row promoted at Info"] });
    const html = h.panel().innerHTML;
    expect(html).toContain("The server also reported:");
    expect(html).toContain("1 row promoted at Info");
    expect(html, "a reasons list headed as skips contradicts a promote").not.toMatch(/skipped[^<]*<ul/);
  });

  // THE WHOLE POINT OF THE SEVERITY QUESTION. An Info row lands in the timeline, where the analyst
  // can read it, and synthesis still never sees it. Promoting a batch of them and saying nothing
  // would leave the analyst believing the AI now reads evidence it cannot.
  it("says an Info row is in the timeline but still invisible to the AI", async () => {
    const h = await reviewed([row("e-info", "Info", 0.8), row("e-hi", "High", 0.8)]);
    selectAll(h);
    promote(h)!.resolve({ promoted: 2, skipped: 0, reasons: [] });
    await settle();
    const html = h.panel().innerHTML;
    expect(html).toContain("1 of the row(s) you sent were graded Info");
    expect(html).toContain("the analysis AI never sees it");
    expect(html).toContain("only rows above Info reach synthesis");
    expect(html).toContain("changed what you can see, not what the AI reads");
  });

  it("does not raise the Info caveat when nothing Info was sent", async () => {
    const h = await promoted();
    expect(h.panel().innerHTML).not.toContain("graded Info");
  });

  it("surfaces a closed case or an unconfigured server as the reason, not as silence", async () => {
    const h = await reviewed();
    selectAll(h);
    promote(h)!.resolve({ error: "case is closed" }, { ok: false, status: 423 });
    await settle();
    expect(h.panel().innerHTML).toContain("Nothing was promoted: case is closed");
  });

  it("stops offering the promoted rows — they are in the timeline now", async () => {
    const h = await promoted();
    const html = h.panel().innerHTML;
    expect(html).toContain("Sent");
    expect(html).toContain("Select all 0 shown");
    // And they stay visible: removing them would leave the analyst unable to see what they did.
    expect(html).toContain("row e-crit");
  });

  it("keeps a sent row out of a later select-all and out of a later post", async () => {
    const h = await promoted();
    h.el("jevHideTooling").checked = false;
    h.el("jevHideTooling").fire("change");
    selectAll(h);
    const req = promote(h)!;
    expect(postedIds(req)).toEqual(["e-tool"]);
  });

  it("escapes the server's strings — the descriptions are attacker-influenced", async () => {
    const h = await reviewed([
      row("e-x", "High", 0.9, 0.1, { description: '<img src=x onerror="alert(1)">' }),
    ]);
    selectAll(h);
    promote(h)!.resolve({ promoted: 1, skipped: 0, reasons: ["<script>alert(2)</script>"] });
    await settle();
    const html = h.panel().innerHTML;
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;img");
  });
});

describe("the promoting flag", () => {
  it("blocks a second promote while one is in flight", async () => {
    const h = await reviewed();
    selectAll(h);
    promote(h);
    const posts = () => promotePosts(h).length;
    expect(posts()).toBe(1);
    // The flag is the lock, not the `disabled` attribute: forcing the attribute off must not let a
    // second write start.
    const btn = h.inPanel("#jevPromoteBtn");
    if (btn) {
      btn.disabled = false;
      btn.fire("click");
      const go = h.inPanel("#jevPromoteGo");
      if (go) go.fire("click");
    }
    expect(posts(), "a second promote started while the first was still going").toBe(1);
  });

  it("comes off when the request rejects, and says why", async () => {
    const h = await reviewed();
    selectAll(h);
    promote(h)!.reject(new Error("socket hang up"));
    await settle();
    expect(h.panel().innerHTML).toContain("Nothing was promoted: socket hang up");
    // And the panel really works again, not merely looks enabled.
    selectAll(h);
    expect(postedIds(promote(h)!)).toHaveLength(3);
  });

  it("turns a 400 into a reason in the panel, with the rows still promotable", async () => {
    const h = await reviewed();
    selectAll(h);
    promote(h)!.resolve({ error: "no rows in the selection" }, { ok: false, status: 400 });
    await settle();
    expect(h.panel().innerHTML).toContain("Nothing was promoted: no rows in the selection");
    // Nothing was written, so nothing is badged Sent and the rows can be tried again.
    expect(h.panel().innerHTML).toContain("Select all 3 shown");
  });

  it("does not let an abandoned promote paint onto the next case", async () => {
    const h = await reviewed();
    selectAll(h);
    const inFlight = promote(h)!;
    const load = h.api.loadJevReview("case-2");
    // The status probe for the new case, NOT the promote still in flight.
    h.pending
      .find((p) => p.url.endsWith("/jev/status"))!
      .resolve({
        configured: true,
        model: "typesafe/jev-1.13",
      });
    await load;
    await settle();
    inFlight.resolve({ promoted: 999, skipped: 0, reasons: [] });
    await settle();
    expect(h.panel().innerHTML).not.toContain("999");
  });
});

describe("what the panel says it does", () => {
  const html = () => readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  it("no longer claims the panel promotes nothing", async () => {
    const page = await html();
    expect(page).not.toContain("This review promotes nothing and changes no case data.");
    expect(page).not.toContain("It promotes nothing and changes no case data.");
    expect(page).not.toContain("It promotes nothing and writes no case data.");
  });

  it("says instead what pressing the button does, before it is pressed", async () => {
    const page = await html();
    expect(page).toContain("Reviewing changes nothing. Promoting writes to the case.");
    expect(page).toContain("carrying the model&rsquo;s grade as its severity");
    expect(page).toContain("which is what decides whether the AI ever reads it");
  });

  it("carries the two filters as native, keyboard-operable controls", async () => {
    const page = await html();
    expect(page).toContain('id="jevGradeFilter"');
    expect(page).toContain('id="jevMinConfidence"');
    expect(page).toMatch(/<select id="jevGradeFilter"/);
    expect(page).toMatch(/<input type="range" id="jevMinConfidence"/);
    // Labelled, or the control is unusable without sight.
    expect(page).toContain('for="jevGradeFilter"');
    expect(page).toContain('for="jevMinConfidence"');
  });

  it("leaves focus visible — nothing in this panel suppresses the ring", async () => {
    const css = await readFile(new URL("../../../public/css/dashboard-panels.css", import.meta.url), "utf8");
    const jev = css.slice(css.indexOf(".jev-note"));
    expect(jev).not.toContain("outline: none");
    expect(jev).toContain(".jev-pick");
    const a11y = await readFile(new URL("../../../public/css/a11y.css", import.meta.url), "utf8");
    expect(a11y).toContain(":focus-visible");
  });
});
