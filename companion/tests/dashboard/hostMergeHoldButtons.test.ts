// #2828 — a case waiting for a duplicate-host decision holds its AI passes on purpose, and every
// gated route answers 409 `host_merge_decision_required`. The status pill said "on hold"; the
// button the analyst pressed said "failed" and printed that code. Each button now says the hold
// in the pill's words and names the panel that releases it. Re-synthesize and Second opinion are
// in synthAiOffMessage.test.ts; the other three are here.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const CODE = "host_merge_decision_required";
// Host names are the case's own text. Only the COUNT of pairs may reach the screen.
const HOSTILE_HOST = '<img src=x onerror="alert(1)">';
const HOLD = {
  error: CODE,
  pairs: [
    { canonical: "WS-SAMPLE-01", other: HOSTILE_HOST },
    { canonical: "WS-SAMPLE-02", other: "ws-sample-02.example.test" },
  ],
};
const holdText = (what: string, count = "2 possible duplicate hosts") =>
  `${what} on hold — ${count} awaiting a merge decision. Decide each pair in the Duplicate Hosts panel.`;

type Handler = (e: { stopPropagation: () => void }) => void;
interface El {
  value: string;
  textContent: string;
  innerHTML: string;
  disabled: boolean;
  checked: boolean;
  title: string;
  onclick: Handler | null;
  dataset: Record<string, string>;
  style: Record<string, string>;
  classList: { add: () => void; remove: () => void; toggle: () => void };
  addEventListener: (type: string, fn: Handler) => void;
  click: () => void;
  querySelectorAll: () => unknown[];
  scrollIntoView: () => void;
}

/** A page whose AI routes all answer `body` with a 409, strict about reading a body once. */
function heldPage(body: unknown = HOLD) {
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
      checked: true,
      title: "",
      onclick: null,
      dataset: {},
      style: {},
      classList: { add: () => {}, remove: () => {}, toggle: () => {} },
      addEventListener: (type, fn) => {
        if (type === "click") handlers.push(fn);
      },
      click: () => handlers.forEach((fn) => fn({ stopPropagation: () => {} })),
      querySelectorAll: () => [],
      scrollIntoView: () => {},
    };
    els.set(id, made);
    return made;
  };
  el("caseId").value = "case-1";
  const fetched: string[] = [];
  const held = () => {
    let read = false;
    return {
      ok: false,
      status: 409,
      json: () => {
        if (read) return Promise.reject(new TypeError("body stream already read"));
        read = true;
        return Promise.resolve(body);
      },
    };
  };
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: () => ({ value: "High" }),
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    // The Duplicate Hosts panel's re-read of the case gets an empty list; every AI route is held.
    fetch: (url: string) => {
      fetched.push(url);
      return Promise.resolve(
        url.includes("/host-duplicates")
          ? { ok: true, status: 200, json: () => Promise.resolve({ pending: [], dismissed: [] }) }
          : held(),
      );
    },
    applyHeavyAiJobLock: () => {},
    loadJobs: () => {},
    loadSynthMeta: () => {},
    markSectionRevealed: () => {},
    render: () => {},
  };
  return { el, globals, fetched };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

function expectHold(text: string, what: string) {
  expect(text).toBe(holdText(what));
  expect(text).not.toContain(CODE);
  expect(text).not.toMatch(/failed|did not run|restart|error/i);
  expect(text).not.toContain("onerror");
}

const PRELOAD = ["dashboard-escape.js", "dashboard-host-duplicates.js"];

interface SecondLookApi {
  initSecondLook: () => void;
  loadSecondLookPreview: (caseId: string) => Promise<void>;
  runSecondLook: () => Promise<void>;
}

async function pressSecondLook(body?: unknown) {
  const page = heldPage(body);
  const api = loadDashboardModule<SecondLookApi>("dashboard-second-look.js", PRELOAD, page.globals);
  api.initSecondLook();
  await api.loadSecondLookPreview("case-1");
  await api.runSecondLook();
  await settle();
  return page;
}

describe("a press held by the duplicate-host gate says so (#2828)", () => {
  it("deep pass: guidance that names the panel, not 'Deep pass failed'", async () => {
    const { el, globals, fetched } = heldPage();
    loadDashboardModule<{ runDeepPass: () => void }>(
      "dashboard-deep-pass.js",
      PRELOAD,
      globals,
    ).runDeepPass();
    await settle();
    expectHold(el("deepPassGuidance").innerHTML, "Deep pass");
    expect(el("deepPassResult").innerHTML).toBe("");
    expect(fetched).toContain("/cases/case-1/host-duplicates");
  });

  it("second look: the hold in the status line", async () => {
    const { el, fetched } = await pressSecondLook();
    expectHold(el("secondLookStatus").textContent, "Second look");
    expect(fetched).toContain("/cases/case-1/host-duplicates");
  });

  it("second look: any other refusal keeps a space after 'did not run:'", async () => {
    const { el } = await pressSecondLook({ error: "budget exceeded" });
    expect(el("secondLookStatus").textContent).toBe("The second look did not run: budget exceeded");
  });

  it("hypotheses generate: the hold beside the button, with no restart advice", async () => {
    const { el, globals, fetched } = heldPage();
    loadDashboardModule<{ initHypotheses: () => void }>(
      "dashboard-hypotheses.js",
      PRELOAD,
      globals,
    ).initHypotheses();
    el("hypGenerateBtn").click();
    await settle();
    expectHold(el("hypGenMsg").textContent, "Hypothesis generation");
    expect(el("hypGenerateBtn").disabled).toBe(false);
    expect(fetched).toContain("/cases/case-1/host-duplicates");
  });
});

interface HoldApi {
  hostMergeHold: (status: number, body: unknown) => boolean;
  hostMergeHoldText: (what: string, body?: unknown) => string;
}

describe("the shared duplicate-host hold check (#2828)", () => {
  const load = () => {
    const page = heldPage();
    return { ...page, api: loadDashboardModule<HoldApi>("dashboard-host-duplicates.js", [], page.globals) };
  };

  it("matches only a 409 carrying the gate's code, and only then re-reads the panel", () => {
    const { api, fetched } = load();
    expect(api.hostMergeHold(409, { error: "presidio_approval_required" })).toBe(false);
    expect(api.hostMergeHold(409, { error: "AI is off for this case" })).toBe(false);
    expect(api.hostMergeHold(500, { error: CODE })).toBe(false);
    expect(api.hostMergeHold(409, null)).toBe(false);
    expect(fetched).toEqual([]);
    expect(api.hostMergeHold(409, { error: CODE })).toBe(true);
    expect(fetched).toContain("/cases/case-1/host-duplicates");
  });

  it("counts the pairs the way the status pill does, and never prints one", () => {
    const { api } = load();
    expect(api.hostMergeHoldText("Deep pass", HOLD)).toBe(holdText("Deep pass"));
    expect(api.hostMergeHoldText("Deep pass", { error: CODE, pairs: [HOLD.pairs[0]] })).toBe(
      holdText("Deep pass", "1 possible duplicate host"),
    );
    expect(api.hostMergeHoldText("Deep pass", { error: CODE })).toBe(
      holdText("Deep pass", "possible duplicate hosts"),
    );
    expect(api.hostMergeHoldText("Deep pass", { error: CODE, pairs: "not a list" })).toBe(
      holdText("Deep pass", "possible duplicate hosts"),
    );
  });
});
