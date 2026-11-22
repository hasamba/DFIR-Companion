// #2832 — the notebook's Promote button and the Hypotheses panel's Add button both POST a new
// hypothesis. When the server refused, each read the answer's body and then threw it away: the
// analyst saw "HTTP 423 — restart the companion server if this 404s" where the server had said
// the case is closed, and went to restart a healthy server. Each button now prints the server's
// own sentence, and keeps the restart advice only for an answer that carries no sentence.
//
// The AI-off refusal and the duplicate-host hold are NOT fed to this route here: it is neither
// metered nor host-gated, so the server cannot send them.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const RESTART = "restart the companion server";
const CLOSED = "Case case-1 is closed — reopen it to make changes.";
const REPAIR = "The audit log for this case needs repair before anything else is written.";
// The sentence can carry the case's own text (a case name), so it is adversary-controlled.
const HOSTILE = 'Case <img src=x onerror="alert(1)"> is closed.';

type Handler = (e: { stopPropagation: () => void }) => void;
interface El {
  value: string;
  textContent: string;
  innerHTML: string;
  disabled: boolean;
  onclick: (() => void) | null;
  dataset: Record<string, string>;
  style: Record<string, string>;
  classList: { add: () => void; remove: () => void; toggle: () => void };
  addEventListener: (type: string, fn: Handler) => void;
  querySelectorAll: () => unknown[];
  scrollIntoView: () => void;
}

interface Refusal {
  status: number;
  /** The JSON body, or `undefined` for an answer whose body is not JSON (a stale server's 404). */
  body?: unknown;
}

interface Api {
  initHypotheses: () => void;
  promoteToHypothesis: (id: string) => void;
}

/** A page whose hypothesis POST is refused with `refusal`, strict about reading a body once. */
function refusedPage(refusal: Refusal) {
  const els = new Map<string, El>();
  const el = (id: string): El => {
    const have = els.get(id);
    if (have) return have;
    const made: El = {
      value: "",
      textContent: "",
      innerHTML: "",
      disabled: false,
      onclick: null,
      dataset: {},
      style: {},
      classList: { add: () => {}, remove: () => {}, toggle: () => {} },
      addEventListener: () => {},
      querySelectorAll: () => [],
      scrollIntoView: () => {},
    };
    els.set(id, made);
    return made;
  };
  el("caseId").value = "case-1";
  const refused = () => {
    let read = false;
    return {
      ok: false,
      status: refusal.status,
      json: () => {
        if (read) return Promise.reject(new TypeError("body stream already read"));
        read = true;
        return refusal.body === undefined
          ? Promise.reject(new SyntaxError("Unexpected token < in JSON"))
          : Promise.resolve(refusal.body);
      },
    };
  };
  const posted: string[] = [];
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: () => null,
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: (url: string, init?: { method?: string }) => {
      if (init?.method === "POST" && url.endsWith("/hypotheses")) {
        posted.push(url);
        return Promise.resolve(refused());
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
    },
    investigatorName: () => "analyst",
    notebookEntry: (id: string) => (id === "n1" ? { id, text: "The intruder came in over RDP" } : null),
    render: () => {},
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  api.initHypotheses();
  return { api, el, posted };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

/** Press Add hypothesis with a title typed in; returns the line beside the button. */
async function pressAdd(refusal: Refusal) {
  const page = refusedPage(refusal);
  page.el("hypTitle").value = "RDP was the way in";
  page.el("hypAddBtn").onclick?.();
  await settle();
  expect(page.posted).toEqual(["/cases/case-1/hypotheses"]);
  return page.el("hypMsg");
}

/** Press Promote on a notebook entry; returns the notebook's message line. */
async function pressPromote(refusal: Refusal) {
  const page = refusedPage(refusal);
  page.api.promoteToHypothesis("n1");
  await settle();
  expect(page.posted).toEqual(["/cases/case-1/hypotheses"]);
  return page.el("nbMsg");
}

const BUTTONS = [
  { name: "add", press: pressAdd, prefix: "failed: ", held: "Add hypothesis" },
  { name: "promote", press: pressPromote, prefix: "promote failed: ", held: "Promote" },
] as const;

describe.each(BUTTONS)("hypothesis $name shows the server's refusal sentence (#2832)", (b) => {
  it("a closed case (423): the server's sentence, no status code, no restart advice", async () => {
    const msg = await b.press({ status: 423, body: { error: CLOSED } });
    expect(msg.textContent).toBe(b.prefix + CLOSED);
    expect(msg.textContent).not.toContain(RESTART);
    expect(msg.textContent).not.toContain("HTTP 423");
  });

  it("a 409 that carries a sentence and a code: the sentence", async () => {
    const msg = await b.press({ status: 409, body: { error: REPAIR, code: "audit_log_needs_repair" } });
    expect(msg.textContent).toBe(b.prefix + REPAIR);
    expect(msg.textContent).not.toContain(RESTART);
    expect(msg.textContent).not.toContain("audit_log_needs_repair");
  });

  it("a 404 with no JSON body keeps the status and the restart advice", async () => {
    const msg = await b.press({ status: 404 });
    expect(msg.textContent).toBe(`${b.prefix}HTTP 404 — ${RESTART} if this 404s`);
  });

  it.each([
    ["no error field", {}],
    ["an empty sentence", { error: "" }],
    ["a non-text error", { error: { message: "nested" } }],
  ])("a refusal with %s falls back to the status and the restart advice", async (_label, body) => {
    const msg = await b.press({ status: 500, body });
    expect(msg.textContent).toBe(`${b.prefix}HTTP 500 — ${RESTART} if this 404s`);
  });

  it("an anonymization hold still reads as a hold, not a failure", async () => {
    const msg = await b.press({ status: 409, body: { error: "presidio_approval_required", findings: [] } });
    expect(msg.textContent).toBe(`${b.held} held for Presidio approval — review in Anonymization`);
  });

  it("a hostile sentence lands as text, never as markup", async () => {
    const msg = await b.press({ status: 423, body: { error: HOSTILE } });
    expect(msg.textContent).toBe(b.prefix + HOSTILE);
    expect(msg.innerHTML).toBe("");
  });
});
