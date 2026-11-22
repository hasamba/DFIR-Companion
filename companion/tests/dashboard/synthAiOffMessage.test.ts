import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2826 — a 409 that is not the Presidio hold (since #2780: "AI is off for this case") had its body
// read twice, once to test for the hold and once more to report it. A response body can be read
// only once, so the analyst saw "body stream already read" instead of the server's own sentence.
// The fake response below is as strict as a real one: the second json() rejects.

interface ScopeApi {
  resynthesize: () => void;
}

interface OpinionApi {
  runSecondOpinion: () => void;
}

interface FakeEl {
  value: string;
  textContent: string;
  innerHTML: string;
  className: string;
  disabled: boolean;
  checked: boolean;
  style: Record<string, string>;
}

const AI_OFF = "AI is off for this case — turn AI on to use this";
const BODY_READ_TWICE = "Failed to execute 'json' on 'Response': body stream already read";

function oneShotResponse(status: number, body: unknown, parses = true) {
  let read = false;
  return {
    status,
    ok: status < 400,
    json: () => {
      if (read) return Promise.reject(new TypeError(BODY_READ_TWICE));
      read = true;
      return parses ? Promise.resolve(body) : Promise.reject(new SyntaxError("Unexpected token <"));
    },
  };
}

function harness(response: ReturnType<typeof oneShotResponse>) {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id))
      els.set(id, {
        value: "",
        textContent: "",
        innerHTML: "",
        className: "",
        disabled: false,
        checked: false,
        style: {},
      });
    return els.get(id) as FakeEl;
  };
  const pending: unknown[] = [];
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: () => true,
    setAi: () => {},
    refreshAiState: () => {},
    render: () => {},
    loadSynthMeta: () => {},
    setPresidioPending: (findings: unknown) => pending.push(findings),
    fetch: () => Promise.resolve(response),
  };
  el("caseId").value = "case-1";
  el("aiStatus").className = "ai-stale";
  return { el, globals, pending };
}

function pressResynthesize(response: ReturnType<typeof oneShotResponse>) {
  const h = harness(response);
  loadDashboardModule<ScopeApi>("dashboard-search-scope.js", [], h.globals).resynthesize();
  return h;
}

function pressSecondOpinion(response: ReturnType<typeof oneShotResponse>) {
  const h = harness(response);
  loadDashboardModule<OpinionApi>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    h.globals,
  ).runSecondOpinion();
  return h;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe("Re-synthesize refused with a 409 (#2826)", () => {
  it("shows the server's AI-off sentence", async () => {
    const { el } = pressResynthesize(oneShotResponse(409, { error: AI_OFF, aiOff: true }));
    await settle();
    expect(el("status").textContent).toBe(`synthesis failed: ${AI_OFF}`);
    expect(el("status").textContent).not.toContain("body stream");
    expect(el("synthesize").disabled).toBe(false);
  });

  it("still reports the Presidio hold and hands over its findings", async () => {
    const findings = [{ value: "sample-value" }];
    const { el, pending } = pressResynthesize(
      oneShotResponse(409, { error: "presidio_approval_required", findings }),
    );
    await settle();
    expect(el("status").textContent).toBe(
      "synthesis held — Presidio found new value(s) to review (see Anonymization)",
    );
    expect(pending).toEqual([findings]);
  });

  it("reports a 409 whose body is not JSON as a failure, not as a result", async () => {
    const { el } = pressResynthesize(oneShotResponse(409, null, false));
    await settle();
    expect(el("status").textContent).toMatch(/^synthesis failed: /);
    expect(el("status").textContent).not.toContain("body stream");
    expect(el("status").textContent).not.toContain("synthesized");
  });
});

describe("Second opinion refused with a 409 (#2826)", () => {
  it("shows the server's AI-off sentence", async () => {
    const { el } = pressSecondOpinion(oneShotResponse(409, { error: AI_OFF, aiOff: true }));
    await settle();
    expect(el("status").textContent).toBe(`second opinion failed: ${AI_OFF}`);
    expect(el("status").textContent).not.toContain("body stream");
    expect(el("secondOpinion").disabled).toBe(false);
    expect(el("secondOpinionPanel").innerHTML).toBe("");
  });

  it("still reports the Presidio hold and hands over its findings", async () => {
    const findings = [{ value: "sample-value" }];
    const { el, pending } = pressSecondOpinion(
      oneShotResponse(409, { error: "presidio_approval_required", findings }),
    );
    await settle();
    expect(el("status").textContent).toBe(
      "second opinion held — Presidio found new value(s) to review (see Anonymization)",
    );
    expect(pending).toEqual([findings]);
    expect(el("secondOpinion").disabled).toBe(false);
  });

  it("reports a 409 whose body is not JSON as a failure, not as a result", async () => {
    const { el } = pressSecondOpinion(oneShotResponse(409, null, false));
    await settle();
    expect(el("status").textContent).toMatch(/^second opinion failed: /);
    expect(el("status").textContent).not.toContain("body stream");
    expect(el("status").textContent).not.toContain("disagreement");
  });
});
