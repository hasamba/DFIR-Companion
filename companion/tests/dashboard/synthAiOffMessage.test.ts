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
// #2828 — the duplicate-host gate's 409. The host names are the case's own text, so the pair below
// carries markup that must never reach the screen.
const HOST_MERGE_CODE = "host_merge_decision_required";
const HOST_MERGE = {
  error: HOST_MERGE_CODE,
  pairs: [
    { canonical: "WS-SAMPLE-01", other: '<img src=x onerror="alert(1)">' },
    { canonical: "WS-SAMPLE-02", other: "ws-sample-02.example.test" },
  ],
};
const hostMergeHold = (what: string) =>
  `${what} on hold — 2 possible duplicate hosts awaiting a merge decision. ` +
  "Decide each pair in the Duplicate Hosts panel.";
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
  const fetched: string[] = [];
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    localStorage: { getItem: () => null, setItem: () => {} },
    confirm: () => true,
    setAi: () => {},
    refreshAiState: () => {},
    render: () => {},
    loadSynthMeta: () => {},
    setPresidioPending: (findings: unknown) => pending.push(findings),
    // The pressed button's request gets `response`; the Duplicate Hosts panel's own re-read of the
    // case (#2828) gets an empty list.
    fetch: (url: string) => {
      fetched.push(url);
      return url.includes("/host-duplicates")
        ? Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ pending: [], dismissed: [] }),
          })
        : Promise.resolve(response);
    },
  };
  el("caseId").value = "case-1";
  el("aiStatus").className = "ai-stale";
  return { el, globals, pending, fetched };
}

function pressResynthesize(response: ReturnType<typeof oneShotResponse>) {
  const h = harness(response);
  loadDashboardModule<ScopeApi>(
    "dashboard-search-scope.js",
    ["dashboard-host-duplicates.js"],
    h.globals,
  ).resynthesize();
  return h;
}

function pressSecondOpinion(response: ReturnType<typeof oneShotResponse>) {
  const h = harness(response);
  loadDashboardModule<OpinionApi>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js", "dashboard-host-duplicates.js"],
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

describe("a press held by the duplicate-host gate (#2828)", () => {
  const presses = [
    { name: "Re-synthesize", press: pressResynthesize, what: "synthesis", button: "synthesize" },
    { name: "Second opinion", press: pressSecondOpinion, what: "second opinion", button: "secondOpinion" },
  ];
  for (const { name, press, what, button } of presses) {
    it(`${name} says it is on hold and what to do, not "failed" and not the raw code`, async () => {
      const { el, fetched } = press(oneShotResponse(409, HOST_MERGE));
      await settle();
      const text = el("status").textContent;
      expect(text).toBe(hostMergeHold(what));
      expect(text).not.toContain(HOST_MERGE_CODE);
      expect(text).not.toMatch(/failed|error|body stream/i);
      expect(text).not.toContain("onerror");
      expect(el(button).disabled).toBe(false);
      // The Duplicate Hosts panel re-reads the case on screen.
      expect(fetched).toContain("/cases/case-1/host-duplicates");
    });
  }
});
