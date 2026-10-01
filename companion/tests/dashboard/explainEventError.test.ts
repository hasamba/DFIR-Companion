// Explain Event must show the server's own error text, not a bare "HTTP 500" (#1910).
//
// With Presidio down, the server answers 500 with the full cause in body.error. The panel used to
// read that body (for the Presidio-hold check), then throw "HTTP 500" and say "check the server
// console". The analyst had to read the log to learn Presidio was down.
//
// The server text is untrusted, so it must land as TEXT: the failure line is built with
// textContent, never innerHTML.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface ExplainApi {
  openExplainPanel: (caseId: string, eventId: string) => void;
}

class FakeNode {
  tag: string;
  textContent = "";
  innerHTML = "";
  style: Record<string, string> = {};
  children: FakeNode[] = [];
  classList = { add: () => {} };
  constructor(tag: string) {
    this.tag = tag;
  }
  replaceChildren(...nodes: FakeNode[]) {
    this.innerHTML = "";
    this.children = nodes;
  }
  querySelectorAll() {
    return [];
  }
}

function harness(reply: () => Promise<unknown>) {
  const body = new FakeNode("div");
  const elements: Record<string, unknown> = {
    explainOverlay: new FakeNode("div"),
    explainEventTitle: new FakeNode("div"),
    explainBody: body,
  };
  const globals = {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      createElement: (tag: string) => new FakeNode(tag),
      addEventListener: () => {},
    },
    fetch: () => reply(),
  };
  const api = loadDashboardModule<ExplainApi>(
    "dashboard-explain-event.js",
    ["dashboard-state.js", "dashboard-escape.js"],
    globals,
  );
  /** What the analyst reads in the panel: markup set via innerHTML, or text of appended nodes. */
  const shown = () => body.innerHTML + body.children.map((c) => c.textContent).join("");
  return { api, body, shown };
}

const respond = (status: number, json: unknown) => () =>
  Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(json) });
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("Explain Event failure line (#1910)", () => {
  it("shows the server's error text instead of a bare HTTP 500", async () => {
    const h = harness(respond(500, { error: "Presidio analyzer unreachable: connect ECONNREFUSED" }));
    h.api.openExplainPanel("INC-1", "e1");
    await settle();

    expect(h.shown()).toContain("Presidio analyzer unreachable: connect ECONNREFUSED");
    expect(h.shown()).toContain("HTTP 500");
    expect(h.shown()).toContain("check the server console for details");
  });

  it("puts the server text in as text, never as markup", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const h = harness(respond(500, { error: hostile }));
    h.api.openExplainPanel("INC-1", "e1");
    await settle();

    expect(h.body.innerHTML).not.toContain("<img");
    expect(h.body.children).toHaveLength(1);
    expect(h.body.children[0].textContent).toContain(hostile); // shown literally, as text
    expect(h.body.children[0].style.color).toBe("var(--sev-high)");
  });

  it("falls back to the status when the body carries no error", async () => {
    const h = harness(respond(500, {}));
    h.api.openExplainPanel("INC-1", "e1");
    await settle();

    expect(h.shown()).toContain("explain failed: HTTP 500 — check the server console for details");
  });

  it("picks the hint from the status, not from words in the message", async () => {
    const h501 = harness(respond(501, { error: "no provider" }));
    h501.api.openExplainPanel("INC-1", "e1");
    await settle();
    expect(h501.shown()).toContain("AI provider not configured");

    const h500 = harness(respond(500, { error: "upstream said 404 for model x" }));
    h500.api.openExplainPanel("INC-1", "e1");
    await settle();
    expect(h500.shown()).not.toContain("route not found");
    expect(h500.shown()).toContain("check the server console for details");
  });

  it("gives a network failure the generic hint even if its text names a status", async () => {
    const h = harness(() => Promise.reject(new Error("fetch failed after 404 retries")));
    h.api.openExplainPanel("INC-1", "e1");
    await settle();

    expect(h.shown()).toContain("fetch failed after 404 retries");
    expect(h.shown()).not.toContain("route not found");
  });
});
