// Explain Event shows "Normal vs. suspicious" as one heading over two blocks. The second block is
// the model's answer to "what is suspicious?", so a reply such as "Very little. ..." read as the
// body of a missing heading. Each block now opens with its own label.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { EXPLAIN_EVENT_PROMPT } from "../../src/analysis/ai/prompts/investigation.js";

interface ExplainApi {
  openExplainPanel: (caseId: string, eventId: string) => void;
}

class FakeNode {
  textContent = "";
  innerHTML = "";
  style: Record<string, string> = {};
  children: FakeNode[] = [];
  classList = { add: () => {} };
  replaceChildren(...nodes: FakeNode[]) {
    this.innerHTML = "";
    this.children = nodes;
  }
  querySelectorAll() {
    return [];
  }
}

function render(result: Record<string, unknown>): Promise<string> {
  const body = new FakeNode();
  const elements: Record<string, unknown> = {
    explainOverlay: new FakeNode(),
    explainEventTitle: new FakeNode(),
    explainBody: body,
  };
  const globals = {
    citeEvents: () => "",
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      createElement: () => new FakeNode(),
      addEventListener: () => {},
    },
    fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(result) }),
  };
  const api = loadDashboardModule<ExplainApi>(
    "dashboard-explain-event.js",
    ["dashboard-state.js", "dashboard-escape.js"],
    globals,
  );
  api.openExplainPanel("INC-1", "e1");
  return new Promise((r) => setTimeout(() => r(body.innerHTML), 0));
}

describe("Explain Event sections", () => {
  it("labels the normal and the suspicious block under their shared heading", async () => {
    const html = await render({
      summary: "Chrome started.",
      normalContext: "Chrome starts many helper processes.",
      suspiciousIndicators: "Nothing in this event is suspicious.",
    });
    expect(html).toContain("Normal vs. suspicious");
    expect(html).toMatch(/Normal: <\/span>Chrome starts many helper processes\./);
    expect(html).toMatch(/Suspicious: <\/span>Nothing in this event is suspicious\./);
  });

  it("shows only the label of a block that has text", async () => {
    const html = await render({ summary: "x", suspiciousIndicators: "A browser ran on a DC." });
    expect(html).toContain("Suspicious: ");
    expect(html).not.toContain("Normal: ");
  });
});

describe("EXPLAIN_EVENT_PROMPT", () => {
  it("asks for short, self-standing fields", () => {
    expect(EXPLAIN_EVENT_PROMPT).toContain("busy analyst");
    expect(EXPLAIN_EVENT_PROMPT).toContain("never open a field with a fragment");
    expect(EXPLAIN_EVENT_PROMPT).toContain("(2–3 sentences)");
    expect(EXPLAIN_EVENT_PROMPT).toContain("Nothing in this event is suspicious.");
  });
});
