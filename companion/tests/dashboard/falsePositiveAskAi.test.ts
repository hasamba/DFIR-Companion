import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// "Ask AI for similar" in the Mark-false-positive modal said nothing when the AI could not run: the
// server answered `aiUnavailable: true` (no AI provider) or an error (AI off for the case), and the
// modal redrew "No similar items found." — the button looked like it only refreshed. Every outcome of
// the AI pass now leaves a visible line, and the deterministic list stays on screen.

interface FpModalApi {
  initFalsePositiveModal(): void;
  openFalsePositiveModal(kind: string, ref: string, label: string): void;
}

type Handler = (e?: unknown) => unknown;

function fakeElement() {
  const handlers: Record<string, Handler> = {};
  return {
    handlers,
    value: "",
    checked: false,
    disabled: false,
    textContent: "",
    innerHTML: "",
    style: {} as Record<string, string>,
    classList: { add: () => {}, remove: () => {}, contains: () => false },
    addEventListener: (type: string, fn: Handler) => {
      handlers[type] = fn;
    },
  };
}

const CANDIDATE = {
  id: "e2",
  kind: "event",
  label: "other event",
  score: 3,
  reasons: ["same detection result"],
};

function harness(aiReply: () => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>) {
  const els: Record<string, ReturnType<typeof fakeElement>> = {};
  const el = (id: string) => (els[id] ??= fakeElement());
  el("caseId").value = "c1";
  const fetch = vi.fn(async (_url: string, init?: { body: string }) => {
    if (init && JSON.parse(init.body).ai) return aiReply();
    return { ok: true, status: 200, json: async () => ({ candidates: [CANDIDATE] }) };
  });
  const api = loadDashboardModule<FpModalApi>("dashboard-false-positive.js", ["dashboard-escape.js"], {
    document: { getElementById: el, querySelectorAll: () => [] },
    fetch,
    isFpAiConfigured: () => true,
  });
  api.initFalsePositiveModal();
  api.openFalsePositiveModal("event", "e1", "anchor event");
  const askAi = async () => {
    await el("fpAskAiBtn").handlers.click();
  };
  return { el, askAi };
}

const reply = (status: number, body: unknown) => async () => ({
  ok: status < 400,
  status,
  json: async () => body,
});

describe("Ask AI for similar always says what happened", () => {
  it("says AI is off when the server reports no AI provider, and keeps the list", async () => {
    const h = harness(reply(200, { candidates: [CANDIDATE], aiUnavailable: true }));
    await h.askAi();
    const html = h.el("fpCandidates").innerHTML;
    expect(html).toContain("other event");
    expect(html).toMatch(/AI is off/);
    expect(h.el("fpAskAiBtn").disabled).toBe(false);
  });

  it("shows the server's error instead of 'No similar items found'", async () => {
    const h = harness(reply(409, { error: "AI is off for this case" }));
    await h.askAi();
    const html = h.el("fpCandidates").innerHTML;
    expect(html).toContain("AI search failed");
    expect(html).toContain("AI is off for this case");
    expect(html).not.toContain("No similar items found");
  });

  it("reports a network failure", async () => {
    const h = harness(async () => {
      throw new Error("Failed to fetch");
    });
    await h.askAi();
    expect(h.el("fpCandidates").innerHTML).toContain("AI search failed");
    expect(h.el("fpAskAiBtn").textContent).toContain("Ask AI for similar");
  });

  it("says so when the AI ran and found nothing new", async () => {
    const h = harness(reply(200, { candidates: [CANDIDATE] }));
    await h.askAi();
    expect(h.el("fpCandidates").innerHTML).toContain("AI found no other similar items");
  });

  it("adds no AI line to the first, non-AI list", async () => {
    const h = harness(reply(200, { candidates: [] }));
    await new Promise((r) => setImmediate(r));
    expect(h.el("fpCandidates").innerHTML).not.toMatch(/AI (is off|found|search)/);
  });
});
