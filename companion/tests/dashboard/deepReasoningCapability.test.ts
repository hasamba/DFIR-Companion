import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The 🧠 deep-reasoning box (#1468). The /health poller hands the capability to
// setDeepReasoningCapability(); the box owner (dashboard-search-scope.js, which reads it on
// Synthesize) greys it out, unticks it and swaps the tooltip when the configured provider does
// not act on thinkingTokens — and puts the original tooltip back when a supporting provider
// arrives, because a page can outlive a settings reload.

interface Api {
  setDeepReasoningCapability(supported: unknown, providerName: unknown): void;
}

const ORIGINAL_TIP = "Deep reasoning (Chain-of-Thought): think before writing findings.";

function stubDom() {
  const box = { disabled: false, checked: true };
  const attrs: Record<string, string> = { "data-tip": ORIGINAL_TIP };
  const label = {
    getAttribute: (k: string) => (k in attrs ? attrs[k] : null),
    setAttribute: (k: string, v: string) => {
      attrs[k] = v;
    },
    hasAttribute: (k: string) => k in attrs,
  };
  const els: Record<string, unknown> = { deepReasoning: box, deepReasoningLabel: label };
  return { box, attrs, document: { getElementById: (id: string) => els[id] ?? null } };
}

function load(dom: ReturnType<typeof stubDom>) {
  return loadDashboardModule<Api>("dashboard-search-scope.js", [], { document: dom.document });
}

describe("setDeepReasoningCapability", () => {
  it("greys the box out, unticks it and names the provider when thinking is unsupported", () => {
    const dom = stubDom();
    load(dom).setDeepReasoningCapability(false, "ollama");
    expect(dom.box.disabled).toBe(true);
    expect(dom.box.checked).toBe(false);
    expect(dom.attrs["data-tip"]).toBe(
      "Deep reasoning is not supported by the configured AI provider (ollama). It needs Anthropic, OpenRouter or Claude Code.",
    );
  });

  it("keeps the original tooltip aside so it can come back", () => {
    const dom = stubDom();
    load(dom).setDeepReasoningCapability(false, "ollama");
    expect(dom.attrs["data-tip-default"]).toBe(ORIGINAL_TIP);
  });

  it("restores the box and the original tooltip when a supporting provider is configured", () => {
    const dom = stubDom();
    const api = load(dom);
    api.setDeepReasoningCapability(false, "ollama");
    api.setDeepReasoningCapability(true, "anthropic");
    expect(dom.box.disabled).toBe(false);
    expect(dom.attrs["data-tip"]).toBe(ORIGINAL_TIP);
  });

  it("does not tick the box on its own when support arrives — the analyst opts in per run", () => {
    const dom = stubDom();
    const api = load(dom);
    api.setDeepReasoningCapability(false, "ollama");
    api.setDeepReasoningCapability(true, "anthropic");
    expect(dom.box.checked).toBe(false);
  });

  it("does not overwrite the stashed default on a second unsupported poll", () => {
    const dom = stubDom();
    const api = load(dom);
    api.setDeepReasoningCapability(false, "ollama");
    api.setDeepReasoningCapability(false, "openai");
    expect(dom.attrs["data-tip-default"]).toBe(ORIGINAL_TIP);
    expect(dom.attrs["data-tip"]).toContain("(openai)");
  });

  it("says 'no provider' rather than an empty pair of brackets when the name is missing", () => {
    const dom = stubDom();
    load(dom).setDeepReasoningCapability(false, "");
    expect(dom.attrs["data-tip"]).toContain("(none configured)");
    expect(dom.attrs["data-tip"]).not.toContain("()");
  });

  it("survives a page without the box", () => {
    const api = loadDashboardModule<Api>("dashboard-search-scope.js", [], {
      document: { getElementById: () => null },
    });
    expect(() => api.setDeepReasoningCapability(false, "ollama")).not.toThrow();
  });
});
