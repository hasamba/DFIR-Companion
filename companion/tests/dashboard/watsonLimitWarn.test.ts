// Watson phase 5, Task 8: the two Settings warnings. Runs the real module in a vm context.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  watsonLimitWarnRefresh(): void;
}
interface FakeEl {
  id: string;
  value: string;
  placeholder: string;
  className: string;
  textContent: string;
  style: { display: string };
  parentElement: { appendChild(e: FakeEl): void } | null;
  addEventListener(): void;
  setAttribute(): void;
}

const LIMIT =
  "Watson can make several lookups for each question, and no Watson cost or token limit is set. Set a limit to control cost.";
const PROVIDER =
  "Watson provider is set, but its model or key is missing. Watson will not answer until you set them.";

function page(values: Record<string, string>, saved: string[] = []) {
  const els = new Map<string, FakeEl>();
  const make = (id: string): FakeEl => {
    const e: FakeEl = {
      id,
      value: values[id] ?? "",
      placeholder: saved.includes(id) ? "(already set)" : "",
      className: "",
      textContent: "",
      style: { display: "" },
      parentElement: { appendChild: (c: FakeEl) => void els.set(c.id, c) },
      addEventListener: () => {},
      setAttribute: () => {},
    };
    return e;
  };
  const ids = new Set([
    ...Object.keys(values),
    ...saved,
    "env-DFIR_AI_WATSON_MAX_TOOL_CALLS",
    "env-DFIR_AI_WATSON_PROVIDER",
  ]);
  for (const id of ids) els.set(id, make(id));
  const document = {
    getElementById: (id: string) => els.get(id) ?? null,
    createElement: () => make(""),
  };
  const api = loadDashboardModule<Api>("dashboard-watson-limit-warn.js", [], { document, URL });
  api.watsonLimitWarnRefresh();
  const shown = (forId: string) => {
    const box = els.get("watsonWarn-" + forId);
    return box && box.style.display === "block" ? box.textContent : null;
  };
  return {
    limit: shown("env-DFIR_AI_WATSON_MAX_TOOL_CALLS"),
    provider: shown("env-DFIR_AI_WATSON_PROVIDER"),
  };
}

const K = (s: string) => `env-DFIR_AI_${s}`;

describe("the lookups warning (U4)", () => {
  it.each([
    ["blank", ""],
    ["4", "4"],
  ])("shows for %s with both limits blank", (_n, v) => {
    expect(page({ [K("WATSON_MAX_TOOL_CALLS")]: v }).limit).toBe(`⚠ ${LIMIT}`);
  });
  it("hides for 0.5, like the server (whole part 0)", () => {
    expect(page({ [K("WATSON_MAX_TOOL_CALLS")]: "0.5" }).limit).toBeNull();
  });
  it("hides for 0", () => {
    expect(page({ [K("WATSON_MAX_TOOL_CALLS")]: "0" }).limit).toBeNull();
  });
  it("hides when the cost limit is set", () => {
    expect(page({ [K("WATSON_MAX_TOOL_CALLS")]: "4", [K("WATSON_COST_LIMIT_USD")]: "5" }).limit).toBeNull();
  });
  it("hides when the token limit is set", () => {
    expect(page({ [K("WATSON_MAX_TOOL_CALLS")]: "4", [K("WATSON_TOKEN_LIMIT")]: "100000" }).limit).toBeNull();
  });
});

describe("the provider warning (#14)", () => {
  it("shows for anthropic with a blank model", () => {
    expect(page({ [K("WATSON_PROVIDER")]: "anthropic", [K("SYNTH_PROVIDER")]: "openai" }).provider).toBe(
      `⚠ ${PROVIDER}`,
    );
  });
  it("shows for anthropic with a model and no key anywhere", () => {
    const r = page({ [K("WATSON_PROVIDER")]: "anthropic", [K("WATSON_MODEL")]: "claude-sonnet-5" });
    expect(r.provider).toBe(`⚠ ${PROVIDER}`);
  });
  it("hides for a blank provider", () => {
    expect(page({ [K("WATSON_PROVIDER")]: "" }).provider).toBeNull();
  });
  it("hides for claude-code with a model", () => {
    expect(page({ [K("WATSON_PROVIDER")]: "claude-code", [K("WATSON_MODEL")]: "opus" }).provider).toBeNull();
  });
  it("hides for anthropic with a model and a typed key", () => {
    const r = page({ [K("WATSON_PROVIDER")]: "anthropic", [K("WATSON_MODEL")]: "m", [K("WATSON_KEY")]: "k" });
    expect(r.provider).toBeNull();
  });
  it("hides for anthropic with a model and a saved provider key", () => {
    const r = page(
      { [K("WATSON_PROVIDER")]: "anthropic", [K("WATSON_MODEL")]: "m", [K("KEY_ANTHROPIC")]: "" },
      [K("KEY_ANTHROPIC")],
    );
    expect(r.provider).toBeNull();
  });
  it("a blank model is fine on the synthesis provider", () => {
    const r = page({ [K("WATSON_PROVIDER")]: "anthropic", [K("SYNTH_PROVIDER")]: "anthropic" }, [
      K("KEY_ANTHROPIC"),
    ]);
    expect(r.provider).toBeNull();
  });
  it("a local ollama needs no key", () => {
    const r = page({
      [K("WATSON_PROVIDER")]: "ollama",
      [K("WATSON_MODEL")]: "m",
      [K("WATSON_BASE_URL")]: "http://localhost:11434",
    });
    expect(r.provider).toBeNull();
  });
});
