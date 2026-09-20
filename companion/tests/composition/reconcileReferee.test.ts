import { describe, it, expect } from "vitest";
import { resolveReconcileReferee } from "../../src/composition/aiProviders.js";

// Who referees the second-opinion verdicts (#1466). A pure function of the env so it can be
// pinned without touching process.env: blank → model A, "same-as-b" → model B, else a third model.
describe("resolveReconcileReferee (#1466)", () => {
  it("defaults to model A when DFIR_AI_RECONCILE_MODEL is blank or unset", () => {
    expect(resolveReconcileReferee({})).toEqual({ kind: "a" });
    expect(resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: "   " })).toEqual({ kind: "a" });
    expect(resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: "same-as-a" })).toEqual({ kind: "a" });
  });

  it("'same-as-b' (any case) hands the whistle to the second-opinion model", () => {
    expect(resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: "same-as-b" })).toEqual({ kind: "b" });
    expect(resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: " Same-As-B " })).toEqual({ kind: "b" });
  });

  it("any other value builds a third provider, falling back to the vision provider/key/url", () => {
    const r = resolveReconcileReferee({
      DFIR_AI_RECONCILE_MODEL: "gpt-4o",
      DFIR_VISION_PROVIDER: "openai",
      DFIR_VISION_KEY: "k",
      DFIR_VISION_BASE_URL: "https://example.com/v1",
    });
    expect(r.kind).toBe("custom");
    if (r.kind !== "custom") return;
    expect(r.label).toBe("gpt-4o");
    expect(r.provider?.name).toBe("openai");
    expect(r.provider?.model).toBe("gpt-4o");
  });

  it("its own provider/key/url win over the vision fallbacks", () => {
    const r = resolveReconcileReferee({
      DFIR_AI_RECONCILE_MODEL: "claude-sonnet-5",
      DFIR_AI_RECONCILE_PROVIDER: "anthropic",
      DFIR_AI_RECONCILE_KEY: "own",
      DFIR_VISION_PROVIDER: "openai",
      DFIR_VISION_KEY: "k",
    });
    expect(r.kind).toBe("custom");
    if (r.kind !== "custom") return;
    expect(r.provider?.name).toBe("anthropic");
  });

  it("a model with no provider anywhere yields no provider, so the run can fall back to model A", () => {
    const r = resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: "gpt-4o" });
    expect(r.kind).toBe("custom");
    if (r.kind !== "custom") return;
    expect(r.provider).toBeUndefined();
  });

  it("an unknown provider name throws at startup, like every other model role", () => {
    expect(() =>
      resolveReconcileReferee({ DFIR_AI_RECONCILE_MODEL: "gpt-4o", DFIR_AI_RECONCILE_PROVIDER: "nope" }),
    ).toThrow(/unknown provider/);
  });
});
