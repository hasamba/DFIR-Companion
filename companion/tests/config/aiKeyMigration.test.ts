import { describe, expect, it } from "vitest";
import {
  AI_ROLE_SOURCES,
  resolveAiRoleSetting,
  type AiRoleId,
  type EnvSource,
} from "../../src/config/aiEnv.js";
import {
  effectiveRoleSetting,
  planAiKeyMigration,
  publicAiKeyMigration,
} from "../../src/config/aiKeyMigration.js";

// The move takes keys and base URLs saved on single models and puts them in the per-provider slot.
// The one promise it must keep: every model sends exactly what it sent before.

const ROLES = Object.keys(AI_ROLE_SOURCES) as AiRoleId[];

function resolvedAll(env: EnvSource): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const role of ROLES) {
    for (const setting of ["KEY", "BASE_URL"] as const) {
      out[`${role}:${setting}`] = effectiveRoleSetting(env, role, setting);
    }
  }
  return out;
}

function applied(env: EnvSource): EnvSource {
  return { ...env, ...planAiKeyMigration(env).updates };
}

function expectNoModelChanged(env: EnvSource): void {
  expect(resolvedAll(applied(env))).toEqual(resolvedAll(env));
}

describe("effectiveRoleSetting", () => {
  it("counts no key for a model on a CLI provider, which sends none", () => {
    const env = { DFIR_VISION_KEY: "k", DFIR_AI_VELO_PROVIDER: "claude-code" };
    expect(resolveAiRoleSetting(env, "velociraptor", "KEY")).toBe("k");
    expect(effectiveRoleSetting(env, "velociraptor", "KEY")).toBeUndefined();
  });
});

describe("planAiKeyMigration", () => {
  it("moves a single model's key into an empty provider slot", () => {
    const env = { DFIR_AI_VELO_PROVIDER: "openrouter", DFIR_AI_VELO_KEY: "or-key" };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({ DFIR_AI_KEY_OPENROUTER: "or-key", DFIR_AI_VELO_KEY: "" });
    expect(plan.moves).toEqual([
      {
        role: "velociraptor",
        provider: "openrouter",
        setting: "key",
        target: "DFIR_AI_KEY_OPENROUTER",
        sources: ["DFIR_AI_VELO_KEY"],
      },
    ]);
    expect(plan.conflicts).toEqual([]);
    expectNoModelChanged(env);
  });

  it("only clears a model value that equals the saved provider value", () => {
    const env = {
      DFIR_AI_KEY_GEMINI: "g-key",
      DFIR_AI_SYNTH_PROVIDER: "gemini",
      DFIR_AI_SYNTH_KEY: "g-key",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({ DFIR_AI_SYNTH_KEY: "" });
    expect(plan.moves.map((m) => m.role)).toEqual(["synthesis"]);
    expectNoModelChanged(env);
  });

  it("keeps a model value that differs from the saved provider value as an override", () => {
    const env = {
      DFIR_AI_KEY_GEMINI: "g-key",
      DFIR_AI_SYNTH_PROVIDER: "gemini",
      DFIR_AI_SYNTH_KEY: "other-g-key",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({});
    expect(plan.conflicts).toEqual([
      { provider: "gemini", setting: "key", roles: ["synthesis"], reason: expect.any(String) },
    ]);
  });

  it("moves nothing when two models on an empty provider slot hold different values", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "openai",
      DFIR_AI_SYNTH_KEY: "a",
      DFIR_AI_RECONCILE_PROVIDER: "openai",
      DFIR_AI_RECONCILE_KEY: "b",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({});
    expect(plan.moves).toEqual([]);
    expect(plan.conflicts).toEqual([
      { provider: "openai", setting: "key", roles: ["synthesis", "reconcile"], reason: expect.any(String) },
    ]);
  });

  it("writes the slot once and clears both models when they share a value", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "openai",
      DFIR_AI_SYNTH_KEY: "same",
      DFIR_AI_RECONCILE_PROVIDER: "openai",
      DFIR_AI_RECONCILE_KEY: "same",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({
      DFIR_AI_KEY_OPENAI: "same",
      DFIR_AI_SYNTH_KEY: "",
      DFIR_AI_RECONCILE_KEY: "",
    });
    expect(plan.moves.map((m) => m.role)).toEqual(["synthesis", "reconcile"]);
    expect(plan.moves.every((m) => m.target === "DFIR_AI_KEY_OPENAI")).toBe(true);
    expectNoModelChanged(env);
  });

  it("ignores the CLI providers, which have no provider slot", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "claude-code",
      DFIR_AI_SYNTH_KEY: "unused",
      DFIR_AI_SECOND_OPINION_PROVIDER: "codex",
      DFIR_AI_SECOND_OPINION_KEY: "unused",
      DFIR_AI_VELO_PROVIDER: "claude-code",
    };
    expect(planAiKeyMigration(env)).toEqual({ moves: [], conflicts: [], updates: {} });
  });

  it("clears the legacy DFIR_AI_KEY along with DFIR_VISION_KEY for the vision model", () => {
    const env = {
      DFIR_VISION_PROVIDER: "gemini",
      DFIR_VISION_KEY: "g-key",
      DFIR_AI_KEY: "g-key-old",
      DFIR_AI_VELO_PROVIDER: "claude-code",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({ DFIR_AI_KEY_GEMINI: "g-key", DFIR_VISION_KEY: "", DFIR_AI_KEY: "" });
    expect(plan.moves[0]).toMatchObject({ role: "vision", sources: ["DFIR_VISION_KEY", "DFIR_AI_KEY"] });
    expectNoModelChanged(env);
  });

  it("moves a vision key that only lives in the legacy DFIR_AI_KEY name", () => {
    const env = { DFIR_AI_PROVIDER: "gemini", DFIR_AI_KEY: "g-key", DFIR_AI_VELO_PROVIDER: "claude-code" };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({ DFIR_AI_KEY_GEMINI: "g-key", DFIR_AI_KEY: "" });
    expectNoModelChanged(env);
  });

  it("is fine when a model inherits the vision provider as well as the vision key", () => {
    // Synthesis has no provider or key of its own: it runs on openrouter with the vision key. After
    // the move it finds the same key in the openrouter slot.
    const env = {
      DFIR_VISION_PROVIDER: "openrouter",
      DFIR_VISION_KEY: "or-key",
      DFIR_AI_VELO_PROVIDER: "claude-code",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({ DFIR_AI_KEY_OPENROUTER: "or-key", DFIR_VISION_KEY: "" });
    expect(plan.conflicts).toEqual([]);
    expectNoModelChanged(env);
  });

  it("refuses the move when a model on another provider borrows the vision value", () => {
    // Synthesis runs on openai with no key of its own, so it sends the vision key today. Clearing
    // the vision key would leave it with nothing.
    const env = {
      DFIR_VISION_PROVIDER: "openrouter",
      DFIR_VISION_KEY: "or-key",
      DFIR_AI_SYNTH_PROVIDER: "openai",
      DFIR_AI_VELO_PROVIDER: "claude-code",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({});
    expect(plan.moves).toEqual([]);
    expect(plan.conflicts).toEqual([
      {
        provider: "openrouter",
        setting: "key",
        roles: ["vision"],
        reason: "another model borrows this value",
      },
    ]);
  });

  it("moves base URLs the same way, into the BASE_URL slot", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "litellm",
      DFIR_AI_SYNTH_BASE_URL: "http://127.0.0.1:4000",
      DFIR_AI_VELO_PROVIDER: "claude-code",
    };
    const plan = planAiKeyMigration(env);
    expect(plan.updates).toEqual({
      DFIR_AI_BASE_URL_LITELLM: "http://127.0.0.1:4000",
      DFIR_AI_SYNTH_BASE_URL: "",
    });
    expect(plan.moves).toEqual([
      {
        role: "synthesis",
        provider: "litellm",
        setting: "baseUrl",
        target: "DFIR_AI_BASE_URL_LITELLM",
        sources: ["DFIR_AI_SYNTH_BASE_URL"],
      },
    ]);
    expectNoModelChanged(env);
  });

  it("finds nothing to do on a second run", () => {
    const env = { DFIR_AI_VELO_KEY: "or-key", DFIR_AI_SYNTH_PROVIDER: "gemini", DFIR_AI_SYNTH_KEY: "g" };
    const once = applied(env);
    expect(planAiKeyMigration(once)).toEqual({ moves: [], conflicts: [], updates: {} });
  });

  it("never puts a secret value in the public plan", () => {
    const secret = "sk-do-not-leak";
    const env = {
      DFIR_VISION_PROVIDER: "openrouter",
      DFIR_VISION_KEY: secret,
      DFIR_AI_SYNTH_PROVIDER: "openai",
      DFIR_AI_SYNTH_KEY: `${secret}-2`,
      DFIR_AI_RECONCILE_PROVIDER: "openai",
      DFIR_AI_RECONCILE_KEY: `${secret}-3`,
      DFIR_AI_VELO_KEY: secret,
      DFIR_AI_SECOND_OPINION_PROVIDER: "litellm",
      DFIR_AI_SECOND_OPINION_BASE_URL: "http://secret-host.example.com",
    };
    const plan = planAiKeyMigration(env);
    expect(Object.keys(plan.updates).length).toBeGreaterThan(0);
    const wire = JSON.stringify(publicAiKeyMigration(plan));
    expect(wire).not.toContain(secret);
    expect(wire).not.toContain("secret-host");
    expect(wire).not.toContain("updates");
  });
});
