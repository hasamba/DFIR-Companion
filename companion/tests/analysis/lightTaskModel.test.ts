import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildLightProvider, buildRuntimePipeline } from "../../src/composition/aiProviders.js";
import { resolveAiRoleSetting } from "../../src/config/aiEnv.js";
import { effectiveRoleSetting } from "../../src/config/aiKeyMigration.js";
import { smallTaskProvider } from "../../src/analysis/ai/smallTaskModel.js";
import { smallTaskModels } from "../../src/config/smallTaskModels.js";
import { buildAiDiagnostics } from "../../src/analysis/diagnostics.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #2593: one optional light-task model for small, well-scoped calls.

class CountingProvider implements AIProvider {
  calls = 0;
  constructor(
    readonly name: string,
    private readonly canned = '{"suggestions":[],"translations":[]}',
    readonly model = name,
  ) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls += 1;
    return { rawText: this.canned };
  }
}

const p = (name: string) => new CountingProvider(name);

describe("smallTaskProvider (#2593)", () => {
  it("language hunts and query translation use the light model when set, else synthesis", () => {
    const light = p("light");
    const synth = p("synth");
    for (const task of ["language-hunt", "query-translation"] as const) {
      expect(smallTaskProvider({ lightProvider: light, synthesisProvider: synth }, task)).toBe(light);
      expect(smallTaskProvider({ synthesisProvider: synth }, task)).toBe(synth);
      expect(smallTaskProvider({}, task)).toBeUndefined();
    }
  });

  it("VQL hunts go Velociraptor hunt model -> light model -> synthesis", () => {
    const velo = p("velo");
    const light = p("light");
    const synth = p("synth");
    expect(
      smallTaskProvider(
        { velociraptorProvider: velo, lightProvider: light, synthesisProvider: synth },
        "vql-hunt",
      ),
    ).toBe(velo);
    expect(smallTaskProvider({ lightProvider: light, synthesisProvider: synth }, "vql-hunt")).toBe(light);
    expect(smallTaskProvider({ synthesisProvider: synth }, "vql-hunt")).toBe(synth);
  });

  it("language hunts and translation never use the VQL-tuned model", () => {
    const velo = p("velo");
    const synth = p("synth");
    expect(smallTaskProvider({ velociraptorProvider: velo, synthesisProvider: synth }, "language-hunt")).toBe(
      synth,
    );
    expect(
      smallTaskProvider({ velociraptorProvider: velo, synthesisProvider: synth }, "query-translation"),
    ).toBe(synth);
  });
});

async function pipelineWith(light?: CountingProvider) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-light-")));
  const stateStore = new StateStore(store);
  const synth = p("synth");
  const pipeline = buildRuntimePipeline({
    provider: synth,
    synthesisProvider: synth,
    lightProvider: light,
    stateStore,
    store,
  });
  return { pipeline, synth };
}

describe("light model through the pipeline (#2593)", () => {
  it("query translation runs on the light model when it is set", async () => {
    const light = p("light");
    const { pipeline, synth } = await pipelineWith(light);
    await pipeline.translateQuery("c1", "powershell downloading a file", ["splunk"]).catch(() => undefined);
    expect(light.calls).toBeGreaterThan(0);
    expect(synth.calls).toBe(0);
  });

  it("query translation stays on the synthesis model when no light model is set", async () => {
    const { pipeline, synth } = await pipelineWith();
    await pipeline.translateQuery("c1", "powershell downloading a file", ["splunk"]).catch(() => undefined);
    expect(synth.calls).toBeGreaterThan(0);
  });

  it("a language hunt and a playbook language hunt run on the light model", async () => {
    const light = p("light");
    const { pipeline, synth } = await pipelineWith(light);
    await pipeline.caseHunts.suggest("c1", { language: "spl" }).catch(() => undefined);
    const afterCase = light.calls;
    await pipeline.caseHunts
      .suggestPlaybook("c1", [{ id: "t1", title: "Hunt for persistence", phase: "scope" } as never], "spl")
      .catch(() => undefined);
    expect(afterCase).toBeGreaterThan(0);
    expect(light.calls).toBeGreaterThan(afterCase);
    expect(synth.calls).toBe(0);
  });
});

describe("buildLightProvider (#2593)", () => {
  const withEnv = <T>(env: Record<string, string | undefined>, fn: () => T): T => {
    const saved = { ...process.env };
    for (const k of Object.keys(process.env)) if (/^DFIR_(AI|VISION)_/.test(k)) delete process.env[k];
    Object.assign(process.env, env);
    try {
      return fn();
    } finally {
      for (const k of Object.keys(process.env)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  };

  it("is off when the model is blank or whitespace, even with a provider and key set", () => {
    expect(withEnv({ DFIR_VISION_PROVIDER: "openai" }, () => buildLightProvider())).toBeUndefined();
    expect(
      withEnv({ DFIR_AI_LIGHT_MODEL: "   ", DFIR_AI_LIGHT_PROVIDER: "openai", DFIR_AI_LIGHT_KEY: "k" }, () =>
        buildLightProvider(),
      ),
    ).toBeUndefined();
  });

  it("uses its own provider, or the main provider when blank", () => {
    expect(
      withEnv(
        { DFIR_VISION_PROVIDER: "openai", DFIR_AI_LIGHT_MODEL: "gpt-mini" },
        () => buildLightProvider()?.name,
      ),
    ).toBe("openai");
    expect(
      withEnv(
        {
          DFIR_VISION_PROVIDER: "openai",
          DFIR_AI_LIGHT_PROVIDER: "anthropic",
          DFIR_AI_LIGHT_MODEL: "claude-haiku-4-5",
        },
        () => buildLightProvider()?.name,
      ),
    ).toBe("anthropic");
  });
});

describe("light role credentials (#2593)", () => {
  it("own key wins, then the provider's key, then the main key", () => {
    const base = { DFIR_VISION_PROVIDER: "openai", DFIR_VISION_KEY: "main", DFIR_AI_LIGHT_MODEL: "m" };
    expect(resolveAiRoleSetting({ ...base, DFIR_AI_LIGHT_KEY: "own" }, "light", "KEY")).toBe("own");
    expect(resolveAiRoleSetting({ ...base, DFIR_AI_KEY_OPENAI: "slot" }, "light", "KEY")).toBe("slot");
    expect(resolveAiRoleSetting(base, "light", "KEY")).toBe("main");
    expect(resolveAiRoleSetting({ ...base, DFIR_VISION_BASE_URL: "http://main" }, "light", "BASE_URL")).toBe(
      "http://main",
    );
  });

  it("a light role with no model is off for key migration", () => {
    const env = { DFIR_VISION_PROVIDER: "openai", DFIR_VISION_KEY: "main", DFIR_AI_LIGHT_KEY: "own" };
    expect(effectiveRoleSetting(env, "light", "KEY")).toBeUndefined();
    expect(effectiveRoleSetting(env, "light", "BASE_URL")).toBeUndefined();
    expect(effectiveRoleSetting({ ...env, DFIR_AI_LIGHT_MODEL: "m" }, "light", "KEY")).toBe("own");
  });
});

describe("diagnostics name the model each small task uses (#2593)", () => {
  it("light model unset: language hunts and translation use the synthesis model", () => {
    const m = smallTaskModels({ DFIR_VISION_MODEL: "v", DFIR_AI_SYNTH_MODEL: "big" });
    expect(m["language-hunt"]).toBe("big (synthesis model)");
    expect(m["query-translation"]).toBe("big (synthesis model)");
    expect(m["vql-hunt"]).toMatch(/\(Velociraptor hunt model\)$/);
  });

  it("light model set: it names it for language hunts and translation", () => {
    const m = smallTaskModels({
      DFIR_AI_SYNTH_MODEL: "big",
      DFIR_AI_LIGHT_MODEL: "small",
      DFIR_AI_VELO_MODEL: "vq",
    });
    expect(m["language-hunt"]).toBe("small (light-task model)");
    expect(m["query-translation"]).toBe("small (light-task model)");
    expect(m["vql-hunt"]).toBe("vq (Velociraptor hunt model)");
  });

  it("the AI diagnostics report carries the per-task models", () => {
    const ai = buildAiDiagnostics({
      DFIR_VISION_PROVIDER: "openai",
      DFIR_VISION_MODEL: "v",
      DFIR_AI_SYNTH_MODEL: "big",
      DFIR_AI_LIGHT_MODEL: "small",
    });
    expect(ai.smallTaskModels["language-hunt"]).toBe("small (light-task model)");
  });
});
