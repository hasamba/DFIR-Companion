// Batched deep pass: read EVERY graded forensic event at or above a severity floor, in as many
// batches as it takes, then fold the observations into ONE final synthesis. Analyst-triggered.
//
//   npm run deep-pass -- <caseId>                  # preview only, no AI calls, no spend
//   npm run deep-pass -- <caseId> --floor Medium   # run it
//   npm run deep-pass -- <caseId> --floor Low --max-batches 20
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { makeImageLoader } from "../src/analysis/imageLoader.js";
import { FalsePositiveStore } from "../src/analysis/falsePositive.js";
import { ScopeStore } from "../src/analysis/scope.js";
import { AnonControlStore } from "../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../src/analysis/anonDiscovered.js";
import { SynthMetaStore } from "../src/analysis/synthMeta.js";
import { HypothesisStore } from "../src/analysis/hypothesisStore.js";
import { buildProviderFrom } from "../src/server.js";
import { visionEnv } from "../src/config/aiEnv.js";
import { parseMinSeverity } from "../src/analysis/severityFloor.js";

function strOpt(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";

  const provName = strOpt("provider") ?? process.env.DFIR_AI_SYNTH_PROVIDER ?? visionEnv(process.env, "PROVIDER");
  const model = strOpt("model") ?? process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL");
  const apiKey = strOpt("key") ?? process.env.DFIR_AI_SYNTH_KEY ?? visionEnv(process.env, "KEY");
  const baseUrl = strOpt("base-url") ?? process.env.DFIR_AI_SYNTH_BASE_URL ?? visionEnv(process.env, "BASE_URL");
  const provider = buildProviderFrom({ provider: provName, model, apiKey, baseUrl });
  if (!provider) {
    console.error("No AI provider configured (DFIR_AI_SYNTH_PROVIDER / DFIR_VISION_PROVIDER / --provider). Aborting.");
    process.exit(1);
  }

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const pipeline = new AnalysisPipeline({
    provider, synthesisProvider: provider, stateStore,
    falsePositiveStore: new FalsePositiveStore(store), scopeStore: new ScopeStore(store),
    imageLoader: makeImageLoader(store), anonStore: new AnonControlStore(store),
    customEntitiesStore: new CustomEntitiesStore(store), discoveredStore: new DiscoveredEntitiesStore(store),
    synthMetaStore: new SynthMetaStore(store), hypothesisStore: new HypothesisStore(store),
  });

  // Always show the preview — it is AI-free, and it is what the floor decision should rest on.
  const { cap, floors } = await pipeline.deepPassPreview(caseId);
  console.log(`\nDeep-pass preview for "${caseId}" (rows per batch: ${cap})`);
  console.log("  floor      events     rows   batches   est.tokens");
  for (const f of floors) {
    console.log(`  ${f.floor.padEnd(9)} ${String(f.events).padStart(7)} ${String(f.rows).padStart(8)} ${String(f.batches).padStart(9)} ${String(Math.round(f.estimatedInputTokens / 1000) + "k").padStart(12)}`);
  }

  const floor = parseMinSeverity(strOpt("floor"));
  if (!floor || floor === "Info") {
    console.log("\nNo --floor given (Critical | High | Medium | Low) — preview only, nothing spent.");
    return;
  }

  const maxBatches = Number(strOpt("max-batches")) || undefined;
  const chosen = floors.find((f) => f.floor === floor);
  console.log(`\nRunning at floor ${floor}+ — ${chosen?.events ?? "?"} event(s), ${chosen?.batches ?? "?"} batch(es), provider=${provider.name} model=${model}\n`);

  const started = Date.now();
  const result = await pipeline.deepPass(caseId, {
    minSeverity: floor,
    ...(maxBatches ? { maxBatches } : {}),
    onProgress: (done, total, detail) => console.log(`  [${done}/${total}] ${detail}`),
  });

  const state = await stateStore.load(caseId);
  console.log(`\nDone in ${Math.round((Date.now() - started) / 1000)}s. ${JSON.stringify(result)}`);
  console.log(`findings=${state.findings.length} mitre=${state.mitreTechniques.length}`);
  for (const f of state.findings) console.log(`  - ${f.severity} | ${f.title}`);
  console.log(`\nattackerPath: ${state.attackerPath ? state.attackerPath.slice(0, 400) : "(empty)"}`);
}

main().catch((e) => { console.error("deep-pass error:", e); process.exit(1); });
