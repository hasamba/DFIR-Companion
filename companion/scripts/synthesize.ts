// Holistic synthesis pass: read a case's full forensic timeline and produce
// findings, MITRE mapping, and the attacker-path narrative. One text-only AI call.
// Run after capturing/reanalyzing, or any time to refresh conclusions.
//
//   npm run synthesize -- <caseId>
//   npm run synthesize -- <caseId> --model openai/gpt-4o
//   npm run synthesize -- <caseId> --provider gemini --model gemini-1.5-pro --key <k>
import { config as loadDotenv } from "dotenv";
loadDotenv({ quiet: true });

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { makeImageLoader } from "../src/analysis/imageLoader.js";
import { LegitimateStore } from "../src/analysis/legitimate.js";
import { ScopeStore } from "../src/analysis/scope.js";
import { AnonControlStore } from "../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../src/analysis/anonDiscovered.js";
import { SynthMetaStore } from "../src/analysis/synthMeta.js";
import { HypothesisStore } from "../src/analysis/hypothesisStore.js";
import { buildProviderFrom } from "../src/server.js";

function strOpt(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";

  // Synthesis prefers the dedicated synth model. Precedence: CLI flag >
  // DFIR_AI_SYNTH_* > the main extraction model in .env.
  const provName = strOpt("provider") ?? process.env.DFIR_AI_SYNTH_PROVIDER ?? process.env.DFIR_AI_PROVIDER;
  const model = strOpt("model") ?? process.env.DFIR_AI_SYNTH_MODEL ?? process.env.DFIR_AI_MODEL;
  const apiKey = strOpt("key") ?? process.env.DFIR_AI_SYNTH_KEY ?? process.env.DFIR_AI_KEY;
  const baseUrl = strOpt("base-url") ?? process.env.DFIR_AI_SYNTH_BASE_URL ?? process.env.DFIR_AI_BASE_URL;
  const imageDetail = process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined;
  const provider = buildProviderFrom({ provider: provName, model, apiKey, baseUrl, imageDetail });
  if (!provider) {
    console.error("No AI provider configured (DFIR_AI_PROVIDER / --provider). Aborting.");
    process.exit(1);
  }
  process.env.DFIR_AI_MODEL = model; // for the log line below
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const pipeline = new AnalysisPipeline({ provider, stateStore, legitimateStore: new LegitimateStore(store), scopeStore: new ScopeStore(store), imageLoader: makeImageLoader(store), anonStore: new AnonControlStore(store), customEntitiesStore: new CustomEntitiesStore(store), discoveredStore: new DiscoveredEntitiesStore(store), synthMetaStore: new SynthMetaStore(store), hypothesisStore: new HypothesisStore(store) });

  const before = await stateStore.load(caseId);
  console.log(`Synthesizing "${caseId}" from ${before.forensicTimeline.length} forensic events (provider=${provider.name} model=${process.env.DFIR_AI_MODEL})…`);
  if (before.forensicTimeline.length === 0) {
    console.log("No forensic timeline yet — run `npm run reanalyze -- " + caseId + "` first.");
    return;
  }

  const state = await pipeline.synthesize(caseId);
  console.log(`\nDone. findings=${state.findings.length} iocs=${state.iocs.length} mitreTechniques=${state.mitreTechniques.length}`);
  console.log(`attackerPath: ${state.attackerPath ? state.attackerPath.slice(0, 200) : "(empty)"}`);
  console.log(`Open the dashboard and connect to "${caseId}", or run: npm run coverage -- ${caseId}`);
}

main().catch((e) => console.error("synthesize error:", e));
