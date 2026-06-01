// Holistic synthesis pass: read a case's full forensic timeline and produce
// findings, MITRE mapping, and the attacker-path narrative. One text-only AI call.
// Run after capturing/reanalyzing, or any time to refresh conclusions.
//
//   npm run synthesize -- <caseId>
//   npm run synthesize -- <caseId> --model openai/gpt-4o
//   npm run synthesize -- <caseId> --provider gemini --model gemini-1.5-pro --key <k>
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { makeImageLoader } from "../src/analysis/imageLoader.js";
import { buildProvider } from "../src/server.js";

function strOpt(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  if (strOpt("provider")) process.env.DFIR_AI_PROVIDER = strOpt("provider");
  if (strOpt("model")) process.env.DFIR_AI_MODEL = strOpt("model");
  if (strOpt("key")) process.env.DFIR_AI_KEY = strOpt("key");

  const provider = buildProvider();
  if (!provider) {
    console.error("No AI provider configured in .env (DFIR_AI_PROVIDER). Aborting.");
    process.exit(1);
  }
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: makeImageLoader(store) });

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
