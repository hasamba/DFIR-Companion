// Re-run AI analysis over a case's already-captured screenshots, rebuilding the
// investigation state. Use this to recover findings that were missed (e.g. when
// analysis was failing, or to re-process after changing the model).
//
//   npm run reanalyze -- <caseId>                  analyze all non-duplicate screenshots
//   npm run reanalyze -- <caseId> --reset          start from an empty state first
//   npm run reanalyze -- <caseId> --all --reset    include duplicates too (most thorough)
//   npm run reanalyze -- <caseId> --window 3       screenshots per AI call (default 4)
//   npm run reanalyze -- <caseId> --reset --model openai/gpt-4o     re-run with another model
//   npm run reanalyze -- <caseId> --provider gemini --model gemini-1.5-pro --key <k>
//
// Two-tier: a CHEAP model reads each screenshot, a STRONGER model writes the
// findings / attacker-path synthesis (one text-only call):
//   npm run reanalyze -- <caseId> --reset --model openai/gpt-4o-mini --synth-model openai/gpt-4o
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { readFile } from "node:fs/promises";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { makeImageLoader } from "../src/analysis/imageLoader.js";
import { emptyState } from "../src/analysis/stateTypes.js";
import { LegitimateStore } from "../src/analysis/legitimate.js";
import { ScopeStore } from "../src/analysis/scope.js";
import { buildProviderFrom } from "../src/server.js";
import type { CaptureMetadata } from "../src/types.js";

function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}
function opt(name: string, fallback: number): number {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? Number(process.argv[i + 1]) : fallback;
}
function strOpt(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  const includeAll = flag("all");
  const reset = flag("reset");
  const windowSize = Math.max(1, opt("window", 4));

  const imageDetail = process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined;

  // Extraction model (per screenshot) — CLI overrides fall back to .env.
  const provName = strOpt("provider") ?? process.env.DFIR_AI_PROVIDER;
  const model = strOpt("model") ?? process.env.DFIR_AI_MODEL;
  const apiKey = strOpt("key") ?? process.env.DFIR_AI_KEY;
  const baseUrl = strOpt("base-url") ?? process.env.DFIR_AI_BASE_URL;
  const provider = buildProviderFrom({ provider: provName, model, apiKey, baseUrl, imageDetail });
  if (!provider) {
    console.error("No AI provider configured (DFIR_AI_PROVIDER / --provider). Aborting.");
    process.exit(1);
  }

  // Optional stronger synthesis model. Precedence: CLI flag > DFIR_AI_SYNTH_* env >
  // the extraction model. Two-tier is active whenever it differs from extraction.
  const synthProvName = strOpt("synth-provider") ?? process.env.DFIR_AI_SYNTH_PROVIDER ?? provName;
  const synthModel = strOpt("synth-model") ?? process.env.DFIR_AI_SYNTH_MODEL ?? model;
  const synthKey = strOpt("synth-key") ?? process.env.DFIR_AI_SYNTH_KEY ?? apiKey;
  const synthBaseUrl = strOpt("synth-base-url") ?? process.env.DFIR_AI_SYNTH_BASE_URL ?? baseUrl;
  const usingTwoTier = synthModel !== model || synthProvName !== provName;
  const synthesisProvider = usingTwoTier
    ? buildProviderFrom({ provider: synthProvName, model: synthModel, apiKey: synthKey, baseUrl: synthBaseUrl, imageDetail })
    : provider;

  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);

  const store = new CaseStore(casesRoot);
  const stateStore = new StateStore(store);
  const pipeline = new AnalysisPipeline({ provider, synthesisProvider, stateStore, legitimateStore: new LegitimateStore(store), scopeStore: new ScopeStore(store), imageLoader: makeImageLoader(store) });

  const logText = await readFile(store.capturesLogPath(caseId), "utf8");
  const all: CaptureMetadata[] = logText.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

  // analyzeWindow skips isDuplicate; with --all we force them in by clearing the flag.
  const pool = includeAll
    ? all.map((c) => ({ ...c, isDuplicate: false }))
    : all.filter((c) => !c.isDuplicate);

  const windows = Math.ceil(pool.length / windowSize);
  console.log(`Case "${caseId}" — extraction: ${provName}/${model}` +
    (usingTwoTier ? `  |  synthesis: ${synthProvName}/${synthModel}` : ""));
  console.log(`Re-analyzing ${pool.length} screenshot(s) in ${windows} window(s) of ${windowSize}` +
    `${includeAll ? " (including duplicates)" : ""}${reset ? " (state reset)" : " (merging into existing state)"}.`);
  console.log(`This makes ~${windows} AI call(s) and will use your API quota.\n`);

  if (reset) await stateStore.save(emptyState(caseId));

  let ok = 0, failed = 0;
  for (let i = 0; i < pool.length; i += windowSize) {
    const win = pool.slice(i, i + windowSize);
    const n = Math.floor(i / windowSize) + 1;
    try {
      const state = await pipeline.analyzeWindow(caseId, win);
      ok++;
      console.log(`  window ${n}/${windows} ✓  findings=${state.findings.length} timeline=${state.timeline.length} iocs=${state.iocs.length}`);
    } catch (err) {
      failed++;
      console.log(`  window ${n}/${windows} ✗  ${(err as Error).message}`);
    }
    await new Promise((r) => setTimeout(r, 400)); // gentle pacing for rate limits
  }

  // Holistic synthesis: derive findings / MITRE / attacker path from the full
  // forensic timeline (each window only sees a few screenshots and can't do this).
  if (!flag("no-synthesis")) {
    console.log(`\nSynthesizing conclusions from the full forensic timeline…`);
    try {
      await pipeline.synthesize(caseId);
    } catch (err) {
      console.log(`  synthesis failed: ${(err as Error).message}`);
    }
  }

  const final = await stateStore.load(caseId);
  console.log(`\nDone. ${ok} window(s) ok, ${failed} failed.`);
  console.log(`Final state: findings=${final.findings.length} iocs=${final.iocs.length} forensicEvents=${final.forensicTimeline.length} techniques=${final.mitreTechniques.length}`);
  console.log(`Attacker path: ${final.attackerPath ? "yes" : "(empty — try a stronger model)"}`);
  console.log(`Open the dashboard and connect to "${caseId}" to view, or run: npm run coverage -- ${caseId}`);
}

main().catch((e) => console.error("reanalyze error:", e));
