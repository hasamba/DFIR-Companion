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
import { buildProvider } from "../src/server.js";
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

  // CLI overrides let you re-run with a different provider/model without editing .env.
  const provOverride = strOpt("provider");
  const modelOverride = strOpt("model");
  const keyOverride = strOpt("key");
  if (provOverride) process.env.DFIR_AI_PROVIDER = provOverride;
  if (modelOverride) process.env.DFIR_AI_MODEL = modelOverride;
  if (keyOverride) process.env.DFIR_AI_KEY = keyOverride;

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

  const logText = await readFile(store.capturesLogPath(caseId), "utf8");
  const all: CaptureMetadata[] = logText.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

  // analyzeWindow skips isDuplicate; with --all we force them in by clearing the flag.
  const pool = includeAll
    ? all.map((c) => ({ ...c, isDuplicate: false }))
    : all.filter((c) => !c.isDuplicate);

  const windows = Math.ceil(pool.length / windowSize);
  console.log(`Case "${caseId}" — provider=${provider.name} model=${process.env.DFIR_AI_MODEL}`);
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

  const final = await stateStore.load(caseId);
  console.log(`\nDone. ${ok} window(s) ok, ${failed} failed.`);
  console.log(`Final state: findings=${final.findings.length} iocs=${final.iocs.length} timeline=${final.timeline.length} techniques=${final.mitreTechniques.length}`);
  console.log(`Open the dashboard and connect to "${caseId}" to view, or run: npm run coverage -- ${caseId}`);
}

main().catch((e) => console.error("reanalyze error:", e));
