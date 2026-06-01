// Report how many of a case's screenshots were actually analyzed by the AI.
//   Usage:  npm run coverage -- <caseId>   (default: test1)
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { readFile } from "node:fs/promises";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CaptureMetadata } from "../src/types.js";
import type { InvestigationState } from "../src/analysis/stateTypes.js";

function casesRoot(): string {
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  return isAbsolute(raw) ? raw : resolve(companionDir, raw);
}

async function main(): Promise<void> {
  const caseId = process.argv[2] ?? "test1";
  const root = casesRoot();

  const logText = await readFile(join(root, caseId, "metadata", "captures.jsonl"), "utf8");
  const captures: CaptureMetadata[] = logText.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const dup = captures.filter((c) => c.isDuplicate).length;
  const uniq = captures.length - dup;

  let state: InvestigationState | null = null;
  try {
    state = JSON.parse(await readFile(join(root, caseId, "state", "investigation.json"), "utf8"));
  } catch { /* none yet */ }

  console.log(`Case "${caseId}":`);
  console.log(`  total captures:          ${captures.length}`);
  console.log(`  duplicates (skipped):    ${dup}`);
  console.log(`  non-duplicate (eligible):${" ".repeat(0)} ${uniq}`);

  if (!state) {
    console.log(`\n  No investigation.json yet — NOTHING analyzed.`);
    return;
  }

  const referenced = new Set<string>();
  for (const t of state.timeline) (t.sourceScreenshots ?? []).forEach((s) => referenced.add(s));
  for (const f of state.findings) (f.sourceScreenshots ?? []).forEach((s) => referenced.add(s));

  const nonDup = captures.filter((c) => !c.isDuplicate).map((c) => c.screenshotFile);
  const analyzed = nonDup.filter((f) => referenced.has(f)).length;

  console.log(`\n  findings=${state.findings.length} iocs=${state.iocs.length} timeline=${state.timeline.length} techniques=${state.mitreTechniques.length}`);
  console.log(`\n  COVERAGE (non-duplicate screenshots):`);
  console.log(`    analyzed:              ${analyzed} / ${uniq}`);
  console.log(`    NOT analyzed:          ${uniq - analyzed}`);
  if (uniq - analyzed > 0) {
    console.log(`\n  ${uniq - analyzed} eligible screenshots were never analyzed.`);
    console.log(`  Run:  npm run reanalyze -- ${caseId}        (analyze the gap)`);
    console.log(`  Or:   npm run reanalyze -- ${caseId} --all --reset   (re-do everything, incl. duplicates)`);
  }
}

main().catch((e) => console.error("coverage error:", e));
