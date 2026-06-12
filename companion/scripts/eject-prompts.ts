// Write the built-in AI prompts to files so they can be customized, then point the
// matching DFIR_AI_*_PROMPT_FILE env vars at them. Usage:
//   npm run prompts:eject            -> writes to ./prompts
//   npm run prompts:eject -- ./mine  -> writes to ./mine
import { writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  SYSTEM_PROMPT, CSV_SYSTEM_PROMPT, LOG_SYSTEM_PROMPT, SYNTHESIS_PROMPT, ASK_PROMPT, EXEC_SUMMARY_PROMPT,
  HUNT_SUGGEST_PROMPT,
} from "../src/analysis/pipeline.js";

const dir = resolve(process.argv[2] || "./prompts");
mkdirSync(dir, { recursive: true });

const files: Array<[string, string, string]> = [
  ["system.txt", SYSTEM_PROMPT, "DFIR_AI_SYSTEM_PROMPT_FILE"],
  ["csv.txt", CSV_SYSTEM_PROMPT, "DFIR_AI_CSV_PROMPT_FILE"],
  ["log.txt", LOG_SYSTEM_PROMPT, "DFIR_AI_LOG_PROMPT_FILE"],
  ["synthesis.txt", SYNTHESIS_PROMPT, "DFIR_AI_SYNTH_PROMPT_FILE"],
  ["ask.txt", ASK_PROMPT, "DFIR_AI_ASK_PROMPT_FILE"],
  ["exec-summary.txt", EXEC_SUMMARY_PROMPT, "DFIR_AI_EXEC_PROMPT_FILE"],
  ["hunts.txt", HUNT_SUGGEST_PROMPT, "DFIR_AI_HUNTS_PROMPT_FILE"],
];

for (const [name, text] of files) {
  const path = join(dir, name);
  writeFileSync(path, text, "utf8");
  console.log(`wrote ${path} (${text.length} chars)`);
}

console.log("\nEdit the files above, then add these to companion/.env to use them:");
for (const [name, , env] of files) console.log(`  ${env}=${join(dir, name)}`);
console.log("\nFiles are re-read on each AI call, so edits apply on the next analysis (no restart).");
