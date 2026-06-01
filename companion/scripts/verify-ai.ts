// Diagnostic: confirm the configured AI provider (from .env) returns JSON that
// passes the schema, using real screenshots from a case.
//   Usage:  npm run verify:ai            (uses case "test1")
//           npm run verify:ai -- mycase  (uses case "mycase")
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { readFile, readdir } from "node:fs/promises";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildProvider } from "../src/server.js";
import { extractJsonText } from "../src/analysis/extractJson.js";
import { deltaSchema } from "../src/analysis/responseSchema.js";
import { SYSTEM_PROMPT } from "../src/analysis/pipeline.js";

function strOpt(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  if (strOpt("provider")) process.env.DFIR_AI_PROVIDER = strOpt("provider");
  if (strOpt("model")) process.env.DFIR_AI_MODEL = strOpt("model");
  if (strOpt("key")) process.env.DFIR_AI_KEY = strOpt("key");

  const provider = buildProvider();
  if (!provider) {
    console.log("No provider configured (DFIR_AI_PROVIDER unset).");
    return;
  }
  console.log(`Provider: ${provider.name}, model: ${process.env.DFIR_AI_MODEL}`);

  const raw = process.env.DFIR_AI_CASES_ROOT ?? process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  const caseId = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "test1";
  const shotsDir = join(casesRoot, caseId, "screenshots");
  let files: string[];
  try {
    const all = (await readdir(shotsDir)).filter((f) => f.endsWith(".webp")).sort();
    // Sample from the MIDDLE of the case — early screenshots are often login/welcome
    // screens with nothing forensic; the middle is more likely to hold real evidence.
    const mid = Math.floor(all.length / 2);
    files = all.slice(mid, mid + 3);
  } catch {
    console.log(`Case "${caseId}" not found under ${casesRoot}. Available: ${(await readdir(casesRoot).catch(() => [])).join(", ") || "(none)"}`);
    return;
  }
  if (files.length === 0) {
    console.log(`No screenshots in ${shotsDir}`);
    return;
  }
  console.log(`Case: ${caseId} (using ${files.length} screenshot(s))`);
  const images = await Promise.all(
    files.map(async (f) => ({
      base64: (await readFile(join(shotsDir, f))).toString("base64"),
      mimeType: "image/png",
    })),
  );

  console.log(`Sending ${images.length} screenshot(s) to the model…`);
  const result = await provider.analyze({
    systemPrompt: SYSTEM_PROMPT,
    userPrompt: "No findings yet. NEW SCREENSHOTS:\n(forensic captures attached)\n\nReturn the JSON delta.",
    images,
  });

  console.log("\n--- RAW model output (first 200 chars) ---");
  console.log(JSON.stringify(result.rawText.slice(0, 200)));
  console.log("\n--- After extractJsonText + schema parse ---");
  try {
    const delta = deltaSchema.parse(JSON.parse(extractJsonText(result.rawText)));
    console.log(`PARSE OK ✓  findings=${delta.findings.length} iocs=${delta.iocs.length} forensicEvents=${(delta.forensicEvents ?? []).length}`);
    for (const e of delta.forensicEvents ?? []) {
      console.log(`    [event] ${e.timestamp} — ${e.description}`);
    }
    if (delta.attackerPath) console.log(`    attackerPath: ${delta.attackerPath.slice(0, 160)}`);
    console.log(`    summary: ${delta.summary.slice(0, 120)}`);
  } catch (err) {
    console.log(`PARSE FAILED ✗  ${(err as Error).message}`);
  }
}

main().catch((e) => console.error("verify-ai error:", e));
