// Backfill the screenshot OCR full-text search index (#176) for a case. OCRs every
// screenshot that isn't already in metadata/ocr.json — use it for a case whose screenshots were
// captured BEFORE this feature existed or BEFORE OCR search was enabled (live captures index
// themselves automatically; the server queues a burst rather than dropping it).
//   Usage:  npm run ocr-index -- <caseId>   (default: test1)
import { config as loadDotenv } from "dotenv";
loadDotenv();

import { readFile } from "node:fs/promises";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { TesseractOcrRunner } from "../src/analysis/ocrRedact.js";
import { extractOcrText, isOcrSearchEnabled } from "../src/analysis/ocrSearch.js";
import type { CaptureMetadata } from "../src/types.js";

function casesRoot(): string {
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  return isAbsolute(raw) ? raw : resolve(companionDir, raw);
}

async function main(): Promise<void> {
  const caseId = process.argv[2] ?? "test1";
  if (!isOcrSearchEnabled()) {
    console.log("OCR search is disabled (DFIR_OCR_SEARCH=off) — backfilling anyway by request.");
  }
  const store = new CaseStore(casesRoot());
  if (!(await store.caseExists(caseId))) {
    console.error(`case "${caseId}" does not exist`);
    process.exit(1);
  }

  let captures: CaptureMetadata[] = [];
  try {
    const log = await readFile(store.capturesLogPath(caseId), "utf8");
    captures = log.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    console.log(`no captures.jsonl for "${caseId}" — nothing to index.`);
    return;
  }

  const index = await store.loadOcrIndex(caseId);
  // Unique screenshot files (duplicates re-use the previous frame's bytes — index once).
  const files = Array.from(new Set(captures.map((c) => c.screenshotFile).filter(Boolean)));
  const todo = files.filter((f) => !index[f]);
  console.log(`Case "${caseId}": ${files.length} screenshots, ${todo.length} need OCR.`);

  const runner = new TesseractOcrRunner();
  let done = 0;
  for (const file of todo) {
    try {
      const bytes = await readFile(join(store.screenshotsDir(caseId), file));
      const words = await runner.recognize(bytes);
      const text = extractOcrText(words);
      await store.putOcrEntry(caseId, {
        screenshotFile: file,
        text,
        ocrAt: new Date().toISOString(),
        wordCount: text.length === 0 ? 0 : text.split(" ").length,
      });
      done++;
      if (done % 10 === 0 || done === todo.length) console.log(`  indexed ${done}/${todo.length}`);
    } catch (err) {
      console.error(`  skip ${file}: ${(err as Error).message}`);
    }
  }
  console.log(`Done. Indexed ${done} screenshot(s).`);
}

main().catch((e) => console.error("ocr-index error:", e));
