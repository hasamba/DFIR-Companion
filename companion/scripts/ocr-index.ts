// Backfill the screenshot OCR full-text search index (#176) for a case. OCRs every
// screenshot that isn't already in metadata/ocr.json — use it for a case whose screenshots were
// captured BEFORE this feature existed or BEFORE OCR search was enabled (live captures index
// themselves automatically; the server queues a burst rather than dropping it).
//   Usage:  npm run ocr-index -- <caseId>   (default: test1)
//
// #1866: the run belongs to the case incarnation it started on. It reads the case's generation at
// start, and every index write re-checks it, so a case deleted — or deleted and re-created under
// the same id — while the run is OCRing is never written to: the run stops and says so.
import { config as loadDotenv } from "dotenv";

import { readFile } from "node:fs/promises";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CaseStore } from "../src/storage/caseStore.js";
import { TesseractOcrRunner, type OcrWord } from "../src/analysis/ocrRedact.js";
import { extractOcrText, isOcrSearchEnabled } from "../src/analysis/ocrSearch.js";
import {
  capturedGeneration,
  caseWriteRefusalFor,
  isCaseWriteRefused,
  runInCaseScope,
} from "../src/storage/caseIncarnation.js";
import type { CaptureMetadata } from "../src/types.js";

function casesRoot(): string {
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  const companionDir = fileURLToPath(new URL("../", import.meta.url));
  return isAbsolute(raw) ? raw : resolve(companionDir, raw);
}

export interface OcrBackfillDeps {
  store: CaseStore;
  caseId: string;
  force: boolean;
  recognize: (bytes: Buffer) => Promise<OcrWord[]>;
  log: (line: string) => void;
  error: (line: string) => void;
}

export type OcrBackfillOutcome = "done" | "missing" | "no-captures" | "case-changed";

async function readCaptures(store: CaseStore, caseId: string): Promise<CaptureMetadata[] | null> {
  let log: string;
  try {
    log = await readFile(store.capturesLogPath(caseId), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  return log
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as CaptureMetadata);
}

/** OCR every un-indexed screenshot of one case incarnation into its index. */
export function backfillOcrIndex(deps: OcrBackfillDeps): Promise<OcrBackfillOutcome> {
  const { store, caseId } = deps;
  // The generation is captured here, once. A case with no case.json captures none.
  return runInCaseScope(store.casesRoot, caseId, async () => {
    if (capturedGeneration(store.casesRoot, caseId) === null || !(await store.caseExists(caseId))) {
      deps.error(`case "${caseId}" does not exist`);
      return "missing";
    }
    // Is the incarnation this run captured still the case on disk? Checked before every exit, so a
    // case deleted or replaced mid-run is reported, never a quiet "done".
    const changed = () => caseWriteRefusalFor(store.caseDir(caseId)) !== null;
    const stopped = (done: number): OcrBackfillOutcome => {
      deps.error(
        `case "${caseId}" was deleted or replaced during the run — stopped after ${done} screenshot(s); nothing more was written.`,
      );
      return "case-changed";
    };
    const captures = await readCaptures(store, caseId);
    if (changed()) return stopped(0);
    if (!captures) {
      deps.log(`no captures.jsonl for "${caseId}" — nothing to index.`);
      return "no-captures";
    }
    const index = await store.loadOcrIndex(caseId);
    // Unique screenshot files (duplicates re-use the previous frame's bytes — index once).
    const files = Array.from(new Set(captures.map((c) => c.screenshotFile).filter(Boolean)));
    const todo = deps.force ? files : files.filter((f) => !index[f]);
    deps.log(
      `Case "${caseId}": ${files.length} screenshots, ${todo.length} to OCR${deps.force ? " (--force: re-indexing all)" : ""}.`,
    );
    let done = 0;
    for (const file of todo) {
      try {
        const bytes = await readFile(join(store.screenshotsDir(caseId), file));
        const text = extractOcrText(await deps.recognize(bytes));
        await store.putOcrEntry(caseId, {
          screenshotFile: file,
          text,
          ocrAt: new Date().toISOString(),
          wordCount: text.length === 0 ? 0 : text.split(" ").length,
        });
        done++;
        if (done % 10 === 0 || done === todo.length) deps.log(`  indexed ${done}/${todo.length}`);
      } catch (err) {
        if (isCaseWriteRefused(err) || changed()) return stopped(done);
        deps.error(`  skip ${file}: ${(err as Error).message}`);
      }
    }
    if (changed()) return stopped(done);
    deps.log(`Done. Indexed ${done} screenshot(s).`);
    return "done";
  });
}

async function main(): Promise<void> {
  loadDotenv({ quiet: true });
  const args = process.argv.slice(2);
  // --force re-OCRs screenshots already in the index (use after changing the OCR text rules,
  // e.g. the confidence floor). Without it, only un-indexed screenshots are processed.
  const force = args.includes("--force");
  const caseId = args.find((a) => !a.startsWith("--")) ?? "test1";
  if (!isOcrSearchEnabled()) {
    console.log("OCR search is disabled (DFIR_OCR_SEARCH=off) — backfilling anyway by request.");
  }
  const runner = new TesseractOcrRunner();
  const outcome = await backfillOcrIndex({
    store: new CaseStore(casesRoot()),
    caseId,
    force,
    recognize: (bytes) => runner.recognize(bytes),
    log: (line) => console.log(line),
    error: (line) => console.error(line),
  });
  if (outcome === "missing" || outcome === "case-changed") process.exitCode = 1;
}

// Run only as the CLI; a test imports backfillOcrIndex without starting a run.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((e) => console.error("ocr-index error:", e));
}
