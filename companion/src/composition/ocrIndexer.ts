/**
 * Screenshot OCR full-text search index (#176), lifted out of createApp by #416.
 *
 * Runs in the BACKGROUND after a capture is persisted — never on the /captures hot path, because
 * Tesseract is ~0.5-2s per image and evidence-first means the screenshot is already safely on disk
 * before anything optional happens to it. Best-effort throughout: a failure is logged at debug and
 * never thrown, since a missing search index is a degraded feature, not lost evidence.
 *
 * A burst of captures (a batch import, a drop folder of screenshots) is QUEUED and drained at most
 * OCR_MAX_CONCURRENT at a time, so every non-duplicate screenshot is eventually indexed rather than
 * dropped — without spawning N Tesseract workers at once. OCR_MAX_QUEUE is a runaway safety net
 * only; in practice captures are paced far slower than OCR drains, and anything the cap does drop
 * is recoverable with `npm run ocr-index`.
 */
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import type { CaseStore } from "../storage/caseStore.js";
import { TesseractOcrRunner, type OcrRunner } from "../analysis/ocrRedact.js";
import { extractOcrText, isOcrSearchEnabled } from "../analysis/ocrSearch.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { CaptureMetadata } from "../types.js";

const OCR_MAX_CONCURRENT = 2;
const OCR_MAX_QUEUE = 1000;

export interface OcrIndexerDeps {
  store: CaseStore;
  /** Absent → a fresh TesseractOcrRunner per job (the production default; tests inject a stub). */
  ocrRunner?: OcrRunner;
}

export interface OcrIndexer {
  /** Queue a capture for background OCR indexing. Returns immediately; never throws. */
  indexCaptureText(metadata: CaptureMetadata): void;
}

export function createOcrIndexer({ store, ocrRunner }: OcrIndexerDeps): OcrIndexer {
  const queue: CaptureMetadata[] = [];
  let active = 0;

  function pump(): void {
    while (active < OCR_MAX_CONCURRENT && queue.length > 0) {
      const metadata = queue.shift()!;
      active++;
      void (async () => {
        try {
          const path = join(store.screenshotsDir(metadata.caseId), metadata.screenshotFile);
          const bytes = await readFile(path);
          const runner = ocrRunner ?? new TesseractOcrRunner();
          const words = await runner.recognize(bytes);
          const text = extractOcrText(words);
          await store.putOcrEntry(metadata.caseId, {
            screenshotFile: metadata.screenshotFile,
            text,
            ocrAt: new Date().toISOString(),
            wordCount: text.length === 0 ? 0 : text.split(" ").length,
          });
        } catch (err) {
          getServerLogger().debug(
            `OCR index failed for ${metadata.screenshotFile}: ${(err as Error).message}`,
            { caseId: metadata.caseId },
          );
        } finally {
          active--;
          pump();
        }
      })();
    }
  }

  return {
    indexCaptureText(metadata) {
      if (!isOcrSearchEnabled() || !metadata.screenshotFile || metadata.isDuplicate) return;
      if (queue.length >= OCR_MAX_QUEUE) {
        // Runaway safety net only — recover anything dropped here with `npm run ocr-index`.
        getServerLogger().debug(`OCR index: queue full, skipped seq=${metadata.sequenceNumber}`, {
          caseId: metadata.caseId,
        });
        return;
      }
      queue.push(metadata);
      pump();
    },
  };
}
