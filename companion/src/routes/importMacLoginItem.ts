import type { Express, Request, Response } from "express";
import { open } from "node:fs/promises";
import { basename } from "node:path";
import type { RouteContext } from "./context.js";
import type { SettleDeps } from "./importSettle.js";
import { commitDedicatedImport } from "./importCommit.js";
import { parseMacLoginItemBtm } from "../analysis/macLoginItemImport.js";
import { detectBinaryImportKind } from "../analysis/macBinaryDetect.js";
import { MAX_INPUT_BYTES } from "../analysis/bplistReader.js";
import { FileTooLargeError, readHandleBounded } from "../storage/boundedRead.js";
import { maxImportFileBytes } from "./importFileHead.js";

/**
 * POST /cases/:id/import-mac-login-item — one macOS Background Task Management file
 * (backgrounditems.btm / BackgroundItems-v*.btm), by SERVER-LOCAL PATH (#1013).
 *
 * Byte-native, not text: every other import kind in this codebase reads `text: string`, but this
 * artifact is a binary keyed-archive bplist, and reading it as text would corrupt it (the same
 * reasoning `saveRawImport`/#688 already established for .evtx/PCAP originals). No existing route
 * accepts raw bytes from the browser upload path today, so this landing is path-based only — the
 * same "operator names a server-local file" mechanism `/cases/:id/import-file` already uses for
 * files the browser can't handle, gated the same way (see auth/policy.ts's
 * CASE_GLOBAL_ADMIN_SEGMENTS). Two paths are deliberately NOT wired to this yet, filed as a
 * follow-up on landing: a drag-and-drop / browser-upload path, and the evidence drop-folder's own
 * auto-import sweep (a BTM file placed there is still classified `raw-tool-input` by
 * dropScan.ts's generic NUL-byte check, exactly as before this route existed). See
 * RECOMMENDATION-12.md for the full research trail.
 */
export function registerMacLoginItemImportRoute(
  app: Express,
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
): void {
  const { store, options } = ctx;

  app.post("/cases/:id/import-mac-login-item", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const pipeline = options.pipeline;
    const caseId = req.params.id;
    const filePath = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!filePath)
      return res.status(400).json({ error: "path is required (absolute path to a file on the server)" });
    const originalName = basename(filePath);

    // Capped at the PARSER's own bound (32 MiB), never the codebase-wide text-import ceiling
    // (256 MiB by default) — reading up to that much into memory only to have the parser reject it
    // immediately would let a trusted-but-mistaken caller force a large, wasted allocation for
    // every oversized file (Ollama code review finding).
    const readCap = Math.min(maxImportFileBytes(), MAX_INPUT_BYTES);
    let bytes: Buffer;
    try {
      const fh = await open(filePath, "r");
      try {
        bytes = await readHandleBounded(fh, readCap);
      } finally {
        await fh.close();
      }
    } catch (err) {
      if (err instanceof FileTooLargeError) {
        return res.status(413).json({ error: `file is too large to import (${err.size} bytes)` });
      }
      return res.status(400).json({ error: `cannot read file: ${(err as Error).message}` });
    }

    if (!detectBinaryImportKind(originalName, bytes)) {
      return res.status(400).json({
        error:
          "not a recognized macOS Background Task Management file " +
          "(expected backgrounditems.btm or BackgroundItems-v*.btm, starting with the bplist00 magic)",
      });
    }

    try {
      const preview = parseMacLoginItemBtm(bytes);
      if (!preview || preview.total === 0) {
        return res
          .status(400)
          .json({ error: "no recognized login-item entries found (unrecognized BTM structure)" });
      }

      const seq = await store.nextImportSeq(caseId);
      const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "backgrounditems.btm";
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveRawImport(caseId, storedName, bytes);
      await store.appendImport(caseId, {
        caseId,
        sequenceNumber: seq,
        importedAt,
        filename: storedName,
        originalName,
        rows: preview.kept,
        bytes: bytes.byteLength,
      });

      res.status(202).json({
        accepted: true,
        file: storedName,
        importSeq: seq,
        events: preview.kept,
        records: preview.total,
        groups: preview.groups,
        format: preview.format,
        sourceFormat: preview.sourceFormat,
      });

      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: importedAt,
        detail: `importing ${preview.kept} macOS login item(s)`,
      });

      commitDedicatedImport(ctx, settleDeps, {
        caseId,
        kind: "macloginitem",
        storedName,
        importedAt,
        linesIn: preview.total,
        path: "deterministic",
        run: () =>
          pipeline.importMacLoginItem(caseId, bytes, {
            label: storedName,
            idPrefix: `bt${seq}`,
            importedAt,
          }),
      });
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
