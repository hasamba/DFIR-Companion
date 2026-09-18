import type { Express, Request, Response } from "express";
import { open } from "node:fs/promises";
import { basename } from "node:path";
import type { RouteContext } from "./context.js";
import type { SettleDeps } from "./importSettle.js";
import { commitDedicatedImport } from "./importCommit.js";
import { parseMacLoginItemBtm } from "../analysis/macLoginItemImport.js";
import { detectBinaryImportKind, MAC_LOGIN_ITEM_FILENAMES } from "../analysis/macBinaryDetect.js";
import { MAX_INPUT_BYTES } from "../analysis/bplistReader.js";
import { FileTooLargeError, readHandleBounded } from "../storage/boundedRead.js";
import { maxImportFileBytes } from "./importFileHead.js";

/**
 * The two byte-native import routes for macOS login-item containers — both BTM generations, the
 * LSSharedFileList `SessionLoginItems.sfl2` list and the classic `com.apple.loginitems.plist`
 * (#1013, #1301). Every other import kind in this codebase reads `text: string`; these artifacts
 * are binary plists, and reading them as text corrupts them (the same reasoning `saveRawImport`/
 * #688 established for .evtx/PCAP originals).
 *
 * - POST /cases/:id/import-mac-login-item — by SERVER-LOCAL PATH: the operator names a file the
 *   server reads, so it sits behind the same global-admin gate `/import-file` uses (auth/policy.ts
 *   CASE_GLOBAL_ADMIN_SEGMENTS) — that gate is about reading the server's filesystem, not about
 *   the format.
 * - POST /cases/:id/import-binary — the caller's OWN bytes, base64 in JSON (the envelope
 *   routes/tools.ts's run-upload already uses), dispatched on detectBinaryImportKind(). Nothing on
 *   the server is read, so it is an ordinary case-scoped write, the same trust as run-upload. This
 *   is what the dashboard's file picker and drop zone call for a recognized binary name (#1301).
 *
 * Both share acceptMacLoginItemBytes() below — detect → preview → persist → ledger → 202 → commit
 * — so the two cannot drift. The evidence drop-folder poller has its own byte-native seam
 * (composition/importIngest.ts ingestMacLoginItemStreamed, #1153).
 */
export function registerMacLoginItemImportRoute(
  app: Express,
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
): void {
  const { options } = ctx;

  // Capped at the PARSER's own bound (32 MiB), never the codebase-wide text-import ceiling
  // (256 MiB by default) — reading up to that much into memory only to have the parser reject it
  // immediately would let a trusted-but-mistaken caller force a large, wasted allocation for
  // every oversized file (Ollama code review finding).
  const readCap = (): number => Math.min(maxImportFileBytes(), MAX_INPUT_BYTES);

  app.post("/cases/:id/import-mac-login-item", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const filePath = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!filePath)
      return res.status(400).json({ error: "path is required (absolute path to a file on the server)" });
    const originalName = basename(filePath);

    let bytes: Buffer;
    try {
      const fh = await open(filePath, "r");
      try {
        bytes = await readHandleBounded(fh, readCap());
      } finally {
        await fh.close();
      }
    } catch (err) {
      if (err instanceof FileTooLargeError) {
        return res.status(413).json({ error: `file is too large to import (${err.size} bytes)` });
      }
      return res.status(400).json({ error: `cannot read file: ${(err as Error).message}` });
    }
    return acceptMacLoginItemBytes(ctx, settleDeps, caseId, originalName, bytes, res);
  });

  app.post("/cases/:id/import-binary", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    // `filename` is caller-controlled here (on the path route it derives from an admin's server
    // path). It is an opaque label only — normalized to its basename, never joined into a path —
    // and anything that could not be a plain file name is refused before a byte is decoded.
    const rawName = typeof req.body?.filename === "string" ? req.body.filename.trim() : "";
    const filename = basename(rawName);
    if (!filename || filename !== rawName || filename.length > 255 || /[\x00-\x1f\x7f\\/]/.test(filename)) {
      return res.status(400).json({ error: "filename is required and must be a plain file name" });
    }
    const dataBase64 = typeof req.body?.dataBase64 === "string" ? req.body.dataBase64 : "";
    if (!dataBase64) return res.status(400).json({ error: "dataBase64 is required" });
    // Bound the DECODED size from the encoded length before allocating anything: 4 base64 chars
    // carry 3 bytes. The JSON body itself is already bounded by DFIR_MAX_BODY_MB in httpStack.ts.
    const cap = readCap();
    if (Math.floor((dataBase64.length * 3) / 4) > cap) {
      return res.status(413).json({ error: `file is too large to import (over ${cap} bytes)` });
    }
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(dataBase64) || dataBase64.length % 4 !== 0) {
      return res.status(400).json({ error: "dataBase64 is not valid base64" });
    }
    const bytes = Buffer.from(dataBase64, "base64");
    if (bytes.length > cap) {
      return res.status(413).json({ error: `file is too large to import (${bytes.length} bytes)` });
    }
    return acceptMacLoginItemBytes(ctx, settleDeps, caseId, filename, bytes, res);
  });
}

/**
 * The shared tail: detect → preview → persist → ledger → 202 → commit. The kind is echoed in the
 * response so the dashboard can say what the server recognized without a second round trip.
 */
async function acceptMacLoginItemBytes(
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
  caseId: string,
  originalName: string,
  bytes: Buffer,
  res: Response,
): Promise<void> {
  const { store, options } = ctx;
  const pipeline = options.pipeline;
  if (!pipeline) {
    res.status(501).json({ error: "AI pipeline not configured" });
    return;
  }
  const kind = detectBinaryImportKind(originalName, bytes);
  if (!kind) {
    res.status(400).json({
      error:
        `not a recognized macOS login-item file (expected ${MAC_LOGIN_ITEM_FILENAMES}, ` +
        "starting with the bplist00 magic)",
    });
    return;
  }

  try {
    const preview = parseMacLoginItemBtm(bytes);
    if (!preview || preview.total === 0) {
      res
        .status(400)
        .json({ error: "no recognized login-item entries found (unrecognized container structure)" });
      return;
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
      kind,
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
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
}
