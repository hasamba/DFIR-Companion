import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { open, rm, rmdir } from "node:fs/promises";
import { join } from "node:path";
import { parseAssetHost } from "../analysis/assetHost.js";
import { maxUploadBytes, uploadTooLargeMessage } from "../analysis/ingest/importFileCap.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { CopyContentChangedError } from "../storage/handleCopy.js";
import {
  spoolUpload,
  UploadAbortedError,
  UploadTooLargeError,
  type SpooledUpload,
} from "../storage/uploadSpool.js";
import type { RouteContext } from "./context.js";
import { importFromHandle } from "./importFromHandle.js";
import { receiptName, recordReceived } from "./importReceipt.js";
import { CHANGED_WHILE_IMPORTING } from "./receiptedFile.js";

/**
 * POST /cases/:id/import-upload — the dashboard's upload for a file too large to read in the
 * browser, and for any `.gz` (#2336). The body is the file's raw bytes (application/octet-stream);
 * the file name and import options travel in the query string:
 *   ?filename=<name>&minSeverity=<sev>&webLogFormat=<profile>&assetHost=<host>
 *
 * WHO and WHICH CASE are settled before a byte is read. The body parsers skip this route
 * (http/rawUploadPath.ts), so by the time this handler runs, team auth has authenticated and
 * authorised the caller as a WRITER of this case (auth/policy.ts — case write, the same as /import,
 * never the global-admin bar of /import-file, because the bytes come from the client, not from a
 * server path), the case lock gate has run, and the import case guard has 404'd an unknown case and
 * 423'd a closed or archived one. The route then refuses a wrong content type or a declared length
 * over DFIR_MAX_UPLOAD_MB, still without reading.
 *
 * Only then is the body streamed to a spool file inside the case folder under the hard cap, hashed
 * as it goes, and receipted on the chain of custody. From there it is Import-from-path: the shared
 * flow in routes/importFromHandle.ts sniffs the head (gzip-aware), detects the kind, streams Plaso
 * and large/gzip cloud exports from disk, stores the evidence copy and registers the job. The spool
 * is removed whatever happens. The client names a file, never a path: only its base name is kept.
 */

/** The spool folder inside a case. Its files live only for the length of one request. */
export const UPLOAD_SPOOL_DIR = "upload-spool";
export const IMPORT_UPLOAD_ROUTE = "import-upload";
const OCTET_STREAM = "application/octet-stream";

/**
 * Answer without reading the body. `Connection: close` stops Node from draining the rest of an
 * unread upload after the answer, so a refused 2 GB body is not received anyway.
 */
function refuse(res: Response, status: number, error: string): Response {
  res.setHeader("Connection", "close");
  return res.status(status).json({ error });
}

const queryText = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/** The validated query options, or the 400 sentence. */
function readOptions(req: Request): { error: string } | { filename: string; body: Record<string, unknown> } {
  const host = parseAssetHost(queryText(req.query.assetHost));
  if (!host.ok) return { error: host.error };
  return {
    filename: receiptName(queryText(req.query.filename), "upload.dat"),
    body: {
      minSeverity: queryText(req.query.minSeverity),
      webLogFormat: queryText(req.query.webLogFormat),
      assetHost: host.host || undefined,
    },
  };
}

export function registerImportUploadRoute(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.post(`/cases/:id/${IMPORT_UPLOAD_ROUTE}`, async (req: Request, res: Response) => {
    if (!options.pipeline) return refuse(res, 501, "AI pipeline not configured");
    const caseId = req.params.id;
    const type = String(req.headers["content-type"] ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (type !== OCTET_STREAM) {
      return refuse(res, 415, `send the file as the raw request body with content-type ${OCTET_STREAM}`);
    }
    const opts = readOptions(req);
    if ("error" in opts) return refuse(res, 400, opts.error);
    const maxBytes = maxUploadBytes();
    if (Number(req.headers["content-length"]) > maxBytes) {
      return refuse(res, 413, uploadTooLargeMessage(maxBytes));
    }

    const dir = join(store.caseDir(caseId), UPLOAD_SPOOL_DIR);
    const path = join(dir, `${randomUUID()}.part`);
    let spooled: SpooledUpload;
    try {
      await store.mkdirInCase(dir);
      spooled = await spoolUpload(req, path, maxBytes, (p) =>
        store.withCaseWrite(p, () => open(p, "wx", 0o600)),
      );
    } catch (err) {
      await rmdir(dir).catch(() => undefined); // only when empty: a concurrent upload keeps it
      if (err instanceof UploadAbortedError) return undefined; // nobody is left to answer
      if (err instanceof UploadTooLargeError) return refuse(res, 413, uploadTooLargeMessage(maxBytes));
      ctx.serverLogger.info(`[import-upload] ${caseId}: spool failed — ${(err as Error).message}`);
      return refuse(res, 500, `the upload could not be written to disk: ${(err as Error).message}`);
    }
    // The whole body is read: an answer from here on may keep the connection (#2353 — the first
    // layer set `Connection: close` so that refusals before the read hang up).
    res.removeHeader("Connection");
    try {
      return await importSpooled(ctx, req, res, caseId, opts, spooled);
    } finally {
      await rm(path, { force: true }).catch(() => undefined);
      await rmdir(dir).catch(() => undefined);
    }
  });
}

async function importSpooled(
  ctx: RouteContext,
  req: Request,
  res: Response,
  caseId: string,
  opts: { filename: string; body: Record<string, unknown> },
  spooled: SpooledUpload,
): Promise<unknown> {
  const { store, options } = ctx;
  if (spooled.bytes === 0) return res.status(400).json({ error: "file is empty" });
  const custody = options.custodyStore;
  if (custody) {
    try {
      const got = { sha256: spooled.sha256, sha1: spooled.sha1, bytes: spooled.bytes, name: opts.filename };
      await recordReceived(custody, caseId, IMPORT_UPLOAD_ROUTE, got);
    } catch (err) {
      return res.status(500).json({
        error: `custody receipt could not be recorded, so the import was refused: ${(err as Error).message}`,
      });
    }
  }
  // buildImportBase and the job parameters read the import options from the body (importBase.ts).
  req.body = opts.body;
  const handle = await open(spooled.path, "r");
  try {
    return await importFromHandle(ctx, req, res, {
      caseId,
      handle,
      originalName: opts.filename,
      minSeverity: parseMinSeverity(opts.body.minSeverity),
      via: "uploaded",
      // The copy must hash what was receipted: the spool is ours, but it sits in a shared folder.
      save: async (storedName) => {
        try {
          return await store.saveImportFromHandle(caseId, storedName, handle, undefined, spooled.sha256);
        } catch (err) {
          if (!(err instanceof CopyContentChangedError)) throw err;
          res.status(409).json({ error: CHANGED_WHILE_IMPORTING });
          return null;
        }
      },
    });
  } finally {
    await handle.close().catch(() => undefined);
  }
}
