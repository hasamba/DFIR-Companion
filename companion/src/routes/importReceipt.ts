import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { Express, NextFunction, Request, Response } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { hashHandleBoth, RECEIVED_PATH_PREFIX, type CustodyStore } from "../analysis/custody.js";
import { EVIDENCE_IMPORT_ROUTES } from "./importCaseGuard.js";
import { openImportPath } from "./serverPathGuard.js";

// Custody at RECEIPT (#2111). Most import routes parse a preview first and store afterwards, so a
// file the importer rejects never reached the chain of custody at all. This runs ahead of every
// route's own parsing and records what arrived — name, size, SHA-256, SHA-1 — as a `received`
// entry. The bytes of a rejected file are NOT stored; the hashes let the analyst match their copy.
//
// If the entry cannot be written the request stops with a 500 and the parser never runs: an import
// with no receipt would quietly re-open the gap this exists to close.

/** The body fields the routes read their payload from, in the priority they use. */
const TEXT_FIELDS = ["text", "json", "csv", "eml", "log"] as const;
const MAX_NAME = 200;

interface Received {
  sha256: string;
  sha1: string;
  bytes: number;
  name: string;
}

const digest = (algo: "sha256" | "sha1", data: Buffer): string => createHash(algo).update(data).digest("hex");

/** A label for the file, never a path: basename, control characters and path separators removed. */
function receiptName(raw: unknown, fallback: string): string {
  const base = typeof raw === "string" ? basename(raw.replace(/\\/g, "/")) : "";
  const clean = base.replace(/[\x00-\x1f\x7f]/g, "").slice(0, MAX_NAME);
  return clean || fallback;
}

const receivedOf = (bytes: Buffer, name: string): Received => ({
  sha256: digest("sha256", bytes),
  sha1: digest("sha1", bytes),
  bytes: bytes.length,
  name,
});

/**
 * One receipt per distinct payload copy in the body. Routes disagree on whether `text` or `json`
 * wins, so hashing only the first present field could record a hash the stored artifact never has;
 * receipting every copy guarantees the one the route keeps is on the chain.
 */
function fromBody(body: Record<string, unknown>): Received[] {
  const name = receiptName(body.filename, "import.dat");
  // utf8 in, utf8 on disk: the same bytes saveImport writes, so each hash equals the stored one.
  const texts = TEXT_FIELDS.filter((f) => typeof body[f] === "string").map((f) =>
    receivedOf(Buffer.from(body[f] as string, "utf8"), name),
  );
  if (texts.length === 0 && typeof body.dataBase64 === "string" && body.dataBase64) {
    return [receivedOf(Buffer.from(body.dataBase64, "base64"), name)];
  }
  return texts.filter((r, i) => texts.findIndex((o) => o.sha256 === r.sha256) === i);
}

/** import-file / import-mac-login-item name a server file: hash the handle the path guard judged. */
async function fromServerPath(
  store: CaseStore,
  caseId: string,
  body: Record<string, unknown>,
): Promise<Received | null> {
  const filePath = typeof body.path === "string" ? body.path.trim() : "";
  if (!filePath) return null;
  try {
    const opened = await openImportPath(filePath, store, caseId);
    if (opened.refusal) return null; // the route reports the refusal; nothing was received
    try {
      const { size } = await opened.file.handle.stat();
      const hashes = await hashHandleBoth(opened.file.handle);
      return { ...hashes, bytes: size, name: receiptName(filePath, "import.dat") };
    } finally {
      await opened.file.handle.close();
    }
  } catch {
    return null; // unreadable: the route returns its own 400
  }
}

export function registerImportReceiptCustody(
  app: Express,
  store: CaseStore,
  custody: CustodyStore | undefined,
): void {
  if (!custody) return;
  const paths = EVIDENCE_IMPORT_ROUTES.map((route) => `/cases/:id/${route}`);
  app.post(paths, async (req: Request, res: Response, next: NextFunction) => {
    const caseId = req.params.id;
    const route = req.path.split("/").filter(Boolean).pop() ?? "import";
    const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
    try {
      const inBody = fromBody(body);
      const fromPath = inBody.length ? null : await fromServerPath(store, caseId, body);
      const receipts = fromPath ? [fromPath] : inBody;
      // Sequential, not parallel: each entry chains onto the previous one's hash.
      for (const got of receipts) {
        await custody.record(caseId, {
          artifactPath: `${RECEIVED_PATH_PREFIX}${route}/${got.name}@${got.sha256.slice(0, 12)}`,
          sha256: got.sha256,
          sha1: got.sha1,
          bytes: got.bytes,
          collectedBy: "companion",
          collectedAt: new Date().toISOString(),
          source: got.name,
          trigger: route,
          caseId,
          event: "received",
        });
      }
    } catch (err) {
      return res.status(500).json({
        error: `custody receipt could not be recorded, so the import was refused: ${(err as Error).message}`,
      });
    }
    return next();
  });
}
