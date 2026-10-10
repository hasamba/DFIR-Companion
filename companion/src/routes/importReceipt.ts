import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { Express, NextFunction, Request, Response } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { hashHandleBoth, RECEIVED_PATH_PREFIX, type CustodyStore } from "../analysis/custody.js";
import { EVIDENCE_IMPORT_ROUTES } from "./importCaseGuard.js";
import { openImportPath, type GuardedFile } from "./serverPathGuard.js";
import { setReceiptedFile, type ReceiptedFile } from "./receiptedFile.js";

// Custody at RECEIPT (#2111). Most import routes parse a preview first and store afterwards, so a
// file the importer rejects never reached the chain of custody at all. This runs ahead of every
// route's own parsing and records what arrived — name, size, SHA-256, SHA-1 — as a `received`
// entry. The bytes of a rejected file are NOT stored; the hashes let the analyst match their copy.
//
// If the entry cannot be written the request stops with a 500 and the parser never runs: an import
// with no receipt would quietly re-open the gap this exists to close.

/** The body fields the routes read their payload from, in the priority they use. */
const TEXT_FIELDS = ["text", "json", "csv", "eml", "log"] as const;
/** The two routes that import a file the server names by `path`; only they get a handle handed over. */
const SERVER_PATH_ROUTES: readonly string[] = ["import-file", "import-mac-login-item"];
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
 * One receipt per payload copy in the body: each text field and the decoded dataBase64. Routes
 * disagree on which copy they keep (import-thor reads `json` before `text`, import-binary stores
 * the decoded bytes), so receipting only one could record a hash the stored artifact never has;
 * receipting every copy guarantees the one the route keeps is on the chain.
 */
function fromBody(body: Record<string, unknown>): Received[] {
  const name = receiptName(body.filename, "import.dat");
  // utf8 in, utf8 on disk: the same bytes saveImport writes, so each hash equals the stored one.
  const copies = TEXT_FIELDS.filter((f) => typeof body[f] === "string").map((f) =>
    Buffer.from(body[f] as string, "utf8"),
  );
  if (typeof body.dataBase64 === "string" && body.dataBase64) {
    copies.push(Buffer.from(body.dataBase64, "base64"));
  }
  return copies.map((bytes) => receivedOf(bytes, name));
}

interface OpenedServerFile {
  received: Received;
  receipted: ReceiptedFile;
}

/**
 * import-file / import-mac-login-item name a server file: hash the handle the path guard judged and
 * KEEP it open for the route, so the bytes receipted are the bytes imported (#2111). The caller owns
 * the handle from here and must close it.
 */
async function openServerFile(
  store: CaseStore,
  caseId: string,
  body: Record<string, unknown>,
): Promise<OpenedServerFile | null> {
  const filePath = typeof body.path === "string" ? body.path.trim() : "";
  if (!filePath) return null;
  let file: GuardedFile | null = null;
  try {
    const opened = await openImportPath(filePath, store, caseId);
    if (opened.refusal) return null; // the route reports the refusal; nothing was received
    file = opened.file;
    const { size } = await file.handle.stat();
    const hashes = await hashHandleBoth(file.handle);
    const received = { ...hashes, bytes: size, name: receiptName(filePath, "import.dat") };
    return { received, receipted: { path: filePath, file, sha256: hashes.sha256 } };
  } catch {
    await file?.handle.close().catch(() => undefined);
    return null; // unreadable: the route returns its own 400
  }
}

const uniqueBySha = (all: Received[]): Received[] =>
  all.filter((r, i) => all.findIndex((o) => o.sha256 === r.sha256) === i);

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
      const server = SERVER_PATH_ROUTES.includes(route) ? await openServerFile(store, caseId, body) : null;
      if (server) {
        // Closed exactly once, when the response does: whether the route used it, refused first, or
        // the request died before reaching it. The routes never close it themselves.
        res.once("close", () => void server.receipted.file.handle.close().catch(() => undefined));
        setReceiptedFile(res, server.receipted);
      }
      const receipts = uniqueBySha([...fromBody(body), ...(server ? [server.received] : [])]);
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
