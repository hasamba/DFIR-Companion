import type { Express, Request, Response } from "express";
import { getImportLimiter, getImportIpLimiter } from "../http/rateLimiter.js";
import { importEncryptedCase, CaseImportConflictError } from "../analysis/caseExportArchive.js";
import { DecryptionError } from "../analysis/caseEncryption.js";
import { sanitizeCaseMeta } from "../analysis/casePassword.js";
import { hashFile } from "../analysis/custody.js";
import type { RouteContext } from "./context.js";

/**
 * Encrypted whole-case import — POST /cases/import/encrypted.
 *
 * Split out of routes/caseLifecycle.ts when the request budget below was added (#424): that file
 * is at its size-ledger cap, and this route's rate limiting is intricate enough to be worth
 * reading in one piece.
 */
export function registerEncryptedImportRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  // Import a `.dfircase` encrypted archive into a NEW case (replaces issue #56's snapshot
  // import). Body: { data: base64, password, targetCaseId? } — base64-in-JSON, matching this
  // codebase's existing convention for binary uploads elsewhere (no multipart/multer). 409 if the
  // target id already exists (the dashboard re-prompts with a new id), 400 on a wrong password,
  // corrupt archive, or malformed payload.
  //
  // Rate-limited like /unlock, and for a sharper reason: opening an archive costs a deliberate
  // ~1s scrypt derivation (caseEncryption.ts). Since #862 that derivation runs on libuv's
  // threadpool rather than on the event loop, so a caller looping wrong-password imports no longer
  // wedges the whole server outright — but the pool is four threads by default and is shared with
  // every other user of it (file I/O, zlib, every OTHER derivation), so filling it still stalls
  // unrelated work server-wide for as long as the caller cares to. That pool is the resource these
  // limits protect. The origin guard doesn't stop it (a caller with no Origin header is allowed by
  // design, see http/originGuard.ts) and in container mode the port is on the network. Keyed by
  // client IP because an import names no case until it has been decrypted; the key is coarse
  // behind a reverse proxy that doesn't strip its own address, where every caller shares one
  // bucket. That's the deliberate trade: a shared 30s import lockout is a far smaller failure than
  // a threadpool no other request can get onto, and refusing to trust a spoofable X-Forwarded-For
  // is worth more than a per-caller bucket.
  app.post("/cases/import/encrypted", async (req: Request, res: Response) => {
    const limiter = getImportLimiter();
    const limiterKey = req.ip ?? "unknown";
    try {
      const remaining = limiter.remainingLockout(limiterKey);
      if (remaining > 0) {
        res.setHeader("Retry-After", String(Math.ceil(remaining / 1000)));
        return res
          .status(429)
          .json({ error: "too many failed imports, try again later", retryAfterMs: remaining });
      }
      const body = (req.body ?? {}) as Record<string, unknown>;
      const { data, password, targetCaseId } = body;
      if (typeof data !== "string" || !data.trim()) {
        return res.status(400).json({ error: "data (base64) is required" });
      }
      if (typeof password !== "string" || !password) {
        return res.status(400).json({ error: "password is required" });
      }
      // Everything past here reaches decryptBuffer, whose scrypt derivation holds a threadpool
      // thread for about a second. The failure limiter above cannot bound that on its own: it
      // counts only outcomes the catch classifies as failures, and deliberately never counts a
      // conflict. This budget is charged per REQUEST, so no outcome — conflict, malformed archive,
      // or success — is an unmetered way to buy another derivation (#424).
      //
      // It is also why the failure limiter above may keep its three-step shape (check the lockout,
      // decrypt, count in the catch) now that the derivation is async. /unlock and
      // /auth/local/login had to move to AttemptLimiter.attemptFor when theirs did (#866, #872),
      // because there the per-key failure budget was the ONLY bound and a burst slipped past the
      // check before anything was counted. Here it is not: this per-request window is charged
      // BEFORE the derivation rather than after it, so a burst is capped at 10/min per IP whatever
      // order the failures land in. The serialized form would not fit anyway — it counts every
      // non-success, and a conflict must stay uncounted (#424).
      if (!getImportIpLimiter().tryAcquire(limiterKey)) {
        res.setHeader("Retry-After", "60");
        return res.status(429).json({ error: "too many import attempts, try again later" });
      }
      const fileBuffer = Buffer.from(data, "base64");
      const { meta, counts, formatVersion, currentFormatVersion, provenance } = await importEncryptedCase(
        store,
        fileBuffer,
        password,
        {
          targetCaseId:
            typeof targetCaseId === "string" && targetCaseId.trim() ? targetCaseId.trim() : undefined,
        },
      );
      options.teamAuth?.grantCreator(req, meta.caseId);
      await recordArrival(ctx, meta.caseId, provenance?.sourceCaseId);
      // An archived case.json is written back byte-for-byte on import (see
      // caseExportArchive.ts), so an exported case that had a case-lock password carries
      // its salt+hash into the archive. Sanitize before responding — never let it reach
      // the client, same as every other route that serializes a CaseMeta.
      limiter.clear(limiterKey);
      // Both versions ride in the response so the dashboard can say "this archive used an older,
      // weaker key derivation" without hardcoding which version is current — a client that
      // hardcoded "warn below 2" would silently stop warning about v2 the day a v3 lands (#672).
      // This is safe to return only because it is the SUCCESS path: the caller has already proven
      // it holds the password. Never answer "what version is this archive?" before a decrypt, or
      // an unauthenticated caller could sort a pile of archives by which are cheapest to crack.
      return res
        .status(201)
        .json({ ...sanitizeCaseMeta(meta), counts, formatVersion, currentFormatVersion, provenance });
    } catch (err) {
      // A conflict means the archive DID open — a real analyst re-importing, not an attacker
      // burning CPU. Deliberately not counted as a failure; the per-request budget above is what
      // stops a loop of them from being free.
      if (err instanceof CaseImportConflictError) {
        return res.status(409).json({ error: err.message, caseId: err.caseId });
      }
      // Every remaining failure got here by paying for the derivation, and they cost the same:
      // a wrong password (DecryptionError) and a correctly-encrypted archive whose ZIP is
      // malformed are one scrypt pass each. Only the first used to be counted, so encrypting
      // arbitrary bytes with a known password gave an unlimited supply of full derivations that
      // never touched the limiter (#424).
      const lockout = limiter.recordFailure(limiterKey);
      const msg = (err as Error).message;
      if (lockout > 0) {
        res.setHeader("Retry-After", String(Math.ceil(lockout / 1000)));
        return res.status(429).json({ error: "too many failed imports, locked out", retryAfterMs: lockout });
      }
      if (err instanceof DecryptionError) return res.status(400).json({ error: msg });
      if (
        /not a valid case archive|invalid target case id|not a ZIP archive|corrupt ZIP|zip entry|zip bomb/i.test(
          msg,
        )
      ) {
        return res.status(400).json({ error: msg });
      }
      return res.status(500).json({ error: msg });
    }
  });
}

/**
 * Record in the new case's custody chain that it ARRIVED rather than being created here (#904).
 * `sourceCaseId` is the id the archive's manifest claimed, and is undefined for an archive written
 * before manifests — the arrival is still worth recording without it.
 *
 * Deliberately never throws. It runs after the atomic rename that publishes the case, so the import
 * has already succeeded by the time it is called; letting a custody append failure escape would turn
 * a completed import into a 500 and tell the analyst their case did not import when it did. The
 * failure is logged instead, which is what a missing chain entry needs — someone to notice it.
 */
async function recordArrival(ctx: RouteContext, caseId: string, sourceCaseId?: string): Promise<void> {
  const custody = ctx.options.custodyStore;
  if (!custody) return;
  try {
    // case.json is the artifact: it exists for every imported case, it lives inside the case
    // directory (so the record stores a relative path and survives archiving), and it is the case
    // identity the package delivered.
    const artifactPath = ctx.store.caseMetaPath(caseId);
    await custody.record(caseId, {
      artifactPath,
      sha256: await hashFile(artifactPath),
      caseId,
      event: "transferred",
      collectedBy: "import",
      collectedAt: new Date().toISOString(),
      // `source` is the chain's free-text "where". Beside a "transferred" event it reads as where
      // the evidence came from — see CustodyStore.recordTransfer for the same field read the other way.
      source: sourceCaseId ? `.dfircase archive of case ${sourceCaseId}` : ".dfircase archive",
      trigger: "encrypted-case-import",
    });
  } catch (err) {
    ctx.serverLogger.warn(
      `imported case ${caseId} published but its custody arrival record could not be written: ` +
        (err as Error).message,
      { caseId },
    );
  }
}
