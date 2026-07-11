import type { Express, Request, Response, CookieOptions } from "express";
import { isValidCaseId } from "../storage/caseStore.js";
import {
  hashCasePassword,
  verifyCasePassword,
  sanitizeCaseMeta,
  signUnlockToken,
  unlockCookieName,
  MIN_CASE_PASSWORD_LENGTH,
} from "../analysis/casePassword.js";
import type { RouteContext } from "./context.js";

// Cookie TTLs for a case-unlock token. Moved verbatim from createApp (they were used only by the
// unlock route below): a "remember on this computer" unlock is long-lived; a plain unlock rides a
// session cookie with a 12h backstop. The case-lock GATE (createCaseLockGate, still mounted in
// server.ts) and readUnlockState (ctx) verify these tokens; they don't need these TTLs.
const UNLOCK_TTL_REMEMBER_MS = 365 * 24 * 60 * 60 * 1000; // ~1 year — "remember on this computer"
const UNLOCK_TTL_SESSION_MS = 12 * 60 * 60 * 1000;        // 12h backstop for a browser-session cookie

/**
 * Case-password protection domain: set / change / clear a case password, unlock a case (issuing the
 * signed unlock cookie), explicitly forget this browser's unlock, and report lock status. Pure
 * structural move out of createApp (see routes/system.ts for the conventions) — no handler logic
 * changed.
 *
 * BOUNDARY: the case-lock GATE middleware (app.use("/cases/:id", createCaseLockGate(...))) STAYS in
 * server.ts — it's middleware, not a route, and it must be mounted before every /cases/:id route.
 * This module only owns the password/unlock/lock ROUTES.
 *
 * Shared surface:
 *   - store — stable ctx field.
 *   - instanceSecret — GRADUATED to ctx (a stable readonly value): the HMAC secret that signs/verifies
 *     unlock cookies. The staying case-lock gate + ctx.readUnlockState both use the SAME secret, so it
 *     was graduated (not moved) rather than recomputed here; the unlock route signs a fresh token with it.
 *   - readUnlockState — already-graduated stable helper: reports whether this request already carries a
 *     valid unlock for a case (and whether it was "remember"-signed), used by the lock-status route.
 */
export function registerCasePasswordRoutes(app: Express, ctx: RouteContext): void {
  const { store, instanceSecret, readUnlockState } = ctx;

  app.get("/cases/:id/lock-status", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const meta = await store.getCaseMeta(id);
      if (!meta) return res.status(404).json({ error: `case ${id} not found` });
      const hasPassword = Boolean(meta.password);
      if (!hasPassword) return res.status(200).json({ hasPassword: false, unlocked: true, remembered: false });
      const state = readUnlockState(req, id, meta.password!.salt);
      return res.status(200).json({ hasPassword: true, ...state });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/unlock", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const meta = await store.getCaseMeta(id);
      if (!meta) return res.status(404).json({ error: `case ${id} not found` });
      if (!meta.password) return res.status(200).json({ ok: true }); // nothing to unlock
      const password = (req.body as { password?: unknown })?.password;
      const remember = (req.body as { remember?: unknown })?.remember === true;
      if (typeof password !== "string" || !verifyCasePassword(password, meta.password)) {
        return res.status(401).json({ error: "incorrect password" });
      }
      const ttl = remember ? UNLOCK_TTL_REMEMBER_MS : UNLOCK_TTL_SESSION_MS;
      const token = signUnlockToken(id, meta.password.salt, instanceSecret, ttl, remember);
      const cookieOpts: CookieOptions = { httpOnly: true, sameSite: "strict", path: "/" };
      if (remember) cookieOpts.maxAge = ttl;
      res.cookie(unlockCookieName(id), token, cookieOpts);
      return res.status(200).json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/password", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      if (!(await store.caseExists(id))) return res.status(404).json({ error: `case ${id} not found` });
      const newPassword = (req.body as { newPassword?: unknown })?.newPassword;
      if (typeof newPassword !== "string" || newPassword.length < MIN_CASE_PASSWORD_LENGTH) {
        return res.status(400).json({ error: `password must be at least ${MIN_CASE_PASSWORD_LENGTH} characters` });
      }
      const password = hashCasePassword(newPassword);
      const updated = await store.updateCaseMeta(id, { password });
      // Deliberately does NOT auto-unlock the browser that just set/changed it: setting a
      // password (or changing one, which rotates the salt and invalidates the caller's own
      // existing cookie) should require going through the real unlock prompt afterward, same
      // as anyone else — matching the analyst's expectation that setting a password protects
      // the case immediately, not just for other people.
      return res.status(200).json(sanitizeCaseMeta(updated));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/password", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      if (!(await store.caseExists(id))) return res.status(404).json({ error: `case ${id} not found` });
      const updated = await store.updateCaseMeta(id, { password: undefined });
      res.clearCookie(unlockCookieName(id), { path: "/" });
      return res.status(200).json(sanitizeCaseMeta(updated));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Explicitly forget THIS browser's unlock for a case, without touching the password
  // itself. The dashboard calls this when navigating away from a case that was unlocked
  // without "remember on this computer" — a session cookie survives switching cases within
  // the same tab (only a real browser close clears it), so without this, a not-remembered
  // unlock would silently stay valid for the rest of the browser session. No case-existence
  // check: clearing a cookie that may not exist for a case that may not exist is harmless
  // and always idempotent, and this route works even while the case is already locked.
  app.post("/cases/:id/lock", (req: Request, res: Response) => {
    res.clearCookie(unlockCookieName(req.params.id), { path: "/" });
    return res.status(200).json({ ok: true });
  });
}
