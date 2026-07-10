import type { Request, Response, NextFunction } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { unlockCookieName, verifyUnlockToken, parseCookieHeader } from "./casePassword.js";

// Routes that must stay reachable on a locked case:
//  - lock-status / unlock / lock: how a client checks/clears/re-locks in the first place.
//    "lock" specifically must work even when ALREADY locked, so the dashboard can forget a
//    non-remembered unlock on page unload without racing the gate.
//  - import: the capture extension's evidence-ingestion route. A background capture
//    session should keep recording evidence even while the dashboard is locked — it's
//    write-only and never exposes case content back to the caller.
const EXEMPT_SUFFIXES = ["/lock-status", "/unlock", "/lock", "/import"];

function pathOnly(url: string): string {
  const q = url.indexOf("?");
  return q === -1 ? url : url.slice(0, q);
}

function lockPromptHtml(caseId: string): string {
  const safeCaseId = encodeURIComponent(caseId);
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Case locked</title></head>
<body style="font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;text-align:center;">
<h2>&#128274; This case is password-protected</h2>
<p>Open <a href="/dashboard?caseId=${safeCaseId}">the dashboard</a> and enter the password to view it.</p>
</body></html>`;
}

/** Gates every `/cases/:id/*` route behind that case's password, when one is set. Mount
 * once via `app.use('/cases/:id', createCaseLockGate(store, secret))`, as early as possible
 * (before ANY `/cases/:id/*` route is registered) — Express's prefix matching means it
 * covers every route registered after it, current or future, with no per-route changes.
 * See docs/superpowers/specs/2026-07-09-case-password-protection-design.md. */
export function createCaseLockGate(store: CaseStore, secret: Buffer) {
  return async function caseLockGate(req: Request, res: Response, next: NextFunction): Promise<void> {
    const caseId = req.params.id;
    const path = pathOnly(req.originalUrl); // full path, independent of Express mount-stripping
    if (EXEMPT_SUFFIXES.some((suffix) => path === `/cases/${caseId}${suffix}`)) {
      next();
      return;
    }

    let meta;
    try {
      meta = await store.getCaseMeta(caseId);
    } catch {
      // getCaseMeta failed unexpectedly (not "case doesn't exist" — that resolves to null,
      // not a throw). Fail CLOSED rather than silently letting a locked case through: this
      // gate's entire job is to block, so an internal error must not default to open.
      res.status(401).json({ error: "locked", caseId });
      return;
    }
    if (!meta?.password) {
      // Case genuinely doesn't exist, or exists with no password set — let it through.
      // A missing case is a 404 for the downstream route to report, not this gate's concern.
      next();
      return;
    }

    const cookies = parseCookieHeader(req.headers.cookie);
    const token = cookies[unlockCookieName(caseId)];
    if (token && verifyUnlockToken(token, caseId, meta.password.salt, secret)) {
      next();
      return;
    }

    if (path === `/cases/${caseId}/present`) {
      res.status(401).type("html").send(lockPromptHtml(caseId));
      return;
    }
    res.status(401).json({ error: "locked", caseId });
  };
}
