import type { NextFunction, Request, RequestHandler, Response } from "express";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

// The case-lock gate (analysis/caseLockGate.ts) covers every /cases/:id/* route by prefix. A route
// that names its case in the request body (or `?caseId=`) is outside that prefix, so it gets this
// per-route check instead: same cookie, same verifier (ctx.readUnlockState), same 401 body.
//
// A request that names no case, or a malformed id, passes through — the route itself answers those
// (default set / 400). A case that does not exist passes through too, for the route's own 404.
// A case.json that cannot be read fails CLOSED, like the gate.

function namedCaseId(req: Request): string {
  const raw = req.body?.caseId ?? req.query?.caseId;
  return typeof raw === "string" ? raw.trim() : "";
}

export function requireBodyCaseUnlocked(ctx: RouteContext): RequestHandler {
  return async function bodyCaseLock(req: Request, res: Response, next: NextFunction): Promise<void> {
    const caseId = namedCaseId(req);
    if (!caseId || !isValidCaseId(caseId)) {
      next();
      return;
    }
    let salt: string | undefined;
    try {
      salt = (await ctx.store.getCaseMeta(caseId))?.password?.salt;
    } catch {
      res.status(401).json({ error: "locked", caseId });
      return;
    }
    if (!salt || ctx.readUnlockState(req, caseId, salt).unlocked) {
      next();
      return;
    }
    res.status(401).json({ error: "locked", caseId });
  };
}
