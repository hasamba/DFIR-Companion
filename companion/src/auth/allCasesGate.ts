/**
 * The extra per-request checks an "all my cases" service token passes through (#2474), in front of
 * the ordinary authorization in TeamAuth.
 *
 * 1. CASE STATE. Closing or archiving a case stops the token for that case on every route — reads
 *    and the notes a session may still edit on a closed case included. The ordinary write guards
 *    leave those open by product decision for people; a bearer credential gets the narrower rule.
 *    The answer comes from `caseLifecycleOf`, injected by composition/httpStack.ts; without it the
 *    token reaches no case (fail closed).
 * 2. CASE LIST. GET /cases (and the cross-case IOC pivot) is filtered through `visibleCaseIds`. For
 *    an all-cases token that set is computed here — the owner's write-capable cases that are open —
 *    and handed to the route through a per-request WeakMap, because the route's filter is
 *    synchronous and the case state is not.
 * 3. AUDIT. Every request that names a case is recorded with the token, the case and the outcome
 *    (status code), written when the response closes so refusals are recorded as well as
 *    successes. A list request acts on no case and is recorded only when it is refused, so the
 *    extension's picker refreshes do not drown the audit.
 */
import type { Request, Response } from "express";
import type { AuthStore } from "./authStore.js";
import { caseRoleAllows, type RequestPolicy } from "./policy.js";
import type { AuthIdentity, RequestAuthentication, ServiceTokenRecord } from "./types.js";

export type CaseLifecycle = "open" | "closed" | "archived" | "missing";

export interface TeamAuthMiddlewareOptions {
  /** The state of a case; "missing" for an unknown or invalid id. */
  caseLifecycleOf?: (caseId: string) => Promise<CaseLifecycle>;
}

export type AllCasesAuthentication = {
  kind: "service-token";
  identity: AuthIdentity;
  token: ServiceTokenRecord & { scope: "all-cases" };
};

/** What GET /cases may show an all-cases token on THIS request; set by allCasesGate. */
export const allCasesVisible = new WeakMap<Request, Set<string>>();

export function isAllCasesToken(
  auth: RequestAuthentication | null | undefined,
): auth is AllCasesAuthentication {
  return auth?.kind === "service-token" && auth.token.scope === "all-cases";
}

interface OwnerReach {
  allCasesTokenReaches(auth: RequestAuthentication, caseId: string): boolean;
  readonly store: AuthStore;
}

function policyCaseId(policy: RequestPolicy, req: Request): string {
  if (policy.kind === "case") return policy.caseId;
  if (policy.kind === "capture") return typeof req.body?.caseId === "string" ? req.body.caseId.trim() : "";
  return "";
}

async function lifecycleOrMissing(
  lookup: TeamAuthMiddlewareOptions["caseLifecycleOf"],
  caseId: string,
): Promise<CaseLifecycle> {
  if (!lookup) return "missing";
  try {
    return await lookup(caseId);
  } catch {
    return "missing"; // an unreadable case.json refuses the token; it never lets it through
  }
}

async function openWritableCases(
  auth: AllCasesAuthentication,
  store: AuthStore,
  lookup: TeamAuthMiddlewareOptions["caseLifecycleOf"],
): Promise<Set<string>> {
  const roles = store.rolesForIdentity(auth.token.ownerIdentityId ?? "");
  const owned = Object.keys(roles).filter((caseId) => caseRoleAllows(roles[caseId], "write"));
  const states = await Promise.all(owned.map((caseId) => lifecycleOrMissing(lookup, caseId)));
  return new Set(owned.filter((_, index) => states[index] === "open"));
}

/**
 * Resolves true when the request may continue to the ordinary authorization, false once it has
 * already been answered. A case the owner cannot reach is left to that authorization, which answers
 * 404 without revealing whether the case is open, closed, or exists at all.
 */
export async function allCasesGate(
  reach: OwnerReach,
  auth: AllCasesAuthentication,
  policy: RequestPolicy,
  req: Request,
  res: Response,
  lookup: TeamAuthMiddlewareOptions["caseLifecycleOf"],
): Promise<boolean> {
  if (policy.kind === "case-list") {
    allCasesVisible.set(req, await openWritableCases(auth, reach.store, lookup));
    return true;
  }
  if (policy.kind !== "case" && policy.kind !== "capture") return true;
  const caseId = policyCaseId(policy, req);
  if (!caseId || !reach.allCasesTokenReaches(auth, caseId)) return true;
  const state = await lifecycleOrMissing(lookup, caseId);
  if (state === "open") return true;
  if (state === "closed" || state === "archived") {
    res.status(423).json({
      error: `case ${caseId} is ${state} — an all-cases token cannot reach a ${state} case`,
    });
    return false;
  }
  res.status(404).json({ error: "case not found or access denied" });
  return false;
}

/** Records the request once its response has closed, with the real outcome. Never throws. */
export function auditAllCasesRequest(
  store: AuthStore,
  auth: AllCasesAuthentication,
  policy: RequestPolicy,
  req: Request,
  res: Response,
): void {
  const method = req.method;
  const path = req.path;
  res.once("close", () => {
    const caseId = policyCaseId(policy, req);
    const status = res.writableFinished ? String(res.statusCode) : "aborted";
    if (!caseId && res.writableFinished && res.statusCode < 400) return;
    try {
      store.addAudit(
        auth.identity,
        "service-token-request",
        auth.token.id,
        caseId || undefined,
        `${method} ${path} status=${status} owner=${auth.token.ownerIdentityId ?? ""}`,
      );
    } catch (err) {
      // The response has already gone; surface the lost row on the process warning channel.
      process.emitWarning(`service-token audit row not written: ${(err as Error).message}`);
    }
  });
}
