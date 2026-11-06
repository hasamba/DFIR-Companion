/**
 * Who may use, edit and attach a cloud account (#2308). One place, so the collect routes (#2311 and
 * the provider issues after it) ask the same question the account routes do.
 *
 * The rules, in team mode:
 *   - An account is attached to the cases that may use it. A writer of any attached case may list,
 *     read and use it FROM THAT CASE. From any other case it does not exist (404, never 403 — a 403
 *     would confirm the id to someone with no right to know it).
 *   - Editing or deleting it changes every attached case's credential, so it needs write on EVERY
 *     attached case.
 *   - Attaching it to another case needs write on both.
 *   - An instance administrator holds write on every case, so every rule passes for them.
 * In single-user mode there is no one to keep out, but the attachment still scopes: an account of
 * case A is never listed or used under case B.
 *
 * Every refusal names no case the caller cannot write, and no response or audit entry carries a
 * secret: audit details are the account name and provider only.
 */
import type { Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import type { CloudAccountVault } from "../integrations/cloudAccounts/cloudAccountVault.js";
import { CloudVaultError, cloudSafeError } from "../integrations/cloudAccounts/errors.js";
import type { CloudAccountView, OpenCloudAccount } from "../integrations/cloudAccounts/types.js";
import type { RouteContext } from "./context.js";

export const CLOUD_NOT_FOUND = "Cloud account not found.";
const UNAVAILABLE = "Cloud accounts are not available.";
const DEMO_REFUSAL = "Demo mode: cloud accounts and cloud collection are disabled on the public demo.";

/** What the team-mode audit log records for a cloud account (#2308). */
export type CloudAuditAction =
  | "cloud-account-created"
  | "cloud-account-updated"
  | "cloud-account-deleted"
  | "cloud-account-attached"
  | "cloud-account-detached"
  | "cloud-account-collect"
  | "cloud-vault-reset";

type Who = { id: string; name: string; provider?: string };

export type CloudAccess<T> = { ok: true; value: T } | { ok: false; status: number; error: string };

/** Records a cloud account action in the auth audit log (team mode) and the server log. */
export function cloudAudit(
  ctx: RouteContext,
  req: Request,
  action: CloudAuditAction,
  who: Who,
  caseId?: string,
): void {
  const auth = requestAuthentication(req);
  const detail = who.provider ? `${who.name} (${who.provider})` : who.name;
  if (auth) ctx.options.teamAuth?.store.addAudit(auth.identity, action, who.id, caseId, detail);
  const provider = who.provider ? ` provider=${who.provider}` : "";
  const inCase = caseId ? ` case=${JSON.stringify(caseId)}` : "";
  ctx.serverLogger.info(
    `[cloud-accounts] ${action} id=${who.id} name=${JSON.stringify(who.name)}${provider}${inCase}`,
  );
}

/** True when the caller may write `caseId`. Single-user mode has no one to keep out. */
export function canWriteCloudCase(ctx: RouteContext, req: Request, caseId: string): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true;
  const auth = requestAuthentication(req);
  return auth !== undefined && teamAuth.canAccessCase(auth, caseId, "write");
}

/** The account as seen from `caseId`: found only when attached to it, and only for its writers. */
export function cloudAccountInCase(
  ctx: RouteContext,
  req: Request,
  vault: CloudAccountVault,
  caseId: string,
  accountId: string,
): CloudAccess<CloudAccountView> {
  if (!canWriteCloudCase(ctx, req, caseId)) return { ok: false, status: 404, error: CLOUD_NOT_FOUND };
  let account: CloudAccountView;
  try {
    account = vault.view(accountId);
  } catch (err) {
    if (err instanceof CloudVaultError && err.code === "not-found")
      return { ok: false, status: 404, error: CLOUD_NOT_FOUND };
    throw err;
  }
  if (!account.caseIds.includes(caseId)) return { ok: false, status: 404, error: CLOUD_NOT_FOUND };
  return { ok: true, value: account };
}

/**
 * The account, when the caller may edit or delete it: attached to `caseId` AND writable in every
 * attached case. A credential shared with a case the caller cannot write is refused with 403.
 */
export function cloudAccountEditable(
  ctx: RouteContext,
  req: Request,
  vault: CloudAccountVault,
  caseId: string,
  accountId: string,
): CloudAccess<CloudAccountView> {
  const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
  if (!found.ok) return found;
  const blocked = found.value.caseIds.filter((c) => !canWriteCloudCase(ctx, req, c)).length;
  if (blocked === 0) return found;
  const cases = blocked === 1 ? "1 other case" : `${blocked} other cases`;
  return {
    ok: false,
    status: 403,
    error:
      `This credential is shared with ${cases} you cannot write. Editing or deleting it needs write ` +
      "access to every case it is attached to — detach it from this case instead, or ask an instance administrator.",
  };
}

/**
 * Opens an account's secrets for collection in `caseId`, and records the collect in the audit log.
 * The single entry point the collect routes use: attached to the case, caller can write the case.
 */
export function openCloudAccountForCollect(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  accountId: string,
): CloudAccess<OpenCloudAccount> {
  const vault = ctx.options.cloudAccountVault;
  if (!vault) return { ok: false, status: 503, error: UNAVAILABLE };
  if (ctx.options.demoMode) return { ok: false, status: 403, error: DEMO_REFUSAL };
  const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
  if (!found.ok) return found;
  const account = vault.open(accountId);
  cloudAudit(ctx, req, "cloud-account-collect", account, caseId);
  return { ok: true, value: account };
}

// A vault refusal is the caller's to fix (400/404/409/423); anything else is a server fault.
function vaultError(ctx: RouteContext, req: Request, res: Response, err: unknown): Response {
  if (err instanceof CloudVaultError) {
    if (err.code === "not-found") return res.status(404).json({ error: CLOUD_NOT_FOUND });
    if (err.code === "locked") return res.status(423).json({ error: err.message, locked: true });
    if (err.code === "conflict") return res.status(409).json({ error: err.message });
    return res.status(400).json({ error: err.message });
  }
  ctx.serverLogger.error(`[cloud-accounts] ${req.method} ${req.path}: ${cloudSafeError(err)}`);
  return res.status(500).json({ error: "Cloud accounts cannot be saved. Check the server log." });
}

/**
 * Wraps a cloud account route: 403 on the public demo (GET included — the demo gate in
 * composition/httpStack.ts refuses first; this is the second line), 503 with no vault, and vault
 * errors turned into safe answers.
 */
export function withCloudVault(
  ctx: RouteContext,
  handler: (vault: CloudAccountVault, req: Request, res: Response) => unknown,
) {
  return async (req: Request, res: Response) => {
    if (ctx.options.demoMode) return res.status(403).json({ error: DEMO_REFUSAL, demo: true });
    const vault = ctx.options.cloudAccountVault;
    if (!vault) return res.status(503).json({ error: UNAVAILABLE });
    try {
      return await handler(vault, req, res);
    } catch (err) {
      return vaultError(ctx, req, res, err);
    }
  };
}

/** Sends a refusal from one of the access checks above. */
export function sendCloudRefusal(res: Response, refusal: { status: number; error: string }): Response {
  return res.status(refusal.status).json({ error: refusal.error });
}
