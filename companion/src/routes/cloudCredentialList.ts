/**
 * The cloud accounts list (#2347): every credential the companion holds that the caller may see,
 * and deleting one or several of them. It extends the administrator's "All cloud accounts" list
 * (#2308) rather than adding a second one.
 *
 *   GET    /cloud-accounts               the accounts the caller may see, each with its cases and
 *                                        their status, who added it and when, and when it was last used
 *   POST   /cloud-accounts/delete        { ids: [...] } — delete several at once (all or none)
 *   DELETE /cloud-accounts/:accountId    delete one
 *
 * Visibility, in team mode: an analyst sees the accounts attached to a case they can write, with the
 * case list cut to those cases (plus how many others there are). An instance administrator sees every
 * account, unattached ones included; single-user mode is the same. Deleting needs write on EVERY
 * attached case (the #2308 rule for a shared credential); an unattached account is the
 * administrator's alone, and to anyone else it does not exist (404, never 403).
 *
 * Every delete writes the team audit log and a custody entry on each attached case
 * (cloudCredentialRelease.ts). No response carries a secret — the names of the stored secrets only.
 */
import type { Express, Request } from "express";
import type { CloudAccountVault } from "../integrations/cloudAccounts/cloudAccountVault.js";
import { CloudVaultError } from "../integrations/cloudAccounts/errors.js";
import type { CloudAccountView } from "../integrations/cloudAccounts/types.js";
import { MINIMUM_POLICIES } from "../integrations/cloudCheck/minimumPolicies.js";
import {
  CLOUD_NOT_FOUND,
  canWriteCloudCase,
  isCloudAdmin,
  sendCloudRefusal,
  withCloudVault,
  type CloudAccess,
} from "./cloudAccountAccess.js";
import { deleteCloudCredentials } from "./cloudCredentialRelease.js";
import type { RouteContext } from "./context.js";

/** At most this many accounts in one multi-delete. */
const MAX_DELETE = 200;

type CaseStatus = "open" | "closed" | "archived" | "missing";

function sharedRefusal(blocked: number): { ok: false; status: number; error: string } {
  const cases = blocked === 1 ? "1 case" : `${blocked} cases`;
  return {
    ok: false,
    status: 403,
    error:
      `A credential you picked is shared with ${cases} you cannot write. Deleting it needs write access ` +
      "to every case it is attached to — detach it from your case instead, or ask an instance administrator.",
  };
}

/** May the caller delete `account`? 404 when they may not even see it. */
export function cloudAccountDeletable(
  ctx: RouteContext,
  req: Request,
  account: CloudAccountView,
): CloudAccess<CloudAccountView> {
  if (isCloudAdmin(ctx, req)) return { ok: true, value: account };
  const writable = account.caseIds.filter((c) => canWriteCloudCase(ctx, req, c)).length;
  if (writable === 0) return { ok: false, status: 404, error: CLOUD_NOT_FOUND };
  const blocked = account.caseIds.length - writable;
  return blocked === 0 ? { ok: true, value: account } : sharedRefusal(blocked);
}

async function caseStatus(ctx: RouteContext, caseId: string): Promise<CaseStatus> {
  try {
    const meta = await ctx.store.getCaseMeta(caseId);
    if (!meta) return "missing";
    return meta.status ?? "open";
  } catch {
    return "missing";
  }
}

/** One row of the list: the cases cut to the ones the caller may name, each with its status. */
async function listRow(ctx: RouteContext, req: Request, account: CloudAccountView, admin: boolean) {
  const caseIds = admin ? account.caseIds : account.caseIds.filter((c) => canWriteCloudCase(ctx, req, c));
  const cases = await Promise.all(
    caseIds.map(async (caseId) => ({ caseId, status: await caseStatus(ctx, caseId) })),
  );
  return { ...account, caseIds, cases, otherCases: account.caseIds.length - caseIds.length };
}

/** Every account the caller may see: all of them for an administrator, else those of a writable case. */
function visibleAccounts(ctx: RouteContext, req: Request, vault: CloudAccountVault, admin: boolean) {
  const all = vault.list();
  return admin ? all : all.filter((a) => a.caseIds.some((c) => canWriteCloudCase(ctx, req, c)));
}

function parseIds(body: unknown): string[] | string {
  const ids = (body as { ids?: unknown } | undefined)?.ids;
  if (!Array.isArray(ids) || ids.length === 0) return "ids lists the cloud accounts to delete.";
  if (ids.length > MAX_DELETE) return `Delete at most ${MAX_DELETE} accounts at once.`;
  if (!ids.every((id) => typeof id === "string" && /^[A-Za-z0-9_-]{1,80}$/.test(id)))
    return "ids holds an invalid account id.";
  return [...new Set(ids as string[])];
}

/** Checks every id first: one refusal deletes nothing. */
function authoriseAll(
  ctx: RouteContext,
  req: Request,
  vault: CloudAccountVault,
  ids: readonly string[],
): CloudAccess<string[]> {
  for (const id of ids) {
    let account: CloudAccountView;
    try {
      account = vault.view(id);
    } catch (err) {
      if (err instanceof CloudVaultError && err.code === "not-found")
        return { ok: false, status: 404, error: CLOUD_NOT_FOUND };
      throw err;
    }
    const allowed = cloudAccountDeletable(ctx, req, account);
    if (!allowed.ok) return allowed;
  }
  return { ok: true, value: [...ids] };
}

export function registerCloudCredentialListRoutes(app: Express, ctx: RouteContext): void {
  app.get(
    "/cloud-accounts",
    withCloudVault(ctx, async (vault, req, res) => {
      const admin = isCloudAdmin(ctx, req);
      const { keyPath, keyState } = vault.status();
      const rows = visibleAccounts(ctx, req, vault, admin);
      const accounts = await Promise.all(rows.map((a) => listRow(ctx, req, a, admin)));
      // The key file's path is the administrator's business; an analyst sees only its state.
      const key = admin ? { keyPath, keyState } : { keyState };
      return res.json({ ...key, admin, accounts, minimumPolicies: MINIMUM_POLICIES });
    }),
  );

  // Registered before the :accountId routes, so "delete" is never read as an account id.
  app.post(
    "/cloud-accounts/delete",
    withCloudVault(ctx, async (vault, req, res) => {
      const ids = parseIds(req.body);
      if (typeof ids === "string") return res.status(400).json({ error: ids });
      const allowed = authoriseAll(ctx, req, vault, ids);
      if (!allowed.ok) return sendCloudRefusal(res, allowed);
      const gone = await deleteCloudCredentials(ctx, req, allowed.value);
      return res.json({ deleted: gone.length });
    }),
  );

  app.delete(
    "/cloud-accounts/:accountId",
    withCloudVault(ctx, async (vault, req, res) => {
      const allowed = authoriseAll(ctx, req, vault, [req.params.accountId]);
      if (!allowed.ok) return sendCloudRefusal(res, allowed);
      await deleteCloudCredentials(ctx, req, allowed.value);
      return res.status(204).end();
    }),
  );
}
