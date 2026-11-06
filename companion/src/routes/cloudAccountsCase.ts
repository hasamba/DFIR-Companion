/**
 * A case's cloud accounts (#2308). Every route needs WRITE on the case, GET included
 * (auth/policy.ts), and checks the account's other cases through cloudAccountAccess.ts.
 *
 *   GET    /cases/:id/cloud-accounts                     the accounts attached to the case (no secrets)
 *   POST   /cases/:id/cloud-accounts                     add an account, attached to this case
 *   GET    /cases/:id/cloud-accounts/:accountId          one account (no secrets)
 *   PUT    /cases/:id/cloud-accounts/:accountId          edit — write on EVERY attached case
 *   DELETE /cases/:id/cloud-accounts/:accountId          delete — write on EVERY attached case
 *   POST   /cases/:id/cloud-accounts/:accountId/attach   { caseId } — share with another case you write
 *   POST   /cases/:id/cloud-accounts/:accountId/detach   remove from THIS case only; others keep it
 *
 * An account seen from a case it is not attached to does not exist (404). The case ids a response
 * lists are cut to the cases the caller can write, so a shared account names no case they cannot.
 */
import type { Express, Request } from "express";
import type { CloudAccountView } from "../integrations/cloudAccounts/types.js";
import { parseCloudAccountInput } from "../integrations/cloudAccounts/accountInput.js";
import {
  canWriteCloudCase,
  cloudAccountEditable,
  cloudAccountInCase,
  cloudAudit,
  sendCloudRefusal,
  withCloudVault,
} from "./cloudAccountAccess.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

const CASE_NOT_FOUND = "Case not found or access denied.";

// The cases a response may name: only those the caller can write, plus how many others there are.
function visibleView(ctx: RouteContext, req: Request, account: CloudAccountView) {
  const caseIds = account.caseIds.filter((c) => canWriteCloudCase(ctx, req, c));
  return { ...account, caseIds, otherCases: account.caseIds.length - caseIds.length };
}

function keyNotice(keyPath: string): string {
  return (
    `A new vault key was made at ${keyPath}. Back it up on its own and keep it OUT of ` +
    "data-folder backups: whoever holds both can read every cloud credential."
  );
}

function registerListAndAdd(app: Express, ctx: RouteContext): void {
  app.get(
    "/cases/:id/cloud-accounts",
    withCloudVault(ctx, (vault, req, res) => {
      const { keyState } = vault.status();
      const accounts = vault.listForCase(req.params.id).map((a) => visibleView(ctx, req, a));
      return res.json({ keyState, accounts });
    }),
  );

  app.post(
    "/cases/:id/cloud-accounts",
    withCloudVault(ctx, async (vault, req, res) => {
      const caseId = req.params.id;
      if (!(await ctx.store.caseExists(caseId))) return res.status(404).json({ error: CASE_NOT_FOUND });
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const { account, keyCreated } = vault.create(parsed.value, caseId);
      if (keyCreated) {
        ctx.serverLogger.info(
          `[cloud-accounts] created the vault key at ${vault.keyPath}; keep it out of data backups`,
        );
      }
      cloudAudit(ctx, req, "cloud-account-created", account, caseId);
      const notice = keyCreated ? { keyCreated, notice: keyNotice(vault.keyPath) } : {};
      return res.status(201).json({ account: visibleView(ctx, req, account), ...notice });
    }),
  );
}

function registerAttachDetach(app: Express, ctx: RouteContext): void {
  app.post(
    "/cases/:id/cloud-accounts/:accountId/attach",
    withCloudVault(ctx, async (vault, req, res) => {
      const { id: caseId, accountId } = req.params;
      const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const target = (req.body as { caseId?: unknown } | undefined)?.caseId;
      if (typeof target !== "string" || !target.trim())
        return res.status(400).json({ error: "caseId names the case to attach the account to." });
      const targetId = target.trim();
      if (!isValidCaseId(targetId)) return res.status(400).json({ error: "caseId is not a valid case id." });
      // Write on both cases: this one by policy, the target here. A case the caller cannot write
      // answers like a case that does not exist.
      if (!canWriteCloudCase(ctx, req, targetId) || !(await ctx.store.caseExists(targetId)))
        return res.status(404).json({ error: CASE_NOT_FOUND });
      const account = vault.attach(accountId, targetId);
      cloudAudit(ctx, req, "cloud-account-attached", account, targetId);
      return res.json({ account: visibleView(ctx, req, account) });
    }),
  );

  app.post(
    "/cases/:id/cloud-accounts/:accountId/detach",
    withCloudVault(ctx, (vault, req, res) => {
      const { id: caseId, accountId } = req.params;
      const found = cloudAccountInCase(ctx, req, vault, caseId, accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      const account = vault.detach(accountId, caseId);
      cloudAudit(ctx, req, "cloud-account-detached", account, caseId);
      return res.json({ detached: true, otherCases: account.caseIds.length });
    }),
  );
}

function registerOne(app: Express, ctx: RouteContext): void {
  app.get(
    "/cases/:id/cloud-accounts/:accountId",
    withCloudVault(ctx, (vault, req, res) => {
      const found = cloudAccountInCase(ctx, req, vault, req.params.id, req.params.accountId);
      if (!found.ok) return sendCloudRefusal(res, found);
      return res.json({ account: visibleView(ctx, req, found.value) });
    }),
  );

  app.put(
    "/cases/:id/cloud-accounts/:accountId",
    withCloudVault(ctx, (vault, req, res) => {
      const { id: caseId, accountId } = req.params;
      const allowed = cloudAccountEditable(ctx, req, vault, caseId, accountId);
      if (!allowed.ok) return sendCloudRefusal(res, allowed);
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const account = vault.update(accountId, parsed.value);
      cloudAudit(ctx, req, "cloud-account-updated", account, caseId);
      return res.json({ account: visibleView(ctx, req, account) });
    }),
  );

  app.delete(
    "/cases/:id/cloud-accounts/:accountId",
    withCloudVault(ctx, (vault, req, res) => {
      const { id: caseId, accountId } = req.params;
      const allowed = cloudAccountEditable(ctx, req, vault, caseId, accountId);
      if (!allowed.ok) return sendCloudRefusal(res, allowed);
      const gone = vault.remove(accountId);
      cloudAudit(ctx, req, "cloud-account-deleted", gone, caseId);
      return res.status(204).end();
    }),
  );
}

export function registerCaseCloudAccountRoutes(app: Express, ctx: RouteContext): void {
  registerListAndAdd(app, ctx);
  // Before the :accountId routes is not needed (attach/detach are a level deeper), but kept
  // together so the inventory reads as one family.
  registerAttachDetach(app, ctx);
  registerOne(app, ctx);
}
