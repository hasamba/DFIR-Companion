/**
 * Cloud accounts (#2307) — the AWS accounts, Microsoft tenants and GCP projects later collection
 * uses. Secrets are sealed with a key file kept OUT of the data folder (vaultKeyFile.ts).
 *
 * Since #2308 accounts belong to cases: case writers use /cases/:id/cloud-accounts
 * (cloudAccountsCase.ts). These top-level routes are the INSTANCE ADMINISTRATOR's view of every
 * account — name, provider and attached cases, never a secret — and stay global admin:
 *
 *   GET    /cloud-accounts                     every account (no secrets), its cases, the key's state,
 *                                              and the minimum read-only policy per provider (#2309)
 *   POST   /cloud-accounts                     add an UNATTACHED account; on first use makes the key
 *   POST   /cloud-accounts/reset               Reset vault — wipes the accounts, needs confirm
 *   PUT    /cloud-accounts/:accountId          edit (a left-out secret keeps the stored one)
 *   DELETE /cloud-accounts/:accountId          delete (overwrites the sealed entry)
 *   POST   /cloud-accounts/:accountId/attach   { caseId } — attach to a case (e.g. an account
 *                                              stored before #2308, which has no case)
 *
 * An account stored before #2308 has no case: only an instance administrator sees it, here, until
 * they attach it to a case or delete it. No response, log line or audit entry carries a credential:
 * responses hold the names of the stored secrets only, and every error text comes from
 * cloudSafeError().
 */
import type { Express } from "express";
import type { CloudAccountVault } from "../integrations/cloudAccounts/cloudAccountVault.js";
import { parseCloudAccountInput } from "../integrations/cloudAccounts/accountInput.js";
import { MINIMUM_POLICIES } from "../integrations/cloudCheck/minimumPolicies.js";
import { cloudAudit, withCloudVault } from "./cloudAccountAccess.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

const RESET_CONFIRM = "Reset vault deletes every cloud account. Send confirm: true to go ahead.";

function keyNotice(vault: CloudAccountVault): string {
  return (
    `A new vault key was made at ${vault.keyPath}. Back it up on its own and keep it OUT of ` +
    "data-folder backups: whoever holds both can read every cloud credential."
  );
}

export function registerCloudAccountRoutes(app: Express, ctx: RouteContext): void {
  app.get(
    "/cloud-accounts",
    withCloudVault(ctx, (vault, _req, res) => {
      const { keyPath, keyState } = vault.status();
      return res.json({ keyPath, keyState, accounts: vault.list(), minimumPolicies: MINIMUM_POLICIES });
    }),
  );

  app.post(
    "/cloud-accounts",
    withCloudVault(ctx, (vault, req, res) => {
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const { account, keyCreated } = vault.create(parsed.value);
      if (keyCreated) {
        ctx.serverLogger.info(
          `[cloud-accounts] created the vault key at ${vault.keyPath}; keep it out of data backups`,
        );
      }
      cloudAudit(ctx, req, "cloud-account-created", account);
      return res.status(201).json({ account, ...(keyCreated && { keyCreated, notice: keyNotice(vault) }) });
    }),
  );

  // Registered before the :accountId routes, so "reset" is never read as an account id.
  app.post(
    "/cloud-accounts/reset",
    withCloudVault(ctx, (vault, req, res) => {
      if ((req.body as { confirm?: unknown } | undefined)?.confirm !== true)
        return res.status(400).json({ error: RESET_CONFIRM });
      const removed = vault.reset();
      cloudAudit(ctx, req, "cloud-vault-reset", { id: "-", name: `${removed} accounts` });
      return res.json({ removed });
    }),
  );

  app.put(
    "/cloud-accounts/:accountId",
    withCloudVault(ctx, (vault, req, res) => {
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const account = vault.update(req.params.accountId, parsed.value);
      cloudAudit(ctx, req, "cloud-account-updated", account);
      return res.json({ account });
    }),
  );

  app.post(
    "/cloud-accounts/:accountId/attach",
    withCloudVault(ctx, async (vault, req, res) => {
      const target = (req.body as { caseId?: unknown } | undefined)?.caseId;
      const caseId = typeof target === "string" ? target.trim() : "";
      if (!caseId) return res.status(400).json({ error: "caseId names the case to attach the account to." });
      if (!isValidCaseId(caseId)) return res.status(400).json({ error: "caseId is not a valid case id." });
      if (!(await ctx.store.caseExists(caseId))) return res.status(404).json({ error: "Case not found." });
      const account = vault.attach(req.params.accountId, caseId);
      cloudAudit(ctx, req, "cloud-account-attached", account, caseId);
      return res.json({ account });
    }),
  );

  app.delete(
    "/cloud-accounts/:accountId",
    withCloudVault(ctx, (vault, req, res) => {
      const gone = vault.remove(req.params.accountId);
      cloudAudit(ctx, req, "cloud-account-deleted", gone);
      return res.status(204).end();
    }),
  );
}
