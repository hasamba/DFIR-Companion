/**
 * Cloud accounts (#2307) — the AWS accounts, Microsoft tenants and GCP projects later collection
 * uses. Secrets are sealed with a key file kept OUT of the data folder (vaultKeyFile.ts).
 *
 *   GET    /cloud-accounts              global admin: the accounts (no secrets) and the key's state
 *   POST   /cloud-accounts              global admin: add; on first use makes the key file
 *   POST   /cloud-accounts/reset        global admin: Reset vault — wipes the accounts, needs confirm
 *   PUT    /cloud-accounts/:accountId   global admin: edit (a left-out secret keeps the stored one)
 *   DELETE /cloud-accounts/:accountId   global admin: delete (overwrites the sealed entry)
 *
 * No response, log line or audit entry carries a credential: responses hold the names of the
 * stored secrets only, and every error text comes from cloudSafeError().
 */
import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import type { CloudAccountVault } from "../integrations/cloudAccounts/cloudAccountVault.js";
import { CloudVaultError, cloudSafeError } from "../integrations/cloudAccounts/errors.js";
import { parseCloudAccountInput } from "../integrations/cloudAccounts/accountInput.js";
import type { RouteContext } from "./context.js";

const UNAVAILABLE = "Cloud accounts are not available.";
const NOT_FOUND = "Cloud account not found.";
const RESET_CONFIRM = "Reset vault deletes every cloud account. Send confirm: true to go ahead.";

type Who = { id: string; name: string; provider?: string };

function audit(ctx: RouteContext, req: Request, action: string, who: Who): void {
  const auth = requestAuthentication(req);
  if (auth?.kind === "session") {
    ctx.options.teamAuth?.store.addAudit(auth.identity, action, who.id, undefined, who.name);
  }
  const provider = who.provider ? ` provider=${who.provider}` : "";
  ctx.serverLogger.info(
    `[cloud-accounts] ${action} id=${who.id} name=${JSON.stringify(who.name)}${provider}`,
  );
}

// A vault refusal is the caller's to fix (400/404/409/423); anything else is a server fault.
function vaultError(ctx: RouteContext, req: Request, res: Response, err: unknown): Response {
  if (err instanceof CloudVaultError) {
    if (err.code === "not-found") return res.status(404).json({ error: NOT_FOUND });
    if (err.code === "locked") return res.status(423).json({ error: err.message, locked: true });
    if (err.code === "conflict") return res.status(409).json({ error: err.message });
    return res.status(400).json({ error: err.message });
  }
  ctx.serverLogger.error(`[cloud-accounts] ${req.method} ${req.path}: ${cloudSafeError(err)}`);
  return res.status(500).json({ error: "Cloud accounts cannot be saved. Check the server log." });
}

function withVault(
  ctx: RouteContext,
  handler: (vault: CloudAccountVault, req: Request, res: Response) => unknown,
) {
  return async (req: Request, res: Response) => {
    const vault = ctx.options.cloudAccountVault;
    if (!vault) return res.status(503).json({ error: UNAVAILABLE });
    try {
      return await handler(vault, req, res);
    } catch (err) {
      return vaultError(ctx, req, res, err);
    }
  };
}

function keyNotice(vault: CloudAccountVault): string {
  return (
    `A new vault key was made at ${vault.keyPath}. Back it up on its own and keep it OUT of ` +
    "data-folder backups: whoever holds both can read every cloud credential."
  );
}

export function registerCloudAccountRoutes(app: Express, ctx: RouteContext): void {
  app.get(
    "/cloud-accounts",
    withVault(ctx, (vault, _req, res) => {
      const { keyPath, keyState } = vault.status();
      return res.json({ keyPath, keyState, accounts: vault.list() });
    }),
  );

  app.post(
    "/cloud-accounts",
    withVault(ctx, (vault, req, res) => {
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const { account, keyCreated } = vault.create(parsed.value);
      if (keyCreated) {
        ctx.serverLogger.info(
          `[cloud-accounts] created the vault key at ${vault.keyPath}; keep it out of data backups`,
        );
      }
      audit(ctx, req, "cloud-account-created", account);
      return res.status(201).json({ account, ...(keyCreated && { keyCreated, notice: keyNotice(vault) }) });
    }),
  );

  // Registered before the :accountId routes, so "reset" is never read as an account id.
  app.post(
    "/cloud-accounts/reset",
    withVault(ctx, (vault, req, res) => {
      if ((req.body as { confirm?: unknown } | undefined)?.confirm !== true)
        return res.status(400).json({ error: RESET_CONFIRM });
      const removed = vault.reset();
      audit(ctx, req, "cloud-vault-reset", { id: "-", name: `${removed} accounts` });
      return res.json({ removed });
    }),
  );

  app.put(
    "/cloud-accounts/:accountId",
    withVault(ctx, (vault, req, res) => {
      const parsed = parseCloudAccountInput(req.body);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      const account = vault.update(req.params.accountId, parsed.value);
      audit(ctx, req, "cloud-account-updated", account);
      return res.json({ account });
    }),
  );

  app.delete(
    "/cloud-accounts/:accountId",
    withVault(ctx, (vault, req, res) => {
      const gone = vault.remove(req.params.accountId);
      audit(ctx, req, "cloud-account-deleted", gone);
      return res.status(204).end();
    }),
  );
}
