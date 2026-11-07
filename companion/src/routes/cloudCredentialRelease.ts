/**
 * Cloud credentials end with the case (#2347). One place that erases or detaches a case's cloud
 * accounts and records it, so close, archive, delete and the cloud-accounts list all leave the same
 * trail:
 *
 *   - the team audit log and the server log (cloudAudit) — name and provider, never a secret;
 *   - the custody log of every case the erased credential was attached to: a `credential-deleted`
 *     entry naming the provider, the account / tenant / project ID, who added it and when, which of
 *     the case's collections used it, who deleted it, when and why. Reports can then still say where
 *     collected evidence came from after the credential is gone.
 *   - a shared credential only DETACHED from an ending case leaves the same provenance in that case's
 *     log as a `credential-detached` entry. It is written BEFORE the detach: a detach is cheap to
 *     retry, lost provenance is not, so a custody write that fails stops the release instead. The
 *     vault lock spans those writes and the release (#2371), so a concurrent attach or detach waits
 *     and the entries match what was done. With several shared accounts, a write that fails after
 *     the first leaves the earlier entries although nothing was detached; the vault is unchanged and
 *     a retry records them again before detaching.
 *
 * Erasing the companion's copy does not stop the credential working in the cloud — the dashboard
 * reminds the analyst to revoke the key or app secret in AWS, Azure or GCP as well.
 *
 * A `credential-deleted` custody write never fails the delete: the secret is already gone when it
 * runs, and reporting "not deleted" for an erased credential would be the worse lie. Failures are
 * logged instead.
 */
import { createHash } from "node:crypto";
import type { Request } from "express";
import { requestAuthentication } from "../auth/types.js";
import {
  CREDENTIAL_DELETED_EVENT,
  CREDENTIAL_DETACHED_EVENT,
  CREDENTIAL_PATH_PREFIX,
  type CredentialCustodyEvent,
} from "../analysis/custody.js";
import type {
  AwsSettings,
  GcpSettings,
  MicrosoftSettings,
  ReleasedCloudAccount,
} from "../integrations/cloudAccounts/types.js";
import { nodeCollectFs } from "../integrations/cloudCollect/collectFs.js";
import { listCollections } from "../integrations/cloudCollect/collectStore.js";
import { cloudAudit } from "./cloudAccountAccess.js";
import type { RouteContext } from "./context.js";

/** Why credentials were deleted, in the custody entry and the audit detail. */
export type CredentialReleaseReason =
  "case closed" | "case archived" | "case deleted" | "deleted from the list";

export const COLLECTION_RUNNING =
  "A cloud collection is running on this case. Stop it, or let it finish, before closing, archiving or deleting the case.";

const NOT_RECORDED = "not recorded";

/** The refusal when a cloud collection of the case is queued or running, else undefined. */
export function runningCollectionRefusal(ctx: RouteContext, caseId: string): string | undefined {
  return ctx.options.jobManager?.hasActive(caseId, "cloud-collect") ? COLLECTION_RUNNING : undefined;
}

/** The AWS account, Microsoft tenant or GCP project an account names — identifiers, not secrets. */
export function credentialIdentifier(account: Pick<ReleasedCloudAccount, "provider" | "settings">): string {
  if (account.provider === "gcp")
    return `project ${(account.settings as GcpSettings).projectId || NOT_RECORDED}`;
  if (account.provider === "microsoft")
    return `tenant ${(account.settings as MicrosoftSettings).tenantId || NOT_RECORDED}`;
  const arn = (account.settings as AwsSettings).roleArn ?? "";
  const id = /^arn:aws[a-z-]*:iam::(\d{12}):/.exec(arn)?.[1];
  return id ? `account ${id}` : `account ${NOT_RECORDED} (access key)`;
}

function actorName(req: Request): string {
  return requestAuthentication(req)?.identity.displayName ?? "analyst";
}

async function collectionsUsing(ctx: RouteContext, caseId: string, accountId: string): Promise<string[]> {
  try {
    const all = await listCollections(nodeCollectFs, ctx.store.caseDir(caseId));
    return all.filter((c) => c.checkpoint.accountId === accountId).map((c) => c.checkpoint.collectionId);
  } catch {
    return [];
  }
}

const PROVIDER_LABEL: Record<string, string> = { aws: "AWS", gcp: "GCP", microsoft: "Microsoft" };

const VERB: Record<CredentialCustodyEvent, string> = {
  [CREDENTIAL_DELETED_EVENT]: "deleted",
  [CREDENTIAL_DETACHED_EVENT]: "detached",
};

/** Writes one credential custody entry on `caseId`. Throws when the write fails. */
async function writeCredentialCustody(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  account: ReleasedCloudAccount,
  reason: CredentialReleaseReason,
  event: CredentialCustodyEvent,
): Promise<void> {
  const custody = ctx.options.custodyStore;
  if (!custody) return;
  const identifier = credentialIdentifier(account);
  const addedBy = account.createdBy?.displayName ?? NOT_RECORDED;
  const actor = actorName(req);
  const at = new Date().toISOString();
  const collections = await collectionsUsing(ctx, caseId, account.id);
  const credential = {
    accountId: account.id,
    provider: account.provider,
    name: account.name,
    identifier,
    addedBy,
    addedAt: account.createdAt,
    collections,
    reason,
  };
  const label = PROVIDER_LABEL[account.provider] ?? account.provider;
  const used = collections.length ? `; used by ${collections.join(", ")}` : "";
  // The hash keys keep the names a `credential-deleted` entry has always hashed under.
  const by =
    event === CREDENTIAL_DELETED_EVENT
      ? { deletedBy: actor, deletedAt: at }
      : { detachedBy: actor, detachedAt: at };
  await custody.record(caseId, {
    artifactPath: `${CREDENTIAL_PATH_PREFIX}${account.provider}/${account.id}`,
    // No file stands behind the entry: the hash pins the entry's own description of the credential.
    sha256: createHash("sha256")
      .update(JSON.stringify({ ...credential, ...by }))
      .digest("hex"),
    caseId,
    event,
    collectedBy: actor,
    collectedAt: at,
    source: `${label} ${identifier} ("${account.name}"), added by ${addedBy} at ${account.createdAt}${used}`,
    trigger: `cloud credential ${VERB[event]} — ${reason}`,
    credential,
  });
}

/** Writes one `credential-deleted` custody entry on `caseId`. Never throws. */
async function recordCredentialCustody(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  account: ReleasedCloudAccount,
  reason: CredentialReleaseReason,
): Promise<void> {
  try {
    await writeCredentialCustody(ctx, req, caseId, account, reason, CREDENTIAL_DELETED_EVENT);
  } catch (err) {
    ctx.serverLogger.error(
      `[cloud-accounts] case=${caseId} credential ${account.id} deleted, but its custody entry failed: ${(err as Error).message}`,
    );
  }
}

/** Audit + custody for credentials already erased from the vault. */
async function recordDeleted(
  ctx: RouteContext,
  req: Request,
  deleted: readonly ReleasedCloudAccount[],
  reason: CredentialReleaseReason,
  inCase?: string,
): Promise<void> {
  for (const account of deleted) {
    cloudAudit(
      ctx,
      req,
      "cloud-account-deleted",
      { ...account, name: `${account.name} — ${reason}` },
      inCase,
    );
    for (const caseId of account.caseIds) await recordCredentialCustody(ctx, req, caseId, account, reason);
  }
}

export interface ReleaseOutcome {
  deleted: number;
  detached: number;
}

/**
 * A case ends: every account only this case used is erased, every shared one detached from it. No
 * vault (or the demo, which has none in use) is a no-op.
 */
export async function releaseCaseCredentials(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  reason: CredentialReleaseReason,
): Promise<ReleaseOutcome> {
  const vault = ctx.options.cloudAccountVault;
  if (!vault || ctx.options.demoMode) return { deleted: 0, detached: 0 };
  // Provenance first: a failed write throws here, before anything is detached or erased. The vault
  // holds its lock from the read through the release, so a concurrent attach or detach cannot make
  // the recorded detaches disagree with what the release does (#2371). Only the custody of the
  // DETACHES needs that snapshot; audit and the deleted entries below run after the lock is let go.
  const { deleted, detached } = await vault.releaseCaseRecorded(caseId, async (shared) => {
    for (const account of shared)
      await writeCredentialCustody(ctx, req, caseId, account, reason, CREDENTIAL_DETACHED_EVENT);
  });
  await recordDeleted(ctx, req, deleted, reason, caseId);
  for (const account of detached)
    cloudAudit(
      ctx,
      req,
      "cloud-account-detached",
      { ...account, name: `${account.name} — ${reason}` },
      caseId,
    );
  return { deleted: deleted.length, detached: detached.length };
}

/**
 * Erases the named accounts (already authorised by the caller) and records each delete. The caller
 * runs inside `vault.exclusive` (withCloudVaultExclusive), with its authorisation in the same
 * section, so nothing changes between the check and the erase (#2371). Not locked here: the vault
 * lock is not re-entrant.
 */
export async function deleteCloudCredentials(
  ctx: RouteContext,
  req: Request,
  ids: readonly string[],
  inCase?: string,
): Promise<ReleasedCloudAccount[]> {
  const vault = ctx.options.cloudAccountVault;
  if (!vault) return [];
  const gone = vault.removeMany(ids);
  await recordDeleted(ctx, req, gone, "deleted from the list", inCase);
  return gone;
}

/** What a lifecycle route adds to its answer: the outcome, or why the release failed. */
export type ReleaseReport = { cloudCredentials?: ReleaseOutcome; cloudCredentialsError?: string };

/**
 * `releaseCaseCredentials` for close, which has already made its change: never throws, so a failed
 * release cannot undo or misreport the close — the answer carries the error for the dashboard to
 * show. Nothing to release adds nothing to the answer. Archive and delete use releaseBeforeCaseEnd.
 */
export async function releaseOnCaseEnd(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  reason: CredentialReleaseReason,
): Promise<ReleaseReport> {
  try {
    const outcome = await releaseCaseCredentials(ctx, req, caseId, reason);
    return outcome.deleted || outcome.detached ? { cloudCredentials: outcome } : {};
  } catch (err) {
    ctx.serverLogger.error(
      `[cloud-accounts] case=${caseId} ${reason}, but its credentials were not released: ${(err as Error).message}`,
    );
    return {
      cloudCredentialsError:
        "The case's cloud credentials could not be deleted. Delete them from Settings → Cloud accounts.",
    };
  }
}

/** Why archive or delete stopped: the credentials go first, so the case is still as it was. */
export const RELEASE_BLOCKED_CASE_END =
  "The case's cloud credentials could not be deleted, so the case was left in place, unchanged. " +
  "Try again; if it keeps failing, delete them from Settings → Cloud accounts first.";

/**
 * `releaseCaseCredentials` as a PREREQUISITE of archive and delete: the caller goes on only when it
 * succeeded, so a case never leaves the active list, or disappears, with its credentials still held.
 * Never throws.
 */
export async function releaseBeforeCaseEnd(
  ctx: RouteContext,
  req: Request,
  caseId: string,
  reason: CredentialReleaseReason,
): Promise<{ ok: true; report: ReleaseReport } | { ok: false; error: string }> {
  try {
    const outcome = await releaseCaseCredentials(ctx, req, caseId, reason);
    return { ok: true, report: outcome.deleted || outcome.detached ? { cloudCredentials: outcome } : {} };
  } catch (err) {
    ctx.serverLogger.error(
      `[cloud-accounts] case=${caseId} ${reason} refused: its credentials were not released: ${(err as Error).message}`,
    );
    return { ok: false, error: RELEASE_BLOCKED_CASE_END };
  }
}

/** The close request's credential choice: delete (the default) or keep; null for anything else. */
export function closeCredentialChoice(body: unknown): "delete" | "keep" | null {
  const raw = (body as { cloudCredentials?: unknown } | undefined)?.cloudCredentials;
  if (raw === undefined || raw === "delete") return "delete";
  return raw === "keep" ? "keep" : null;
}
