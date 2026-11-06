// Runs a cloud account read check (#2309): the analyst picks sources, the check makes one read per
// source with the account's credential, and the report says which reads worked — never that the
// account is read-only. See readCheckTypes.ts for the sources and readCheckWording.ts for the words.

import type { OpenCloudAccount } from "../cloudAccounts/types.js";
import { secretsOfAccount } from "../cloudAccounts/types.js";
import { derivedSecretParts, microsoftCertificatePem } from "../cloudAccounts/microsoftCertificate.js";
import { runAwsReadCheck } from "./awsReadCheck.js";
import type { CheckClientFactory } from "./checkClients.js";
import { runGcpReadCheck } from "./gcpReadCheck.js";
import { runMicrosoftReadCheck } from "./microsoftReadCheck.js";
import {
  CHECK_SOURCES,
  sourceResult,
  type AwsCheckSource,
  type CloudCheckReport,
  type CloudCheckRequest,
  type CloudCheckSource,
  type GcpCheckSource,
  type MicrosoftCheckSource,
  type SourceCheckResult,
} from "./readCheckTypes.js";
import { checkFailureReason, checkSummary } from "./readCheckWording.js";

/** What the route calls. Production builds it over the cloud transport; tests inject mocks. */
export type CloudCheckRunner = (
  account: OpenCloudAccount,
  request: CloudCheckRequest,
) => Promise<CloudCheckReport>;

// S3's bucket naming rules: 3–63 lower-case letters, digits, dots and hyphens.
const BUCKET_NAME = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const MAX_PREFIX = 1024;
// A key prefix never holds a control character; one in the request is a mistake or an attack.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

type Parsed = { ok: true; value: CloudCheckRequest } | { ok: false; error: string };

function parseSources(provider: OpenCloudAccount["provider"], raw: unknown): CloudCheckSource[] | string {
  const valid = CHECK_SOURCES[provider];
  if (raw === undefined || raw === null) return [...valid];
  if (!Array.isArray(raw) || raw.some((s) => typeof s !== "string"))
    return "sources must be a list of source names.";
  const unknown = raw.filter((s: string) => !valid.includes(s as CloudCheckSource));
  if (unknown.length > 0)
    return `Unknown source for this account: ${unknown.join(", ")}. Valid: ${valid.join(", ")}.`;
  const picked = valid.filter((s) => raw.includes(s));
  return picked.length > 0 ? picked : [...valid];
}

function optionalText(raw: unknown, field: string): string | undefined | { error: string } {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "string") return { error: `${field} must be text.` };
  const trimmed = raw.trim();
  return trimmed || undefined;
}

/** Reads a check request body. Absent or empty `sources` means every source of the provider. */
export function parseCloudCheckRequest(provider: OpenCloudAccount["provider"], body: unknown): Parsed {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const sources = parseSources(provider, b.sources);
  if (typeof sources === "string") return { ok: false, error: sources };
  const bucket = optionalText(b.s3Bucket, "s3Bucket");
  const prefix = optionalText(b.s3Prefix, "s3Prefix");
  if (typeof bucket === "object") return { ok: false, error: bucket.error };
  if (typeof prefix === "object") return { ok: false, error: prefix.error };
  if (bucket !== undefined && !BUCKET_NAME.test(bucket))
    return { ok: false, error: "s3Bucket is not a valid S3 bucket name." };
  if (prefix !== undefined && (prefix.length > MAX_PREFIX || CONTROL_CHARS.test(prefix)))
    return { ok: false, error: "s3Prefix is not a valid S3 key prefix." };
  return {
    ok: true,
    value: { sources, ...(bucket ? { s3Bucket: bucket } : {}), ...(prefix ? { s3Prefix: prefix } : {}) },
  };
}

function allFailed(
  sources: CloudCheckSource[],
  err: unknown,
  secrets: readonly string[],
): SourceCheckResult[] {
  const reason = checkFailureReason(err, secrets);
  return sources.map((s) => sourceResult(s, "failed", reason));
}

async function resultsFor(
  account: OpenCloudAccount,
  request: CloudCheckRequest,
  factory: () => CheckClientFactory,
  secrets: readonly string[],
): Promise<{ results: SourceCheckResult[]; signedInAs?: string }> {
  if (account.provider === "aws") {
    const clients = factory().aws(account.settings, account.secrets);
    const sources = request.sources as AwsCheckSource[];
    return runAwsReadCheck(clients, {
      sources,
      s3Bucket: request.s3Bucket,
      s3Prefix: request.s3Prefix,
      secrets,
    });
  }
  if (account.provider === "microsoft") {
    const sources = request.sources as MicrosoftCheckSource[];
    // PEM as stored, or a PFX opened in memory (#2315) — before any client is built, so a PFX that
    // will not open fails every source with fixed text and signs in with nothing.
    const pem = microsoftCertificatePem(account.settings, account.secrets);
    const all = [...secrets, ...derivedSecretParts(pem)];
    return {
      results: await runMicrosoftReadCheck(factory().microsoft(account.settings, pem), {
        sources,
        secrets: all,
      }),
    };
  }
  const sources = request.sources as GcpCheckSource[];
  const client = await factory().gcp(account.settings, account.secrets);
  return {
    results: await runGcpReadCheck(client, { projectId: account.settings.projectId, sources, secrets }),
  };
}

/**
 * Checks one opened account. `factory` is called only when a network check will run, so a PFX
 * that will not open or a bad request never builds a client. A client that cannot be built (a credential
 * missing from the account) fails every selected source with the reason.
 */
export async function runCloudAccountCheck(
  account: OpenCloudAccount,
  request: CloudCheckRequest,
  factory: () => CheckClientFactory,
): Promise<CloudCheckReport> {
  const secrets = secretsOfAccount(account);
  let outcome: { results: SourceCheckResult[]; signedInAs?: string };
  try {
    outcome = await resultsFor(account, request, factory, secrets);
  } catch (err) {
    outcome = { results: allFailed(request.sources, err, secrets) };
  }
  return {
    provider: account.provider,
    results: outcome.results,
    ...(outcome.signedInAs ? { signedInAs: outcome.signedInAs } : {}),
    summary: checkSummary(outcome.results),
    checkedAt: new Date().toISOString(),
  };
}
