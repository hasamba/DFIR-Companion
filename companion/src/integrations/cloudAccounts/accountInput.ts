import { X509Certificate, createPrivateKey } from "node:crypto";
import { createSecureContext } from "node:tls";
import { CloudVaultError } from "./errors.js";
import {
  CLOUD_PROVIDERS,
  type AwsSecrets,
  type AwsSettings,
  type CloudAccountInput,
  type CloudCredential,
  type CloudProvider,
  type GcpSecrets,
  type GcpSettings,
  type MicrosoftSecrets,
  type MicrosoftSettings,
} from "./types.js";

// Validation of a cloud account request. Every refusal names the field, never its value: the
// values here are credentials, and a refusal travels to the analyst and the server log.

export const MAX_NAME = 80;
const MAX_SECRET = 128 * 1024;
const ROLE_ARN = /^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/;
const ACCESS_KEY_ID = /^[A-Z0-9]{16,128}$/;
const EXTERNAL_ID = /^[\w+=,.@:/-]{2,1224}$/;
const AWS_REGION = /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/;
const GCP_PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const GCP_SA_EMAIL = /^[^@\s]{1,100}@[a-z0-9.-]{1,200}\.gserviceaccount\.com$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT_DOMAIN = /^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;
const MIN_SESSION = 900;
const MAX_SESSION = 3600; // the issue's ceiling: a session never outlives one hour

const bad = (msg: string): never => {
  throw new CloudVaultError("invalid", msg);
};

const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);

export type Parsed = { ok: true; value: CloudAccountInput } | { ok: false; error: string };

/** The request's shape only: name, provider, and the settings and secrets objects. */
export function parseCloudAccountInput(body: unknown): Parsed {
  if (!isObject(body)) return { ok: false, error: "Send a JSON object." };
  const { name, provider, settings, secrets } = body;
  if (typeof name !== "string") return { ok: false, error: "name required" };
  if (typeof provider !== "string" || !CLOUD_PROVIDERS.includes(provider as CloudProvider))
    return { ok: false, error: "provider must be aws, gcp or microsoft" };
  if (settings !== undefined && !isObject(settings))
    return { ok: false, error: "settings must be an object" };
  if (secrets !== undefined && !isObject(secrets)) return { ok: false, error: "secrets must be an object" };
  return {
    ok: true,
    value: { name, provider: provider as CloudProvider, settings: settings ?? {}, secrets: secrets ?? {} },
  };
}

/** A name, trimmed and length-checked. Uniqueness is the vault's check. */
export function cleanName(raw: string): string {
  const name = raw.trim();
  if (!name) bad("name required");
  if (name.length > MAX_NAME) bad(`name must be at most ${MAX_NAME} characters`);
  return name;
}

function str(src: Record<string, unknown>, key: string): string | undefined {
  const v = src[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") return bad(`${key} must be text`);
  const t = v.trim();
  return t ? t : undefined;
}

// A new secret value, or the stored one when the request leaves it out or empty (edit keeps it).
function secret(input: Record<string, unknown>, stored: object | undefined, key: string): string | undefined {
  const v = input[key];
  if (v !== undefined && v !== null && typeof v !== "string") return bad(`${key} must be text`);
  if (typeof v === "string" && v.length > MAX_SECRET) return bad(`${key} is too large`);
  if (typeof v === "string" && v.trim()) return v; // exact: a password may hold spaces
  const kept = (stored as Record<string, unknown> | undefined)?.[key];
  return typeof kept === "string" && kept ? kept : undefined;
}

function need<T>(value: T | undefined, field: string): T {
  return value === undefined ? bad(`${field} required`) : value;
}

function oneOf<T extends string>(v: string | undefined, allowed: readonly T[], field: string): T {
  if (v === undefined || !allowed.includes(v as T)) bad(`${field} must be ${allowed.join(" or ")}`);
  return v as T;
}

function awsCredential(input: CloudAccountInput, stored?: AwsSecrets): CloudCredential {
  const s = input.settings;
  const authMode = oneOf(str(s, "authMode"), ["assume-role", "access-key"] as const, "authMode");
  const region = str(s, "region");
  if (region !== undefined && !AWS_REGION.test(region)) bad("region is not an AWS region name");
  const keyId = (): string => {
    const id = need(secret(input.secrets, stored, "accessKeyId"), "accessKeyId");
    return ACCESS_KEY_ID.test(id) ? id : bad("accessKeyId is not an AWS access key id");
  };
  const keyPair = (): AwsSecrets => ({
    accessKeyId: keyId(),
    secretAccessKey: need(secret(input.secrets, stored, "secretAccessKey"), "secretAccessKey"),
  });
  if (authMode === "access-key") {
    const sessionToken = secret(input.secrets, stored, "sessionToken");
    return {
      provider: "aws",
      settings: { authMode, ...(region && { region }) },
      secrets: { ...keyPair(), ...(sessionToken && { sessionToken }) },
    };
  }
  const roleArn = need(str(s, "roleArn"), "roleArn");
  if (!ROLE_ARN.test(roleArn)) bad("roleArn is not an IAM role ARN");
  const baseCredential = oneOf(
    str(s, "baseCredential"),
    ["access-key", "ambient"] as const,
    "baseCredential",
  );
  const sessionSeconds = s.sessionSeconds === undefined ? MAX_SESSION : Number(s.sessionSeconds);
  if (!Number.isInteger(sessionSeconds) || sessionSeconds < MIN_SESSION || sessionSeconds > MAX_SESSION)
    bad(`sessionSeconds must be ${MIN_SESSION}–${MAX_SESSION}`);
  const externalId = secret(input.secrets, stored, "externalId");
  if (externalId !== undefined && !EXTERNAL_ID.test(externalId)) bad("externalId has characters AWS refuses");
  const settings: AwsSettings = {
    authMode,
    roleArn,
    baseCredential,
    sessionSeconds,
    ...(region && { region }),
  };
  const base = baseCredential === "access-key" ? keyPair() : {};
  return { provider: "aws", settings, secrets: { ...base, ...(externalId && { externalId }) } };
}

// A service-account key JSON; returns its client_email. Refusals never quote the file.
function gcpKeyEmail(json: string): string {
  let key: unknown;
  try {
    key = JSON.parse(json);
  } catch {
    return bad("serviceAccountKeyJson is not JSON");
  }
  if (!isObject(key) || key.type !== "service_account")
    return bad("serviceAccountKeyJson is not a service-account key");
  if (typeof key.client_email !== "string" || !GCP_SA_EMAIL.test(key.client_email))
    return bad("serviceAccountKeyJson has no client_email");
  if (typeof key.private_key !== "string" || !key.private_key.includes("PRIVATE KEY"))
    return bad("serviceAccountKeyJson has no private_key");
  return key.client_email;
}

function gcpCredential(input: CloudAccountInput, stored?: GcpSecrets): CloudCredential {
  const s = input.settings;
  const projectId = need(str(s, "projectId"), "projectId");
  if (!GCP_PROJECT.test(projectId)) bad("projectId is not a GCP project id");
  const authMode = oneOf(str(s, "authMode"), ["service-account-key", "impersonation"] as const, "authMode");
  const keyJson = (): string =>
    need(secret(input.secrets, stored, "serviceAccountKeyJson"), "serviceAccountKeyJson");
  if (authMode === "service-account-key") {
    const json = keyJson();
    const settings: GcpSettings = { projectId, authMode, clientEmail: gcpKeyEmail(json) };
    return { provider: "gcp", settings, secrets: { serviceAccountKeyJson: json } };
  }
  const target = need(str(s, "targetServiceAccount"), "targetServiceAccount");
  if (!GCP_SA_EMAIL.test(target)) bad("targetServiceAccount is not a service-account email");
  const baseCredential = oneOf(
    str(s, "baseCredential"),
    ["service-account-key", "ambient"] as const,
    "baseCredential",
  );
  const settings: GcpSettings = { projectId, authMode, targetServiceAccount: target, baseCredential };
  if (baseCredential === "ambient") return { provider: "gcp", settings, secrets: {} };
  const json = keyJson();
  return {
    provider: "gcp",
    settings: { ...settings, clientEmail: gcpKeyEmail(json) },
    secrets: { serviceAccountKeyJson: json },
  };
}

// The PEM must hold a certificate and the private key that belongs to it. Returns the thumbprint.
function pemThumbprint(pem: string): string {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    return bad("certificatePem has no certificate");
  }
  let matches = false;
  try {
    matches = cert.checkPrivateKey(createPrivateKey(pem));
  } catch {
    return bad("certificatePem has no unencrypted private key");
  }
  if (!matches) bad("certificatePem private key does not belong to its certificate");
  return cert.fingerprint.replace(/:/g, "").toUpperCase();
}

// Opens the PFX in memory with its password, to refuse a wrong password at save time. Nothing is
// written: the PFX stays sealed in the vault, and the PEM a collector needs is made at use.
function checkPfx(pfxBase64: string, password: string): void {
  const pfx = Buffer.from(pfxBase64, "base64");
  if (pfx.length === 0) bad("pfxBase64 is not base64");
  try {
    createSecureContext({ pfx, passphrase: password });
  } catch {
    bad("the PFX file cannot be opened with that password");
  }
}

function microsoftCredential(input: CloudAccountInput, stored?: MicrosoftSecrets): CloudCredential {
  const s = input.settings;
  const tenantId = need(str(s, "tenantId"), "tenantId");
  if (!GUID.test(tenantId) && !TENANT_DOMAIN.test(tenantId)) bad("tenantId is not a tenant id or domain");
  const clientId = need(str(s, "clientId"), "clientId");
  if (!GUID.test(clientId)) bad("clientId is not an application (client) id");
  const certificateFormat = oneOf(str(s, "certificateFormat"), ["pem", "pfx"] as const, "certificateFormat");
  if (certificateFormat === "pem") {
    const pem = need(secret(input.secrets, stored, "certificatePem"), "certificatePem");
    const settings: MicrosoftSettings = {
      tenantId,
      clientId,
      certificateFormat,
      certificateThumbprint: pemThumbprint(pem),
    };
    return { provider: "microsoft", settings, secrets: { certificatePem: pem } };
  }
  // A new PFX brings its own password (possibly empty); otherwise a typed password replaces the stored one.
  const newPfx = typeof input.secrets.pfxBase64 === "string" && input.secrets.pfxBase64.trim() !== "";
  const pfxBase64 = need(secret(input.secrets, stored, "pfxBase64"), "pfxBase64");
  const typed = input.secrets.pfxPassword;
  if (typed !== undefined && typed !== null && typeof typed !== "string") bad("pfxPassword must be text");
  let pfxPassword = stored?.pfxPassword ?? "";
  if (newPfx) pfxPassword = typeof typed === "string" ? typed : "";
  else if (typeof typed === "string" && typed) pfxPassword = typed;
  checkPfx(pfxBase64, pfxPassword);
  return {
    provider: "microsoft",
    settings: { tenantId, clientId, certificateFormat },
    secrets: { pfxBase64, ...(pfxPassword && { pfxPassword }) },
  };
}

/**
 * The credential a request describes, validated, with every secret the request leaves out taken
 * from `stored` (an edit). Secrets the chosen mode does not use are dropped, so switching an AWS
 * account to an ambient base credential deletes its stored access key.
 */
export function buildCredential(input: CloudAccountInput, stored?: CloudCredential): CloudCredential {
  const kept = stored && stored.provider === input.provider ? stored.secrets : undefined;
  if (input.provider === "aws") return awsCredential(input, kept as AwsSecrets | undefined);
  if (input.provider === "gcp") return gcpCredential(input, kept as GcpSecrets | undefined);
  return microsoftCredential(input, kept as MicrosoftSecrets | undefined);
}
