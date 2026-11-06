// Cloud accounts (#2307): an AWS account, a Microsoft tenant or a GCP project, with the credential
// later collection issues use. Settings are plain identifiers; every credential is a secret, sealed
// in the vault and never sent back — a view carries only the NAMES of the secrets it holds.

export type CloudProvider = "aws" | "gcp" | "microsoft";
export const CLOUD_PROVIDERS: readonly CloudProvider[] = ["aws", "gcp", "microsoft"];

/** AWS: assume a role (preferred, short-lived) or use an access key on its own. */
export interface AwsSettings {
  authMode: "assume-role" | "access-key";
  /** assume-role: the role to assume. */
  roleArn?: string;
  /** assume-role: what calls AssumeRole — a stored access key, or an ambient profile/instance role. */
  baseCredential?: "access-key" | "ambient";
  region?: string;
  /** assume-role: session length, 900–3600 seconds. */
  sessionSeconds?: number;
}
export interface AwsSecrets {
  externalId?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
}

/** GCP: a service-account key, or impersonation of a target service account. */
export interface GcpSettings {
  projectId: string;
  authMode: "service-account-key" | "impersonation";
  /** impersonation: the service account to impersonate. */
  targetServiceAccount?: string;
  /** impersonation: what calls the IAM Credentials API — a stored key, or ambient credentials. */
  baseCredential?: "service-account-key" | "ambient";
  /** The client_email of the stored key, read from it on save. An identifier, not a secret. */
  clientEmail?: string;
}
export interface GcpSecrets {
  serviceAccountKeyJson?: string;
}

/** Microsoft: an app registration with a certificate, app-only. */
export interface MicrosoftSettings {
  tenantId: string;
  clientId: string;
  certificateFormat: "pem" | "pfx";
  /** SHA-1 thumbprint of a PEM certificate, read from it on save (hex, upper case). */
  certificateThumbprint?: string;
}
export interface MicrosoftSecrets {
  /** The certificate and its private key, PEM. */
  certificatePem?: string;
  /** A PFX file, base64. The PEM that ClientCertificateCredential needs is made in memory at use. */
  pfxBase64?: string;
  pfxPassword?: string;
}

export type CloudCredential =
  | { provider: "aws"; settings: AwsSettings; secrets: AwsSecrets }
  | { provider: "gcp"; settings: GcpSettings; secrets: GcpSecrets }
  | { provider: "microsoft"; settings: MicrosoftSettings; secrets: MicrosoftSecrets };

/** Who added an account (#2347). Absent on an account added before it was recorded. */
export interface CloudAccountAdder {
  id: string;
  displayName: string;
}

interface AccountMeta {
  id: string;
  name: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  /** Who added it (#2347); absent on accounts added before this was recorded. */
  createdBy?: CloudAccountAdder;
  /** When collection or a read check last opened it (#2347); absent until then. */
  lastUsedAt?: string;
}

/** An account opened with the vault key: the only shape that holds secrets. Never sent to a client. */
export type OpenCloudAccount = AccountMeta & CloudCredential;

/**
 * What the vault writes to disk: the secrets as one sealed string. `caseIds` (#2308) are the cases
 * that may use the account — plain metadata, never sealed. An account stored before #2308 has none
 * and reads as unattached: only an instance administrator sees it until they attach it to a case.
 */
export type StoredCloudAccount = AccountMeta & {
  provider: CloudProvider;
  settings: AwsSettings | GcpSettings | MicrosoftSettings;
  sealed: string;
  caseIds?: string[];
};

/** What a client sees. `locked` holds the reason when the vault cannot open the account. */
export type CloudAccountView = AccountMeta & {
  provider: CloudProvider;
  settings: AwsSettings | GcpSettings | MicrosoftSettings;
  storedSecrets: string[];
  /** The cases attached to the account (#2308); empty for an unattached one. */
  caseIds: string[];
  locked?: string;
};

/**
 * An account the vault just erased or detached, without its secrets (#2347): what an audit or
 * custody entry may say about it. `caseIds` are the cases it was attached to BEFORE the change for
 * an erased account, and the cases it is still attached to for a detached one.
 */
export type ReleasedCloudAccount = Omit<StoredCloudAccount, "sealed" | "caseIds"> & { caseIds: string[] };

/** A create or edit request. On edit, an absent or empty secret keeps the stored one. */
export interface CloudAccountInput {
  name: string;
  provider: CloudProvider;
  settings: Record<string, unknown>;
  secrets: Record<string, unknown>;
}

const PEM_BEGIN = /^-----BEGIN [A-Z0-9 ]+-----$/;
const PEM_END = /^-----END [A-Z0-9 ]+-----$/;

/** Every non-empty body line of each PEM block in `text`: a log line can hold one line of a key. */
export function pemBodyLines(text: string): string[] {
  const out: string[] = [];
  let inPem = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (PEM_BEGIN.test(line)) inPem = true;
    else if (PEM_END.test(line)) inPem = false;
    else if (inPem && line) out.push(line);
  }
  return out;
}

function gcpKeyParts(json: string): string[] {
  try {
    const key = JSON.parse(json) as { private_key?: unknown; private_key_id?: unknown };
    const out: string[] = [];
    if (typeof key.private_key === "string") out.push(key.private_key, ...pemBodyLines(key.private_key));
    if (typeof key.private_key_id === "string") out.push(key.private_key_id);
    return out;
  } catch {
    return [];
  }
}

/** Every secret value one opened account holds, whole and in the pieces a log line could carry. */
export function secretsOfAccount(account: CloudCredential): string[] {
  const values = Object.values(account.secrets).filter(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  const out = [...values];
  if (account.provider === "microsoft" && account.secrets.certificatePem) {
    out.push(...pemBodyLines(account.secrets.certificatePem));
  }
  if (account.provider === "gcp" && account.secrets.serviceAccountKeyJson) {
    out.push(...gcpKeyParts(account.secrets.serviceAccountKeyJson));
  }
  return out;
}

/** The names of the secrets an account holds, for the view. */
export function storedSecretNames(secrets: object): string[] {
  return Object.entries(secrets)
    .filter(([, v]) => typeof v === "string" && v.length > 0)
    .map(([k]) => k)
    .sort();
}
