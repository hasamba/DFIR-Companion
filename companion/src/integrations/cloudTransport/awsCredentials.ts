import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import type { AwsSecrets, AwsSettings } from "../cloudAccounts/types.js";
import type { CloudTransport } from "./cloudAgent.js";
import type { AwsTransportConfig } from "./awsTransport.js";
import { awsAmbientCredentials } from "./awsAmbient.js";

// How an AWS cloud account becomes SDK credentials (#2309, shared with collection #2313): an access
// key on its own, or AssumeRole with a stored access key or the machine's ambient credentials as the
// base. The transport reaches every client involved — the assume-role provider's own STS client is
// the token path — and an ambient base is the transport-aware chain, never the SDK's default one.

export const DEFAULT_AWS_REGION = "us-east-1";

export type AwsCredentials =
  | { accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  | ReturnType<typeof fromTemporaryCredentials>;

export interface AwsCredentialOptions {
  /** The client config every client gets (the transport, or a test's recording handler). */
  config: AwsTransportConfig | { requestHandler: unknown };
  transport: CloudTransport;
  /** Shows in the role's CloudTrail entries: who assumed it, and why. */
  roleSessionName: string;
  /** An account that cannot be used as stored: the caller's own error type, fixed text only. */
  fail: (message: string) => Error;
}

/** Refresh role credentials this long before they expire: a collection outlives one session. */
const REFRESH_BEFORE_MS = 5 * 60_000;

/**
 * One AssumeRole at a time, shared by every client built on it (each would otherwise assume the role
 * on its own). A failed attempt is forgotten, and credentials close to their expiry are fetched
 * again, so a collection running for hours keeps signing.
 */
export function onePerSession<P, T extends { expiration?: Date }>(
  provider: (props?: P) => Promise<T>,
  nowMs: () => number = Date.now,
): (props?: P) => Promise<T> {
  let pending: Promise<T> | undefined;
  let expiresAt = Infinity;
  return (props) => {
    if (pending && expiresAt - REFRESH_BEFORE_MS <= nowMs()) pending = undefined;
    if (!pending) expiresAt = Infinity; // until the new credentials say otherwise
    pending ??= provider(props).then(
      (value) => {
        expiresAt = value.expiration ? value.expiration.getTime() : Infinity;
        return value;
      },
      (err: unknown) => {
        pending = undefined;
        throw err;
      },
    );
    return pending;
  };
}

/** The credentials of an AWS account, over the transport. Lazy: nothing is sent until a client signs. */
export function awsAccountCredentials(
  settings: AwsSettings,
  secrets: AwsSecrets,
  opts: AwsCredentialOptions,
): AwsCredentials {
  const { accessKeyId, secretAccessKey, sessionToken } = secrets;
  const keys =
    accessKeyId && secretAccessKey
      ? { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) }
      : undefined;
  if (settings.authMode === "access-key") {
    if (!keys) throw opts.fail("the account has no stored access key");
    return keys;
  }
  if (!settings.roleArn) throw opts.fail("the account has no role ARN");
  const ambient = settings.baseCredential === "ambient";
  if (!ambient && !keys) throw opts.fail("the account has no stored access key to assume the role with");
  const region = settings.region || DEFAULT_AWS_REGION;
  const masterCredentials = ambient
    ? awsAmbientCredentials(opts.transport, { region, clientConfig: opts.config })
    : keys;
  return onePerSession(
    fromTemporaryCredentials({
      params: {
        RoleArn: settings.roleArn,
        RoleSessionName: opts.roleSessionName,
        DurationSeconds: settings.sessionSeconds ?? 3600,
        ...(secrets.externalId ? { ExternalId: secrets.externalId } : {}),
      },
      masterCredentials,
      clientConfig: { region, ...(opts.config as AwsTransportConfig) },
    }),
  );
}
