// The real clients a cloud read check uses (#2309), built from an opened account over the cloud
// transport (#2310). The only file of the check that signs in; the check modules take the
// structural interfaces these return, so tests hand them mocks instead.
//
// Every client and every credential provider gets the transport — the token endpoints included:
// AWS STS (the assume-role provider's own client), login.microsoftonline.com, oauth2.googleapis.com
// and iamcredentials.googleapis.com.

import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { S3Client } from "@aws-sdk/client-s3";
import { STSClient } from "@aws-sdk/client-sts";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import { ClientCertificateCredential } from "@azure/identity";
import type { JWTInput } from "google-auth-library";
import type {
  AwsSecrets,
  AwsSettings,
  GcpSecrets,
  GcpSettings,
  MicrosoftSettings,
} from "../cloudAccounts/types.js";
import type { CloudTransport } from "../cloudTransport/cloudAgent.js";
import { awsClientConfig, type AwsTransportConfig } from "../cloudTransport/awsTransport.js";
import { azureCredentialOptions } from "../cloudTransport/azureTransport.js";
import { cloudFetch, type CloudFetch } from "../cloudTransport/cloudFetch.js";
import { createGoogleAuth, googleImpersonatedClient } from "../cloudTransport/googleTransport.js";
import { googleAmbientImpersonatedClient } from "../cloudTransport/googleAmbient.js";
import { awsAmbientCredentials } from "../cloudTransport/awsAmbient.js";
import type { AwsCheckClients } from "./awsReadCheck.js";
import type { GcpRequester } from "./gcpReadCheck.js";
import type { MicrosoftCheckClients } from "./microsoftReadCheck.js";
import { CHECK_CALL_TIMEOUT_MS } from "./readCheckTypes.js";

/** An account that cannot be checked as stored. The message is fixed text, never a secret. */
export class CheckSetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CheckSetupError";
  }
}

export interface CheckClientFactory {
  aws(settings: AwsSettings, secrets: AwsSecrets): AwsCheckClients;
  microsoft(settings: MicrosoftSettings, certificatePem: string): MicrosoftCheckClients;
  gcp(settings: GcpSettings, secrets: GcpSecrets): Promise<GcpRequester>;
}

/** The wire the factory sends on. Defaults to the transport; a test records the calls instead. */
export interface CheckWire {
  awsConfig: AwsTransportConfig | { requestHandler: unknown };
  fetch: CloudFetch;
}

const DEFAULT_AWS_REGION = "us-east-1";
const ROLE_SESSION_NAME = "dfir-companion-read-check";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const LOGGING_READ_SCOPE = "https://www.googleapis.com/auth/logging.read";

function awsCredentials(
  settings: AwsSettings,
  secrets: AwsSecrets,
  config: CheckWire["awsConfig"],
  transport: CloudTransport,
) {
  const { accessKeyId, secretAccessKey, sessionToken } = secrets;
  const keys =
    accessKeyId && secretAccessKey
      ? { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) }
      : undefined;
  if (settings.authMode === "access-key") {
    if (!keys) throw new CheckSetupError("the account has no stored access key");
    return keys;
  }
  if (!settings.roleArn) throw new CheckSetupError("the account has no role ARN");
  const ambient = settings.baseCredential === "ambient";
  if (!ambient && !keys)
    throw new CheckSetupError("the account has no stored access key to assume the role with");
  const region = settings.region || DEFAULT_AWS_REGION;
  // An ambient base is the machine's own chain, built with the transport on every inner client —
  // never fromTemporaryCredentials' option-less default chain (see cloudTransport/awsAmbient.ts).
  const masterCredentials = ambient
    ? awsAmbientCredentials(transport, { region, clientConfig: config })
    : keys;
  return onePerCheck(
    fromTemporaryCredentials({
      params: {
        RoleArn: settings.roleArn,
        RoleSessionName: ROLE_SESSION_NAME,
        DurationSeconds: settings.sessionSeconds ?? 3600,
        ...(secrets.externalId ? { ExternalId: secrets.externalId } : {}),
      },
      masterCredentials,
      // The provider's own STS client is the token path: it goes through the transport too.
      clientConfig: { region, ...(config as AwsTransportConfig) },
    }),
  );
}

/**
 * One AssumeRole for the whole check, shared by the STS, CloudTrail and S3 clients (each would
 * otherwise assume the role on its own). A check lasts minutes; the shortest session is 15.
 */
function onePerCheck<P, T>(provider: (props?: P) => Promise<T>): (props?: P) => Promise<T> {
  let pending: Promise<T> | undefined;
  return (props) => {
    pending ??= provider(props).catch((err: unknown) => {
      pending = undefined;
      throw err;
    });
    return pending;
  };
}

function awsClients(
  settings: AwsSettings,
  secrets: AwsSecrets,
  wire: CheckWire,
  transport: CloudTransport,
): AwsCheckClients {
  const config = wire.awsConfig as AwsTransportConfig;
  const credentials = awsCredentials(settings, secrets, config, transport);
  const region = settings.region || DEFAULT_AWS_REGION;
  return {
    sts: new STSClient({ region, credentials, ...config }),
    cloudtrail: new CloudTrailClient({ region, credentials, ...config }),
    // The trail bucket may live in another region; the client follows the redirect.
    s3: new S3Client({ region, credentials, followRegionRedirects: true, ...config }),
  };
}

function microsoftClients(
  settings: MicrosoftSettings,
  certificatePem: string,
  transport: CloudTransport,
  wire: CheckWire,
): MicrosoftCheckClients {
  const credential = new ClientCertificateCredential(
    settings.tenantId,
    settings.clientId,
    { certificate: certificatePem },
    azureCredentialOptions(transport),
  );
  return {
    getToken: async () => {
      const token = await credential.getToken(GRAPH_SCOPE, {
        abortSignal: AbortSignal.timeout(CHECK_CALL_TIMEOUT_MS),
      });
      if (!token?.token) throw new CheckSetupError("Microsoft returned no access token");
      return token.token;
    },
    fetch: wire.fetch,
  };
}

function parseKey(json: string | undefined): JWTInput {
  if (!json) throw new CheckSetupError("the account has no stored service-account key");
  try {
    return JSON.parse(json) as JWTInput;
  } catch {
    // A JSON parse error quotes part of its input, and this input is a private key.
    throw new CheckSetupError("the stored service-account key is not valid JSON");
  }
}

async function gcpClient(
  settings: GcpSettings,
  secrets: GcpSecrets,
  transport: CloudTransport,
): Promise<GcpRequester> {
  const scopes = [LOGGING_READ_SCOPE];
  if (settings.authMode === "service-account-key") {
    const auth = createGoogleAuth(transport, {
      credentials: parseKey(secrets.serviceAccountKeyJson),
      scopes,
      // Known already; without it the library runs the gcloud CLI and asks the metadata server.
      projectId: settings.projectId,
    });
    return await auth.getClient();
  }
  const targetPrincipal = settings.targetServiceAccount;
  if (!targetPrincipal) throw new CheckSetupError("the account names no service account to impersonate");
  if (settings.baseCredential === "service-account-key") {
    const sourceCredentials = parseKey(secrets.serviceAccountKeyJson);
    return googleImpersonatedClient(transport, {
      sourceCredentials,
      targetPrincipal,
      targetScopes: scopes,
    });
  }
  // Ambient base: the machine's own credentials call the IAM Credentials API, through the transport;
  // only a GCE metadata token stays direct (see cloudTransport/googleAmbient.ts).
  return googleAmbientImpersonatedClient(transport, {
    targetPrincipal,
    targetScopes: scopes,
    projectId: settings.projectId,
  });
}

/** The real clients, all over `transport`. `wire` replaces the AWS handler and Graph fetch in tests. */
export function createCheckClientFactory(
  transport: CloudTransport,
  wire: CheckWire = { awsConfig: awsClientConfig(transport), fetch: cloudFetch(transport) },
): CheckClientFactory {
  return {
    aws: (settings, secrets) => awsClients(settings, secrets, wire, transport),
    microsoft: (settings, pem) => microsoftClients(settings, pem, transport, wire),
    gcp: (settings, secrets) => gcpClient(settings, secrets, transport),
  };
}
