// The real clients a cloud read check uses (#2309), built from an opened account over the cloud
// transport (#2310). The only file of the check that signs in; the check modules take the
// structural interfaces these return, so tests hand them mocks instead.
//
// Every client and every credential provider gets the transport — the token endpoints included:
// AWS STS (the assume-role provider's own client), login.microsoftonline.com, oauth2.googleapis.com
// and iamcredentials.googleapis.com.

import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { EC2Client } from "@aws-sdk/client-ec2";
import { S3Client } from "@aws-sdk/client-s3";
import { STSClient } from "@aws-sdk/client-sts";
import type {
  AwsSecrets,
  AwsSettings,
  GcpSecrets,
  GcpSettings,
  MicrosoftSettings,
} from "../cloudAccounts/types.js";
import type { CloudTransport } from "../cloudTransport/cloudAgent.js";
import { awsClientConfig, type AwsTransportConfig } from "../cloudTransport/awsTransport.js";
import { accessToken, GRAPH_SCOPE, microsoftCredential } from "../cloudTransport/microsoftCredential.js";
import { cloudFetch, type CloudFetch } from "../cloudTransport/cloudFetch.js";
import {
  GoogleAccountSetupError,
  LOGGING_READ_SCOPE,
  googleAccountClient,
} from "../cloudTransport/googleAccountAuth.js";
import { awsAccountCredentials, DEFAULT_AWS_REGION } from "../cloudTransport/awsCredentials.js";
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

const ROLE_SESSION_NAME = "dfir-companion-read-check";

function awsClients(
  settings: AwsSettings,
  secrets: AwsSecrets,
  wire: CheckWire,
  transport: CloudTransport,
): AwsCheckClients {
  const config = wire.awsConfig as AwsTransportConfig;
  const credentials = awsAccountCredentials(settings, secrets, {
    config,
    transport,
    roleSessionName: ROLE_SESSION_NAME,
    fail: (message) => new CheckSetupError(message),
  });
  const region = settings.region || DEFAULT_AWS_REGION;
  return {
    sts: new STSClient({ region, credentials, ...config }),
    cloudtrail: new CloudTrailClient({ region, credentials, ...config }),
    // The trail bucket may live in another region; the client follows the redirect.
    s3: new S3Client({ region, credentials, followRegionRedirects: true, ...config }),
    ec2: new EC2Client({ region, credentials, ...config }),
  };
}

function microsoftClients(
  settings: MicrosoftSettings,
  certificatePem: string,
  transport: CloudTransport,
  wire: CheckWire,
): MicrosoftCheckClients {
  const credential = microsoftCredential(settings, certificatePem, transport);
  return {
    getToken: () => accessToken(credential, GRAPH_SCOPE, AbortSignal.timeout(CHECK_CALL_TIMEOUT_MS)),
    fetch: wire.fetch,
  };
}

async function gcpClient(
  settings: GcpSettings,
  secrets: GcpSecrets,
  transport: CloudTransport,
): Promise<GcpRequester> {
  try {
    return await googleAccountClient(settings, secrets, transport, [LOGGING_READ_SCOPE]);
  } catch (err) {
    // The check words its own setup errors (readCheckWording.ts matches CheckSetupError).
    if (err instanceof GoogleAccountSetupError) throw new CheckSetupError(err.message);
    throw err;
  }
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
