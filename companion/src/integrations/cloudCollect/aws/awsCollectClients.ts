// The real AWS clients a collection uses (#2313), built from an opened account over the cloud
// transport (#2310) — the only file of the AWS collector that signs in. Every client gets the
// transport's request handler, and so does the assume-role provider's own STS client (the token
// path); an ambient base credential is the transport-aware chain (cloudTransport/awsAmbient.ts).
// The credential is built once per session and shared by every client, regional ones included.

import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { EC2Client } from "@aws-sdk/client-ec2";
import { GuardDutyClient } from "@aws-sdk/client-guardduty";
import { S3Client } from "@aws-sdk/client-s3";
import { STSClient } from "@aws-sdk/client-sts";
import type { AwsSecrets, AwsSettings } from "../../cloudAccounts/types.js";
import type { CloudTransport } from "../../cloudTransport/cloudAgent.js";
import type { AwsTransportConfig } from "../../cloudTransport/awsTransport.js";
import { awsAccountCredentials, DEFAULT_AWS_REGION } from "../../cloudTransport/awsCredentials.js";
import type { AwsCollectClients } from "./awsCollectTypes.js";

const ROLE_SESSION_NAME = "dfir-companion-collect";

/** An account that cannot collect as stored. The message is fixed text, never a secret. */
export class AwsCollectSetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AwsCollectSetupError";
  }
}

export function createAwsCollectClients(
  settings: AwsSettings,
  secrets: AwsSecrets,
  transport: CloudTransport,
  config: AwsTransportConfig | { requestHandler: unknown },
): AwsCollectClients {
  const wire = config as AwsTransportConfig;
  const credentials = awsAccountCredentials(settings, secrets, {
    config,
    transport,
    roleSessionName: ROLE_SESSION_NAME,
    fail: (message) => new AwsCollectSetupError(message),
  });
  const region = settings.region || DEFAULT_AWS_REGION;
  const trails = new Map<string, CloudTrailClient>();
  const guardduty = new Map<string, GuardDutyClient>();
  return {
    sts: new STSClient({ region, credentials, ...wire }),
    s3: new S3Client({ region, credentials, followRegionRedirects: true, ...wire }),
    // #2363: ec2:DescribeRegions only — asked in the account's own region.
    ec2: new EC2Client({ region, credentials, ...wire }),
    cloudtrail(r: string) {
      let client = trails.get(r);
      if (!client) {
        client = new CloudTrailClient({ region: r, credentials, ...wire });
        trails.set(r, client);
      }
      return client;
    },
    guardduty(r: string) {
      let client = guardduty.get(r);
      if (!client) {
        client = new GuardDutyClient({ region: r, credentials, ...wire });
        guardduty.set(r, client);
      }
      return client;
    },
  };
}
