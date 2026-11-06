import type { Agent as HttpsAgent } from "node:https";
import { NodeHttpHandler } from "@smithy/node-http-handler";
import type { CloudTransport } from "./cloudAgent.js";

// AWS SDK v3 over the cloud transport (#2310). Spread the result into EVERY client's config AND into
// every credential provider's `clientConfig` — the provider's own STS client is the token path:
//
//   const config = awsClientConfig(transport);
//   const credentials = fromTemporaryCredentials({ params: { RoleArn }, clientConfig: config });
//   new CloudTrailClient({ region, credentials, ...config });
//
// A provider left without it would call sts.amazonaws.com (or the regional STS) on the default
// trust and no proxy, which is exactly the gap this issue closes. The SDK `logger` option is never
// set here: the @smithy/core releases available at the time carry a deprecation for a bug in custom
// logger redaction.

export interface AwsTransportConfig {
  requestHandler: NodeHttpHandler;
}

export function awsClientConfig(transport: CloudTransport): AwsTransportConfig {
  // The agent is a Node http.Agent decided per host; NodeHttpHandler takes any agent with destroy().
  const agent = transport.agent as unknown as HttpsAgent;
  return { requestHandler: new NodeHttpHandler({ httpsAgent: agent, httpAgent: agent }) };
}
