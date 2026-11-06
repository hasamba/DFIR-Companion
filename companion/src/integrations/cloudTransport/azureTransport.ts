import type { PipelinePolicy } from "@azure/core-rest-pipeline";
import type { CloudTransport } from "./cloudAgent.js";

// Azure SDK over the cloud transport (#2310). The same options object goes to the credential and to
// every ARM client, because @azure/identity sends its token requests (login.microsoftonline.com,
// including MSAL's metadata and token calls) through the same Azure pipeline:
//
//   const options = azureClientOptions(transport);
//   const credential = new ClientCertificateCredential(tenantId, clientId, { certificate }, options);
//   new MonitorClient(credential, subscriptionId, options);
//
// Microsoft Graph needs no SDK: call it with cloudFetch(transport) and a token from
// credential.getToken("https://graph.microsoft.com/.default").

export const CLOUD_TRANSPORT_POLICY = "dfirCloudTransport";

/**
 * Sets the transport's agent on every request, unconditionally. The pipeline's own proxyPolicy
 * (which would read HTTPS_PROXY) leaves a request that already has an agent alone, and the Node
 * client uses `request.agent` before any TLS settings — so CA, insecure and proxy all come from
 * the transport. The request object is mutated because that is the pipeline's contract.
 */
function transportPolicy(transport: CloudTransport): PipelinePolicy {
  return {
    name: CLOUD_TRANSPORT_POLICY,
    sendRequest: (request, next) => {
      request.agent = transport.agent;
      return next(request);
    },
  };
}

export interface AzureTransportOptions {
  additionalPolicies: { policy: PipelinePolicy; position: "perCall" | "perRetry" }[];
}

export function azureClientOptions(transport: CloudTransport): AzureTransportOptions {
  return { additionalPolicies: [{ policy: transportPolicy(transport), position: "perRetry" }] };
}

/** The credential options are the client options: one transport for the token and the data. */
export const azureCredentialOptions = azureClientOptions;
