// The real wire of the Microsoft collector (#2315), over the cloud transport (#2310).
//
//   sign-in    ClientCertificateCredential (azureCredentialOptions) — the account's PEM, or its PFX
//              opened IN MEMORY (cloudAccounts/microsoftCertificate.ts); the key never hits the disk
//   Graph      cloudFetch(transport) with a graph.microsoft.com token; the body read as raw bytes
//   ARM        MonitorClient(credential, azureClientOptions) — its own pipeline, so the bearer token
//              (management.azure.com scope), retries and the transport policy all apply — sending
//              the request directly, because a page must be saved byte for byte (see
//              azureActivitySource.ts for why the SDK's paged iterator is not used)

import { MonitorClient } from "@azure/arm-monitor";
import { createDefaultHttpClient, createPipelineRequest } from "@azure/core-rest-pipeline";
import type { OpenCloudAccount } from "../cloudAccounts/types.js";
import { microsoftCertificatePem } from "../cloudAccounts/microsoftCertificate.js";
import { azureClientOptions } from "../cloudTransport/azureTransport.js";
import type { CloudTransport } from "../cloudTransport/cloudAgent.js";
import { cloudFetch } from "../cloudTransport/cloudFetch.js";
import { accessToken, GRAPH_SCOPE, microsoftCredential } from "../cloudTransport/microsoftCredential.js";
import type { HttpAnswer, HttpCall } from "./microsoftHttp.js";
import type { MicrosoftWire } from "./microsoftProvider.js";

/** One request's ceiling: a slow page is retried by a resume, never waited on forever. */
const CALL_TIMEOUT_MS = 120_000;

function signalFor(signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(CALL_TIMEOUT_MS);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function lowerHeaders(entries: Iterable<[string, string]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of entries) out[k.toLowerCase()] = v;
  return out;
}

export function microsoftWire(
  account: Extract<OpenCloudAccount, { provider: "microsoft" }>,
  transport: CloudTransport,
): MicrosoftWire {
  const pem = microsoftCertificatePem(account.settings, account.secrets);
  const credential = microsoftCredential(account.settings, pem, transport);
  const fetch = cloudFetch(transport);
  const graph: HttpCall = async (req) => {
    const signal = signalFor(req.signal);
    const token = await accessToken(credential, GRAPH_SCOPE, signal);
    const res = await fetch(req.url, {
      method: req.method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        ...(req.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      ...(req.body !== undefined ? { body: req.body } : {}),
      signal,
    });
    const body = new Uint8Array(await res.arrayBuffer());
    return { status: res.status, headers: lowerHeaders(res.headers.entries()), body };
  };
  const monitor = new MonitorClient(credential, azureClientOptions(transport));
  const httpClient = createDefaultHttpClient();
  const arm: HttpCall = async (req): Promise<HttpAnswer> => {
    const res = await monitor.pipeline.sendRequest(
      httpClient,
      createPipelineRequest({
        url: req.url,
        method: req.method,
        abortSignal: signalFor(req.signal),
        ...(req.body !== undefined ? { body: req.body } : {}),
      }),
    );
    const headers = lowerHeaders([...res.headers].map(([k, v]) => [k, String(v)] as [string, string]));
    return { status: res.status, headers, body: new TextEncoder().encode(res.bodyAsText ?? "") };
  };
  return { graph, arm };
}
