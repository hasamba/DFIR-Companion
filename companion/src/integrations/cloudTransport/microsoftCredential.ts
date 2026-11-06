import { ClientCertificateCredential, type TokenCredential } from "@azure/identity";
import type { MicrosoftSettings } from "../cloudAccounts/types.js";
import { azureCredentialOptions } from "./azureTransport.js";
import type { CloudTransport } from "./cloudAgent.js";

// The one Microsoft sign-in the companion makes (#2309 read check, #2315 collection): app-only,
// certificate, over the cloud transport — the token requests to login.microsoftonline.com go
// through the same CA, insecure and proxy policy as the data calls. The PEM comes from
// cloudAccounts/microsoftCertificate.ts (stored PEM, or a PFX opened in memory).

export const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
export const ARM_SCOPE = "https://management.azure.com/.default";

/** Signing in proved nothing came back: fixed text, never a secret. */
export class MicrosoftTokenError extends Error {
  constructor(message = "Microsoft returned no access token") {
    super(message);
    this.name = "MicrosoftTokenError";
  }
}

export function microsoftCredential(
  settings: MicrosoftSettings,
  certificatePem: string,
  transport: CloudTransport,
): ClientCertificateCredential {
  return new ClientCertificateCredential(
    settings.tenantId,
    settings.clientId,
    { certificate: certificatePem },
    azureCredentialOptions(transport),
  );
}

/** A bearer token for `scope`. The credential caches and refreshes it. */
export async function accessToken(
  credential: TokenCredential,
  scope: string,
  signal?: AbortSignal,
): Promise<string> {
  const token = await credential.getToken(scope, signal ? { abortSignal: signal } : {});
  if (!token?.token) throw new MicrosoftTokenError();
  return token.token;
}
