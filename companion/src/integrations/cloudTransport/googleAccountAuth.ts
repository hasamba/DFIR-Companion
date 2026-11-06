// A Google auth client for a stored GCP cloud account, over the cloud transport (#2310). Shared by
// the read check (#2309, cloudCheck/checkClients.ts) and live collection (#2314): the same three
// account shapes — a service-account key, impersonation from a stored key, impersonation from the
// machine's own credentials — signed in the same way, with only the scopes differing.
//
// Never a plain GoogleAuth: createGoogleAuth / googleImpersonatedClient /
// googleAmbientImpersonatedClient put the transport on every client in the chain.

import type { AuthClient, JWTInput } from "google-auth-library";
import type { GcpSecrets, GcpSettings } from "../cloudAccounts/types.js";
import type { CloudTransport } from "./cloudAgent.js";
import { createGoogleAuth, googleImpersonatedClient } from "./googleTransport.js";
import { googleAmbientImpersonatedClient } from "./googleAmbient.js";

/** An account that cannot sign in as stored. The message is fixed text, never a secret. */
export class GoogleAccountSetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GoogleAccountSetupError";
  }
}

export const LOGGING_READ_SCOPE = "https://www.googleapis.com/auth/logging.read";
export const STORAGE_READ_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only";

/** The stored service-account key, parsed. */
export function parseGoogleKey(json: string | undefined): JWTInput {
  if (!json) throw new GoogleAccountSetupError("the account has no stored service-account key");
  try {
    return JSON.parse(json) as JWTInput;
  } catch {
    // A JSON parse error quotes part of its input, and this input is a private key.
    throw new GoogleAccountSetupError("the stored service-account key is not valid JSON");
  }
}

/** The auth client for `settings`, every hop of it over `transport`. */
export async function googleAccountClient(
  settings: GcpSettings,
  secrets: GcpSecrets,
  transport: CloudTransport,
  scopes: string[],
): Promise<AuthClient> {
  if (settings.authMode === "service-account-key") {
    const auth = createGoogleAuth(transport, {
      credentials: parseGoogleKey(secrets.serviceAccountKeyJson),
      scopes,
      // Known already; without it the library runs the gcloud CLI and asks the metadata server.
      projectId: settings.projectId,
    });
    return await auth.getClient();
  }
  const targetPrincipal = settings.targetServiceAccount;
  if (!targetPrincipal)
    throw new GoogleAccountSetupError("the account names no service account to impersonate");
  if (settings.baseCredential === "service-account-key") {
    return googleImpersonatedClient(transport, {
      sourceCredentials: parseGoogleKey(secrets.serviceAccountKeyJson),
      targetPrincipal,
      targetScopes: scopes,
    });
  }
  // Ambient base: the machine's own credentials call the IAM Credentials API, through the transport;
  // only a GCE metadata token stays direct (see googleAmbient.ts).
  return googleAmbientImpersonatedClient(transport, {
    targetPrincipal,
    targetScopes: scopes,
    projectId: settings.projectId,
  });
}
