import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Compute, Impersonated, JWT, UserRefreshClient, type AuthClient } from "google-auth-library";
import type { CloudTransport } from "./cloudAgent.js";
import { CloudTransportError } from "./destinationTls.js";
import { createGoogleAuth, googleClientOptions } from "./googleTransport.js";
import { assertOnLinkMetadataEnv } from "./metadataEndpoints.js";

// The machine's own Google credentials (Application Default Credentials) over the cloud transport
// (#2309 review), and impersonation built on them.
//
// createGoogleAuth gives every client it builds the transport's transporter, so these reach Google
// through the transport: a service-account key file (JWT → oauth2.googleapis.com), a gcloud user
// login (UserRefreshClient → oauth2.googleapis.com), impersonated_service_account JSON (both halves,
// see googleTransport.ts), and every DATA call and the IAM generateAccessToken call made with them.
//
// What stays DIRECT, by design: on GCE/GKE the token comes from the metadata server
// (metadata.google.internal / 169.254.169.254) through gcp-metadata's own client — link-local, never
// proxied (metadataEndpoints.ts). GCE_METADATA_HOST / GCE_METADATA_IP may not move it off-link.
//
// Refused: external-account configurations (workload identity federation, external_account and
// external_account_authorized_user). Their subject-token suppliers fetch from URLs, cloud metadata
// or executables with their own clients, and their STS exchange would leave the transport's control.
// The credential file is read FIRST, so such a configuration is refused before the library builds
// anything from it; any client type not on the allow-list below is refused as well.
//
// The project id is passed in: without it the library looks it up by running the gcloud CLI and
// asking the metadata server, which is slow and not needed for a run that already knows its project.

export const GOOGLE_METADATA_ENV = ["GCE_METADATA_HOST", "GCE_METADATA_IP"] as const;

const CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

function allowed(client: AuthClient): boolean {
  return (
    client instanceof JWT ||
    client instanceof UserRefreshClient ||
    client instanceof Impersonated ||
    client instanceof Compute
  );
}

const EXTERNAL_TYPES = new Set(["external_account", "external_account_authorized_user"]);
const EXTERNAL_REFUSAL =
  "The machine's Google credentials are an external account (workload identity federation). " +
  "Cloud collection cannot send that sign-in through the cloud proxy and TLS settings, so it " +
  "refuses it. Store a service-account key on the account instead.";

/** Where ADC reads its credential file: the env variable, else gcloud's well-known file. */
function adcFile(env: NodeJS.ProcessEnv): string {
  const explicit = env.GOOGLE_APPLICATION_CREDENTIALS?.trim();
  if (explicit) return explicit;
  const base =
    env.CLOUDSDK_CONFIG?.trim() ||
    (process.platform === "win32" ? join(env.APPDATA ?? "", "gcloud") : join(homedir(), ".config", "gcloud"));
  return join(base, "application_default_credentials.json");
}

/** The `type` of the ADC credential file, or undefined when there is none (the library reports it). */
function adcFileType(env: NodeJS.ProcessEnv): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(adcFile(env), "utf8")) as { type?: unknown };
    return typeof parsed.type === "string" ? parsed.type : undefined;
  } catch {
    return undefined;
  }
}

export interface GoogleAmbientOptions {
  scopes: string[];
  /** The project the run reads; saves the library's gcloud and metadata lookups. */
  projectId?: string;
  env?: NodeJS.ProcessEnv;
}

/** The ADC client, with the transport on every non-metadata request it makes. */
export async function googleAmbientClient(
  transport: CloudTransport,
  options: GoogleAmbientOptions,
): Promise<AuthClient> {
  const env = options.env ?? process.env;
  assertOnLinkMetadataEnv(env, GOOGLE_METADATA_ENV);
  const type = adcFileType(env);
  if (type && EXTERNAL_TYPES.has(type)) throw new CloudTransportError(EXTERNAL_REFUSAL);
  const auth = createGoogleAuth(transport, {
    scopes: options.scopes,
    ...(options.projectId ? { projectId: options.projectId } : {}),
  });
  const client = await auth.getClient();
  if (!allowed(client)) throw new CloudTransportError(EXTERNAL_REFUSAL);
  return client;
}

export interface GoogleAmbientImpersonationOptions {
  targetPrincipal: string;
  targetScopes: string[];
  projectId?: string;
  env?: NodeJS.ProcessEnv;
}

/** Impersonation whose source is the machine's own credentials; transport on both sides. */
export async function googleAmbientImpersonatedClient(
  transport: CloudTransport,
  options: GoogleAmbientImpersonationOptions,
): Promise<Impersonated> {
  const sourceClient = await googleAmbientClient(transport, {
    scopes: [CLOUD_PLATFORM_SCOPE],
    projectId: options.projectId,
    env: options.env,
  });
  return new Impersonated({
    sourceClient,
    targetPrincipal: options.targetPrincipal,
    targetScopes: options.targetScopes,
    delegates: [],
    lifetime: 3600,
    ...googleClientOptions(transport),
  });
}
