import { Gaxios } from "gaxios";
import {
  GoogleAuth,
  Impersonated,
  type AuthClient,
  type GoogleAuthOptions,
  type JWTInput,
} from "google-auth-library";
import type { CloudTransport } from "./cloudAgent.js";

// Google over the cloud transport (#2310). google-auth-library sends the token exchange
// (oauth2.googleapis.com), the IAM Credentials call that impersonation makes
// (iamcredentials.googleapis.com) and the data calls through each auth client's transporter, so
// every client in the chain needs the transport's transporter:
//
//   const auth = createGoogleAuth(transport, { credentials, scopes });
//   const client = await auth.getClient();
//   await client.request({ url: "https://logging.googleapis.com/v2/entries:list", method: "POST", data });
//
// or, for impersonation built from a stored key:
//
//   const client = googleImpersonatedClient(transport, { sourceCredentials, targetPrincipal, targetScopes });
//
// Do NOT hand googleClientOptions to a plain `new GoogleAuth({ clientOptions })`: for
// impersonated_service_account JSON the library builds the source and target clients itself and
// drops clientOptions, so the token refresh, the IAM call and the data calls would leave on the
// default trust with no proxy. createGoogleAuth closes that path.
//
// @google-cloud/logging is deliberately not used: its gRPC transport has its own TLS and proxy
// handling, and its REST fallback sets its own agent on every request. Logging's entries:list is a
// single REST call, made with the auth client above.

export interface GoogleClientOptions {
  transporter: Gaxios;
}

/** Transporter options for ONE client built directly (JWT, UserRefreshClient). */
export function googleClientOptions(transport: CloudTransport): GoogleClientOptions {
  const transporter = new Gaxios({ agent: transport.agent });
  // A library that sets its own per-request agent would bypass the default above; the interceptor
  // puts the transport's agent back on every request this transporter sends.
  transporter.interceptors.request.add({
    resolved: async (options) => ({ ...options, agent: transport.agent }),
  });
  return { transporter };
}

/** What the library's validated Impersonated holds; read back so its own parsing stays the authority. */
interface ImpersonationTarget {
  targetPrincipal: string;
  targetScopes: string[];
  delegates: string[];
  lifetime: number;
}

/**
 * GoogleAuth whose every client — including both halves of impersonated_service_account JSON —
 * carries the cloud transport.
 */
class CloudGoogleAuth extends GoogleAuth {
  readonly #transport: CloudTransport;

  constructor(transport: CloudTransport, options: GoogleAuthOptions) {
    super({ ...options, clientOptions: { ...options.clientOptions, ...googleClientOptions(transport) } });
    this.#transport = transport;
  }

  fromImpersonatedJSON(json: Parameters<GoogleAuth["fromImpersonatedJSON"]>[0]): Impersonated {
    // The library validates the JSON and extracts the target; its clients are discarded unused
    // (constructing them makes no request) and rebuilt with the transport on both sides.
    const target = super.fromImpersonatedJSON(json) as unknown as ImpersonationTarget;
    // super has already refused JSON without source_credentials; the guard is for the type only.
    if (!json.source_credentials) throw new Error("impersonated credentials have no source_credentials");
    const sourceClient = this.fromJSON(json.source_credentials, googleClientOptions(this.#transport));
    return new Impersonated({
      sourceClient,
      targetPrincipal: target.targetPrincipal,
      targetScopes: target.targetScopes,
      delegates: target.delegates,
      lifetime: target.lifetime,
      ...googleClientOptions(this.#transport),
    });
  }
}

/** A GoogleAuth whose clients all go through the transport. Any clientOptions transporter is replaced. */
export function createGoogleAuth(transport: CloudTransport, options: GoogleAuthOptions = {}): GoogleAuth {
  return new CloudGoogleAuth(transport, options);
}

export interface GoogleImpersonationOptions {
  /** The stored credential that calls the IAM Credentials API (a service-account key). */
  sourceCredentials: JWTInput;
  /** Scopes for the source token. Generating an access token needs cloud-platform. */
  sourceScopes?: string[];
  targetPrincipal: string;
  targetScopes: string[];
  delegates?: string[];
  lifetime?: number;
}

const CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

/** Impersonated credentials with the transport on the source client AND the target client. */
export function googleImpersonatedClient(
  transport: CloudTransport,
  options: GoogleImpersonationOptions,
): Impersonated {
  const sourceAuth = createGoogleAuth(transport, { scopes: options.sourceScopes ?? [CLOUD_PLATFORM_SCOPE] });
  const sourceClient: AuthClient = sourceAuth.fromJSON(
    options.sourceCredentials,
    googleClientOptions(transport),
  );
  return new Impersonated({
    sourceClient,
    targetPrincipal: options.targetPrincipal,
    targetScopes: options.targetScopes,
    delegates: options.delegates ?? [],
    lifetime: options.lifetime ?? 3600,
    ...googleClientOptions(transport),
  });
}
