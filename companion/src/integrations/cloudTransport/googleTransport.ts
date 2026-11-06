import { Gaxios } from "gaxios";
import type { CloudTransport } from "./cloudAgent.js";

// Google over the cloud transport (#2310). google-auth-library sends the token exchange
// (oauth2.googleapis.com, or the key's token_uri) through the auth client's transporter, so one
// transporter carries both the token and the data:
//
//   const auth = new GoogleAuth({ credentials, scopes, ...googleAuthOptions(transport) });
//   const client = await auth.getClient();
//   await client.request({ url: "https://logging.googleapis.com/v2/entries:list", method: "POST", data });
//
// For a client built directly (JWT, Impersonated — give BOTH the source and the target client the
// options) spread googleClientOptions(transport) into its constructor options.
//
// @google-cloud/logging is deliberately not used: its gRPC transport has its own TLS and proxy
// handling, and its REST fallback sets its own agent on every request. Logging's entries:list is a
// single REST call, made with the auth client above.

export interface GoogleClientOptions {
  transporter: Gaxios;
}

export function googleClientOptions(transport: CloudTransport): GoogleClientOptions {
  const transporter = new Gaxios({ agent: transport.agent });
  // A library that sets its own per-request agent would bypass the default above; the interceptor
  // puts the transport's agent back on every request this transporter sends.
  transporter.interceptors.request.add({
    resolved: async (options) => ({ ...options, agent: transport.agent }),
  });
  return { transporter };
}

export function googleAuthOptions(transport: CloudTransport): { clientOptions: GoogleClientOptions } {
  return { clientOptions: googleClientOptions(transport) };
}
