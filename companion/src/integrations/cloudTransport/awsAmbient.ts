import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";
import { awsClientConfig, type AwsTransportConfig } from "./awsTransport.js";
import type { CloudTransport } from "./cloudAgent.js";
import { assertOnLinkMetadataEnv } from "./metadataEndpoints.js";

// The machine's own AWS credentials ("ambient": env keys, shared profiles, SSO, web identity, ECS/EKS
// container credentials, EC2 instance role) over the cloud transport (#2309 review).
//
// fromTemporaryCredentials without masterCredentials builds the default chain with NO options, so a
// profile that assumes a role, an SSO profile or a web-identity token would call STS / SSO / SSO-OIDC
// on the default trust and no proxy. This chain hands the transport to every inner client:
//   - `clientConfig` reaches fromIni's role assumer, fromSSO's SSO client and its token refresh,
//     fromTokenFile's STS client and the login provider;
//   - `parentClientConfig` reaches the one path that does not take clientConfig: a shared-config
//     profile with web_identity_token_file (the nested STS client falls back to its requestHandler).
// What stays DIRECT, by design (metadataEndpoints.ts): EC2 IMDS and the ECS/EKS container endpoints,
// all link-local. Their override variables are refused when they point elsewhere — including
// AWS_CONTAINER_CREDENTIALS_FULL_URI, which may name any https host and is fetched by the SDK's own
// HTTP client. A credential_process runs the operator's configured local program; whatever network
// that program uses is its own and outside the companion.

export const AWS_METADATA_ENV = [
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
] as const;

export interface AwsAmbientOptions {
  region?: string;
  /** The transport's client config; a test passes a recording request handler instead. */
  clientConfig?: AwsTransportConfig | { requestHandler: unknown };
  env?: NodeJS.ProcessEnv;
}

/** The ambient credential chain with the transport on every client it builds. Lazy: no I/O until called. */
export function awsAmbientCredentials(
  transport: CloudTransport,
  options: AwsAmbientOptions = {},
): AwsCredentialIdentityProvider {
  const config = (options.clientConfig ?? awsClientConfig(transport)) as AwsTransportConfig;
  const env = options.env ?? process.env;
  const chain = fromNodeProviderChain({
    clientConfig: { ...config, ...(options.region ? { region: options.region } : {}) },
    parentClientConfig: { ...config, ...(options.region ? { region: options.region } : {}) },
  });
  return async (props?: Parameters<AwsCredentialIdentityProvider>[0]): Promise<AwsCredentialIdentity> => {
    // Checked at use, not at build, so it reads the environment the run actually has.
    assertOnLinkMetadataEnv(env, AWS_METADATA_ENV);
    return chain(props);
  };
}
