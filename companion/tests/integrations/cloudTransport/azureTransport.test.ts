import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { MonitorClient } from "@azure/arm-monitor";
import { ClientCertificateCredential } from "@azure/identity";
import {
  createCloudTransport,
  type CloudTransport,
} from "../../../src/integrations/cloudTransport/cloudAgent.js";
import {
  azureClientOptions,
  azureCredentialOptions,
} from "../../../src/integrations/cloudTransport/azureTransport.js";
import { cloudFetch } from "../../../src/integrations/cloudTransport/cloudFetch.js";
import {
  makeTlsMaterial,
  startConnectProxy,
  startTlsServer,
  type ConnectProxy,
  type Route,
  type TlsMaterial,
  type TlsServer,
} from "../../helpers/cloudTlsHarness.js";

// Azure over the cloud transport (#2310): @azure/identity's token calls (MSAL's authority metadata
// and the token POST — login.microsoftonline.com in production) and the ARM data call both go
// through it. The authority host and the ARM endpoint are overridden to the local TLS server, and
// instance discovery is off so nothing asks the real login.microsoftonline.com.

const TENANT = "00000000-0000-0000-0000-00000000000a";
const SUBSCRIPTION = "00000000-0000-0000-0000-00000000000b";

const route: Route = (req, origin) => {
  if (req.path.startsWith(`/${TENANT}/v2.0/.well-known/openid-configuration`)) {
    return {
      body: JSON.stringify({
        issuer: `${origin}/${TENANT}/v2.0`,
        authorization_endpoint: `${origin}/${TENANT}/oauth2/v2.0/authorize`,
        token_endpoint: `${origin}/${TENANT}/oauth2/v2.0/token`,
        end_session_endpoint: `${origin}/${TENANT}/oauth2/v2.0/logout`,
        jwks_uri: `${origin}/${TENANT}/discovery/v2.0/keys`,
      }),
    };
  }
  if (req.path.startsWith(`/${TENANT}/oauth2/v2.0/token`)) {
    return {
      body: JSON.stringify({
        token_type: "Bearer",
        access_token: "test-access",
        expires_in: 3600,
        ext_expires_in: 3600,
      }),
    };
  }
  if (req.path.includes("/providers/Microsoft.Insights/eventtypes/management/values")) {
    return {
      body: JSON.stringify({
        value: [{ operationName: { value: "Microsoft.Compute/virtualMachines/write" } }],
      }),
    };
  }
  if (req.path.startsWith("/v1.0/auditLogs/directoryAudits")) return { body: JSON.stringify({ value: [] }) };
  return undefined;
};

let material: TlsMaterial;
let server: TlsServer;
let proxy: ConnectProxy;
let transport: CloudTransport | undefined;

beforeAll(async () => {
  material = makeTlsMaterial();
  server = await startTlsServer(material, route);
  proxy = await startConnectProxy(server.port);
});
afterEach(() => {
  transport?.close();
  transport = undefined;
  server.seen.length = 0;
  proxy.tunnels.length = 0;
});
afterAll(async () => {
  await proxy.close();
  await server.close();
  material.cleanup();
});

function credentialFor(t: CloudTransport, authorityHost: string): ClientCertificateCredential {
  // The test server's own key + certificate double as the app registration's PEM certificate.
  return new ClientCertificateCredential(
    TENANT,
    "00000000-0000-0000-0000-00000000000c",
    { certificate: material.keyPem + material.certPem },
    {
      ...azureCredentialOptions(t),
      authorityHost,
      disableInstanceDiscovery: true,
      retryOptions: { maxRetries: 0 },
    },
  );
}

async function listActivity(
  t: CloudTransport,
  authorityHost: string,
  armEndpoint: string,
): Promise<unknown[]> {
  const client = new MonitorClient(credentialFor(t, authorityHost), SUBSCRIPTION, {
    ...azureClientOptions(t),
    endpoint: armEndpoint,
    retryOptions: { maxRetries: 0 },
  });
  const out: unknown[] = [];
  for await (const e of client.activityLogs.list("eventTimestamp ge '2026-11-01T00:00:00Z'")) out.push(e);
  return out;
}

const kinds = (s: TlsServer) =>
  s.seen.map((r) =>
    r.path.includes("openid-configuration") ? "metadata" : r.path.includes("/token") ? "token" : "data",
  );

describe("Azure identity and ARM over the cloud transport", () => {
  it("carries the custom CA to the token requests and the ARM data request", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath });
    const events = await listActivity(transport, server.origin, server.origin);
    expect(events).toHaveLength(1);
    expect(kinds(server)).toContain("token");
    expect(kinds(server).at(-1)).toBe("data");
  });

  it("fails the token request without the CA — nothing reaches ARM", async () => {
    transport = createCloudTransport({});
    await expect(listActivity(transport, server.origin, server.origin)).rejects.toThrow();
    expect(server.seen).toEqual([]);
  });

  it("accepts the self-signed server with the insecure override on a loopback host", async () => {
    transport = createCloudTransport({ insecure: true });
    expect(await listActivity(transport, server.origin, server.origin)).toHaveLength(1);
  });

  it("tunnels the token and ARM calls through the proxy, each verified as its own host", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    await listActivity(transport, "https://login.cloud.test", "https://arm.cloud.test");
    expect(new Set(proxy.tunnels)).toEqual(new Set(["login.cloud.test:443", "arm.cloud.test:443"]));
    expect(server.seen.find((r) => r.path.includes("/token"))?.sni).toBe("login.cloud.test");
    expect(server.seen.at(-1)?.sni).toBe("arm.cloud.test");
  });

  it("calls Graph with cloudFetch and a token from the same credential", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    const token = await credentialFor(transport, "https://login.cloud.test").getToken(
      "https://graph.microsoft.com/.default",
    );
    const res = await cloudFetch(transport)("https://graph.cloud.test/v1.0/auditLogs/directoryAudits", {
      headers: { authorization: `Bearer ${token.token}` },
    });
    expect(await res.json()).toEqual({ value: [] });
    expect(server.seen.at(-1)?.sni).toBe("graph.cloud.test");
  });
});
