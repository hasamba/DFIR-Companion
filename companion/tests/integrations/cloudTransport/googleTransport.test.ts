import { generateKeyPairSync } from "node:crypto";
import { Agent as HttpsAgent } from "node:https";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  createCloudTransport,
  type CloudTransport,
} from "../../../src/integrations/cloudTransport/cloudAgent.js";
import {
  createGoogleAuth,
  googleImpersonatedClient,
} from "../../../src/integrations/cloudTransport/googleTransport.js";
import {
  makeTlsMaterial,
  startConnectProxy,
  startTlsServer,
  type ConnectProxy,
  type Route,
  type TlsMaterial,
  type TlsServer,
  GOOGLE_IAM_HOST,
  GOOGLE_TOKEN_HOST,
} from "../../helpers/cloudTlsHarness.js";

// Google over the cloud transport (#2310): the service-account token exchange and the Logging
// entries:list data call both go through the auth client's transporter. google-auth-library
// hardcodes the token URL (https://oauth2.googleapis.com/token), so EVERY test here goes through the
// local CONNECT proxy, which answers for that host from the local TLS server — no request leaves the
// machine. The service-account key is generated at runtime.

const TARGET = "collector-target@lab-project.iam.gserviceaccount.com";
const SOURCE_EMAIL = "collector@lab-project.iam.gserviceaccount.com";

const route: Route = (req) => {
  if (req.method === "POST" && req.path === "/token") {
    return { body: JSON.stringify({ access_token: "test-access", expires_in: 3600, token_type: "Bearer" }) };
  }
  if (
    req.method === "POST" &&
    decodeURIComponent(req.path).endsWith(`/serviceAccounts/${TARGET}:generateAccessToken`)
  ) {
    return {
      body: JSON.stringify({ accessToken: "impersonated-access", expireTime: "2099-01-01T00:00:00Z" }),
    };
  }
  if (req.method === "POST" && req.path === "/v2/entries:list")
    return { body: JSON.stringify({ entries: [] }) };
  return undefined;
};

let material: TlsMaterial;
let server: TlsServer;
let proxy: ConnectProxy;
let transport: CloudTransport | undefined;
let privateKey: string;

beforeAll(async () => {
  material = makeTlsMaterial();
  server = await startTlsServer(material, route);
  proxy = await startConnectProxy(server.port);
  privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
});
afterEach(() => {
  vi.unstubAllEnvs();
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

const DATA_ORIGIN = "https://logging.cloud.test";

function serviceAccountKey() {
  return { type: "service_account", client_email: SOURCE_EMAIL, private_key: privateKey };
}

async function entriesWith(
  client: { request: (o: object) => Promise<{ data: unknown }> },
  requestAgent?: HttpsAgent,
): Promise<unknown> {
  const res = await client.request({
    url: `${DATA_ORIGIN}/v2/entries:list`,
    method: "POST",
    data: { resourceNames: ["projects/lab-project"], pageSize: 1000 },
    retry: false,
    ...(requestAgent ? { agent: requestAgent } : {}),
  });
  return res.data;
}

async function listEntries(t: CloudTransport, requestAgent?: HttpsAgent): Promise<unknown> {
  const auth = createGoogleAuth(t, {
    credentials: serviceAccountKey(),
    scopes: ["https://www.googleapis.com/auth/logging.read"],
  });
  return entriesWith(await auth.getClient(), requestAgent);
}

const IMPERSONATED_JSON = () => ({
  type: "impersonated_service_account",
  source_credentials: serviceAccountKey(),
  service_account_impersonation_url: `https://${GOOGLE_IAM_HOST}/v1/projects/-/serviceAccounts/${TARGET}:generateAccessToken`,
});

describe("Google auth over the cloud transport", () => {
  it("carries the custom CA to the token exchange and the Logging data request", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    expect(await listEntries(transport)).toEqual({ entries: [] });
    expect(server.seen.map((r) => r.path)).toEqual(["/token", "/v2/entries:list"]);
    expect(proxy.tunnels).toEqual([`${GOOGLE_TOKEN_HOST}:443`, "logging.cloud.test:443"]);
    expect(server.seen.map((r) => r.sni)).toEqual([GOOGLE_TOKEN_HOST, "logging.cloud.test"]);
  });

  it("fails the token exchange without the CA — nothing reaches the data endpoint", async () => {
    transport = createCloudTransport({ proxyUrl: proxy.url });
    await expect(listEntries(transport)).rejects.toThrow(/certificate/i);
    expect(server.seen).toEqual([]);
  });

  it("refuses the insecure override toward the real token host without the global override", async () => {
    vi.stubEnv("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "");
    transport = createCloudTransport({ insecure: true, proxyUrl: proxy.url });
    await expect(listEntries(transport)).rejects.toThrow(/DFIR_TLS_ALLOW_INSECURE_EXTERNAL/);
    expect(proxy.tunnels).toEqual([]);
  });

  it("applies the insecure override once DFIR_TLS_ALLOW_INSECURE_EXTERNAL=true", async () => {
    vi.stubEnv("DFIR_TLS_ALLOW_INSECURE_EXTERNAL", "true");
    transport = createCloudTransport({ insecure: true, proxyUrl: proxy.url });
    expect(await listEntries(transport)).toEqual({ entries: [] });
  });

  it("keeps the transport even when a library sets its own per-request agent", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    expect(await listEntries(transport, new HttpsAgent())).toEqual({ entries: [] });
    expect(proxy.tunnels).toContain("logging.cloud.test:443");
  });
});

describe("Google impersonation over the cloud transport", () => {
  const expectImpersonatedFlow = () => {
    // Source key → oauth2 token; source token → IAM generateAccessToken; target token → data.
    expect(proxy.tunnels).toEqual([
      `${GOOGLE_TOKEN_HOST}:443`,
      `${GOOGLE_IAM_HOST}:443`,
      "logging.cloud.test:443",
    ]);
    expect(server.seen.map((r) => r.sni)).toEqual([GOOGLE_TOKEN_HOST, GOOGLE_IAM_HOST, "logging.cloud.test"]);
    expect(server.seen[1]?.authorization).toBe("Bearer test-access");
    expect(server.seen[2]?.authorization).toBe("Bearer impersonated-access");
  };

  it("routes impersonated_service_account JSON through the transport on source AND target", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    const auth = createGoogleAuth(transport, {
      credentials: IMPERSONATED_JSON() as never,
      scopes: ["https://www.googleapis.com/auth/logging.read"],
    });
    expect(await entriesWith(await auth.getClient())).toEqual({ entries: [] });
    expectImpersonatedFlow();
  });

  it("builds impersonated credentials explicitly with the transport on both clients", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    const client = googleImpersonatedClient(transport, {
      sourceCredentials: serviceAccountKey(),
      targetPrincipal: TARGET,
      targetScopes: ["https://www.googleapis.com/auth/logging.read"],
    });
    expect(await entriesWith(client)).toEqual({ entries: [] });
    expectImpersonatedFlow();
  });

  it("fails the source token refresh without the CA — IAM and data are never reached", async () => {
    transport = createCloudTransport({ proxyUrl: proxy.url });
    const auth = createGoogleAuth(transport, { credentials: IMPERSONATED_JSON() as never });
    await expect(entriesWith(await auth.getClient())).rejects.toThrow(/certificate/i);
    expect(server.seen).toEqual([]);
  });
});
