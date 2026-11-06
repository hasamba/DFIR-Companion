import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { awsAmbientCredentials } from "../../../src/integrations/cloudTransport/awsAmbient.js";
import {
  createCloudTransport,
  type CloudTransport,
} from "../../../src/integrations/cloudTransport/cloudAgent.js";
import { CloudTransportError } from "../../../src/integrations/cloudTransport/destinationTls.js";
import {
  googleAmbientClient,
  googleAmbientImpersonatedClient,
} from "../../../src/integrations/cloudTransport/googleAmbient.js";
import {
  assertOnLinkMetadataEnv,
  isOnLinkHost,
} from "../../../src/integrations/cloudTransport/metadataEndpoints.js";
import { fakeAwsSecret } from "../../helpers/cloudAccountFixtures.js";
import {
  GOOGLE_IAM_HOST,
  GOOGLE_TOKEN_HOST,
  makeTlsMaterial,
  startConnectProxy,
  startTlsServer,
  type ConnectProxy,
  type Route,
  type TlsMaterial,
  type TlsServer,
} from "../../helpers/cloudTlsHarness.js";

// #2309 review: the machine's OWN cloud credentials ("ambient") go through the cloud transport —
// every STS / SSO / OAuth / IAM call — and only the link-local metadata endpoints stay direct.

const ENV_NAMES = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_DEFAULT_REGION",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_CONFIG_FILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_EC2_METADATA_DISABLED",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GCE_METADATA_HOST",
  "GCE_METADATA_IP",
  "CLOUDSDK_CONFIG",
];
let saved: Record<string, string | undefined>;
let dir: string;

beforeEach(() => {
  saved = Object.fromEntries(ENV_NAMES.map((n) => [n, process.env[n]]));
  for (const n of ENV_NAMES) delete process.env[n];
  dir = mkdtempSync(join(tmpdir(), "cloud-ambient-"));
  // No shared files of the real user, no instance metadata, no gcloud login.
  process.env.AWS_CONFIG_FILE = join(dir, "aws-config");
  process.env.AWS_SHARED_CREDENTIALS_FILE = join(dir, "aws-credentials");
  process.env.AWS_EC2_METADATA_DISABLED = "true";
  process.env.CLOUDSDK_CONFIG = join(dir, "gcloud");
});
afterEach(() => {
  for (const n of ENV_NAMES) {
    if (saved[n] === undefined) delete process.env[n];
    else process.env[n] = saved[n];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("metadata endpoint overrides", () => {
  it("accepts link-local, loopback and the GCE metadata name", () => {
    for (const h of [
      "169.254.169.254",
      "169.254.170.2",
      "127.0.0.1",
      "::1",
      "fd00:ec2::254",
      "metadata.google.internal",
    ])
      expect(isOnLinkHost(h), h).toBe(true);
    for (const h of ["imds.example.net", "10.0.0.5", "8.8.8.8", "2001:db8::1"])
      expect(isOnLinkHost(h), h).toBe(false);
    expect(() =>
      assertOnLinkMetadataEnv({ AWS_EC2_METADATA_SERVICE_ENDPOINT: "http://[fd00:ec2::254]" }, [
        "AWS_EC2_METADATA_SERVICE_ENDPOINT",
      ]),
    ).not.toThrow();
  });

  it("refuses an AWS container or IMDS endpoint moved off the machine's link", async () => {
    const t = createCloudTransport({});
    process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI = "https://creds.example.net/role";
    await expect(awsAmbientCredentials(t)()).rejects.toThrow(/AWS_CONTAINER_CREDENTIALS_FULL_URI/);
    delete process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI;
    process.env.AWS_EC2_METADATA_SERVICE_ENDPOINT = "http://imds.example.net";
    await expect(awsAmbientCredentials(t)()).rejects.toBeInstanceOf(CloudTransportError);
  });

  it("refuses a GCE metadata host moved off the machine's link", async () => {
    process.env.GCE_METADATA_HOST = "metadata.example.net";
    await expect(googleAmbientClient(createCloudTransport({}), { scopes: ["s"] })).rejects.toThrow(
      /GCE_METADATA_HOST/,
    );
  });
});

// ---- AWS: the ambient chain sends STS through the given request handler ----

interface WireRequest {
  method: string;
  hostname: string;
  body?: unknown;
}

const stsCreds = (op: string) =>
  `<${op}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><${op}Result><Credentials>` +
  "<AccessKeyId>TESTKEYID0001</AccessKeyId><SecretAccessKey>test-secret</SecretAccessKey>" +
  "<SessionToken>test-session</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>" +
  `</Credentials></${op}Result><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></${op}Response>`;

function bodyText(body: unknown): string {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return Buffer.from(body).toString("utf8");
  return "";
}

function stsRecorder(sent: WireRequest[]) {
  return {
    metadata: { handlerProtocol: "http/1.1" },
    handle: async (req: WireRequest) => {
      sent.push(req);
      const op = /(?:^|&)Action=([A-Za-z]+)/.exec(bodyText(req.body))?.[1] ?? "Unknown";
      return {
        response: {
          statusCode: 200,
          headers: { "content-type": "text/xml" },
          body: Readable.from([Buffer.from(stsCreds(op))]),
        },
      };
    },
    updateHttpClientConfig: () => undefined,
    httpHandlerConfigs: () => ({}),
    destroy: () => undefined,
  };
}

const actions = (sent: WireRequest[]) =>
  sent.map((r) => `${r.hostname.split(".")[0]}:${/Action=([A-Za-z]+)/.exec(bodyText(r.body))?.[1]}`);

describe("AWS ambient credentials over the transport", () => {
  const ROLE = "arn:aws:iam::123456789012:role/collector";

  async function resolve(): Promise<WireRequest[]> {
    const sent: WireRequest[] = [];
    const provider = awsAmbientCredentials(createCloudTransport({}), {
      region: "eu-west-1",
      clientConfig: { requestHandler: stsRecorder(sent) },
    });
    const creds = await provider();
    expect(creds.accessKeyId).toBe("TESTKEYID0001");
    return sent;
  }

  it("sends a web-identity token exchange (env) through the handler", async () => {
    writeFileSync(join(dir, "token"), "web-identity-token");
    process.env.AWS_WEB_IDENTITY_TOKEN_FILE = join(dir, "token");
    process.env.AWS_ROLE_ARN = ROLE;
    expect(actions(await resolve())).toEqual(["sts:AssumeRoleWithWebIdentity"]);
  });

  it("sends a profile's assume-role through the handler", async () => {
    writeFileSync(
      join(dir, "aws-credentials"),
      `[base]\naws_access_key_id = TESTBASEKEY01\naws_secret_access_key = ${fakeAwsSecret()}\n`,
    );
    writeFileSync(join(dir, "aws-config"), `[profile target]\nrole_arn = ${ROLE}\nsource_profile = base\n`);
    process.env.AWS_PROFILE = "target";
    expect(actions(await resolve())).toEqual(["sts:AssumeRole"]);
  });

  it("sends a profile's web_identity_token_file exchange through the handler", async () => {
    writeFileSync(join(dir, "token"), "web-identity-token");
    writeFileSync(
      join(dir, "aws-config"),
      `[profile wid]\nrole_arn = ${ROLE}\nweb_identity_token_file = ${join(dir, "token")}\n`,
    );
    process.env.AWS_PROFILE = "wid";
    expect(actions(await resolve())).toEqual(["sts:AssumeRoleWithWebIdentity"]);
  });
});

// ---- Google: ADC over the local CONNECT proxy; external accounts refused ----

const TARGET = "collector-target@lab-project.iam.gserviceaccount.com";
const route: Route = (req) => {
  if (req.method === "POST" && req.path === "/token")
    return { body: JSON.stringify({ access_token: "user-access", expires_in: 3600, token_type: "Bearer" }) };
  if (
    req.method === "POST" &&
    decodeURIComponent(req.path).endsWith(`/serviceAccounts/${TARGET}:generateAccessToken`)
  )
    return {
      body: JSON.stringify({ accessToken: "impersonated-access", expireTime: "2099-01-01T00:00:00Z" }),
    };
  if (req.method === "POST" && req.path === "/v2/entries:list")
    return { body: JSON.stringify({ entries: [] }) };
  return undefined;
};

describe("Google ambient credentials over the transport", () => {
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

  it("impersonates from a gcloud user login with every call through the proxy", async () => {
    const adc = join(dir, "adc.json");
    writeFileSync(
      adc,
      JSON.stringify({
        type: "authorized_user",
        client_id: "cid",
        client_secret: "csecret",
        refresh_token: "rtok",
      }),
    );
    process.env.GOOGLE_APPLICATION_CREDENTIALS = adc;
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    const client = await googleAmbientImpersonatedClient(transport, {
      targetPrincipal: TARGET,
      targetScopes: ["https://www.googleapis.com/auth/logging.read"],
      projectId: "lab-project",
    });
    const res = await client.request({
      url: "https://logging.cloud.test/v2/entries:list",
      method: "POST",
      data: {},
      retry: false,
    });
    expect(res.data).toEqual({ entries: [] });
    expect(proxy.tunnels).toEqual([
      `${GOOGLE_TOKEN_HOST}:443`,
      `${GOOGLE_IAM_HOST}:443`,
      "logging.cloud.test:443",
    ]);
    expect(server.seen[1]?.authorization).toBe("Bearer user-access");
  });

  it("refuses an external-account (workload identity) configuration, with no request made", async () => {
    const adc = join(dir, "external.json");
    writeFileSync(
      adc,
      JSON.stringify({
        type: "external_account",
        audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        token_url: "https://sts.googleapis.com/v1/token",
        credential_source: { file: join(dir, "subject-token") },
      }),
    );
    process.env.GOOGLE_APPLICATION_CREDENTIALS = adc;
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    await expect(googleAmbientClient(transport, { scopes: ["s"], projectId: "lab-project" })).rejects.toThrow(
      /external account/,
    );
    expect(proxy.tunnels).toEqual([]);
  });
});
