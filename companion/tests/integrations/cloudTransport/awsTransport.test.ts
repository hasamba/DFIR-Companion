import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import {
  createCloudTransport,
  type CloudTransport,
} from "../../../src/integrations/cloudTransport/cloudAgent.js";
import { awsClientConfig } from "../../../src/integrations/cloudTransport/awsTransport.js";
import {
  makeTlsMaterial,
  startConnectProxy,
  startTlsServer,
  type ConnectProxy,
  type Route,
  type TlsMaterial,
  type TlsServer,
} from "../../helpers/cloudTlsHarness.js";

// AWS SDK v3 over the cloud transport (#2310): the AssumeRole call to STS (the token path) and the
// S3 data call both go through it, with endpoint overrides pointing at the local TLS server.

const ASSUME_ROLE_XML = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>ASIATESTTESTTEST</AccessKeyId><SecretAccessKey>test-secret</SecretAccessKey>
<SessionToken>test-session</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><AssumedRoleId>AROATEST:dfir</AssumedRoleId><Arn>arn:aws:sts::111122223333:assumed-role/r/dfir</Arn></AssumedRoleUser>
</AssumeRoleResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></AssumeRoleResponse>`;

const LIST_XML = `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>trail</Name><Prefix>AWSLogs/</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>
<Contents><Key>AWSLogs/111122223333/CloudTrail/x.json.gz</Key><Size>10</Size></Contents></ListBucketResult>`;

const route: Route = (req) => {
  if (req.method === "POST" && req.body.includes("Action=AssumeRole"))
    return { type: "text/xml", body: ASSUME_ROLE_XML };
  if (req.path.startsWith("/trail")) return { type: "application/xml", body: LIST_XML };
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

function s3Through(t: CloudTransport, stsEndpoint: string, s3Endpoint: string): S3Client {
  const config = awsClientConfig(t);
  const credentials = fromTemporaryCredentials({
    params: { RoleArn: "arn:aws:iam::111122223333:role/r", RoleSessionName: "dfir" },
    masterCredentials: { accessKeyId: "AKIATESTTESTTEST", secretAccessKey: "base-secret" },
    clientConfig: { region: "us-east-1", endpoint: stsEndpoint, ...config },
  });
  return new S3Client({
    region: "us-east-1",
    endpoint: s3Endpoint,
    forcePathStyle: true,
    credentials,
    ...config,
  });
}

const listTrail = (s3: S3Client) =>
  s3.send(new ListObjectsV2Command({ Bucket: "trail", Prefix: "AWSLogs/" }));

describe("AWS SDK over the cloud transport", () => {
  it("carries the custom CA to the STS token request and the S3 data request", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath });
    const out = await listTrail(s3Through(transport, server.origin, server.origin));
    expect(out.Contents?.[0]?.Key).toBe("AWSLogs/111122223333/CloudTrail/x.json.gz");
    expect(server.seen.map((r) => (r.body.includes("AssumeRole") ? "sts" : "s3"))).toEqual(["sts", "s3"]);
  });

  it("fails the token request without the CA — nothing reaches the data endpoint", async () => {
    transport = createCloudTransport({});
    await expect(listTrail(s3Through(transport, server.origin, server.origin))).rejects.toThrow(
      /certificate/i,
    );
    expect(server.seen).toEqual([]);
  });

  it("accepts the self-signed server with the insecure override on a loopback host", async () => {
    transport = createCloudTransport({ insecure: true });
    const out = await listTrail(s3Through(transport, server.origin, server.origin));
    expect(out.KeyCount).toBe(1);
  });

  it("tunnels the STS and S3 calls through the proxy, each verified as its own host", async () => {
    transport = createCloudTransport({ caCertPath: material.caPath, proxyUrl: proxy.url });
    await listTrail(s3Through(transport, "https://sts.cloud.test", "https://s3.cloud.test"));
    expect(proxy.tunnels).toEqual(["sts.cloud.test:443", "s3.cloud.test:443"]);
    expect(server.seen.map((r) => r.sni)).toEqual(["sts.cloud.test", "s3.cloud.test"]);
  });
});
