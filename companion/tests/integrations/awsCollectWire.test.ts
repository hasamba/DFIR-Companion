import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createAwsCollectProvider } from "../../src/integrations/cloudCollect/aws/awsCollectProvider.js";
import { createCloudTransport } from "../../src/integrations/cloudTransport/cloudAgent.js";
import type { OpenCloudAccount } from "../../src/integrations/cloudAccounts/types.js";
import { fakeAccessKeyId, fakeAwsSecret } from "../helpers/cloudAccountFixtures.js";
import { ACCOUNT, recordJson, trailKey, trailObject } from "../helpers/awsCollectFakes.js";
import { trailRecord } from "../helpers/cloudCollectFakes.js";

// #2313 on the WIRE: the real SDK clients the collector builds — the assume-role provider's own STS
// client included — send every request through the injected request handler (in production, the
// cloud transport's), and only the read APIs the minimum policy grants are called.

interface WireRequest {
  method: string;
  hostname: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, string>;
  body?: unknown;
}

const ROOT = `AWSLogs/${ACCOUNT}/`;
const KEY = trailKey(ROOT, "us-east-1", "2026-10-01T01:00:00Z");
const OBJECT = trailObject([trailRecord(3, "StopLogging")]);

const text = (body: unknown): string =>
  typeof body === "string" ? body : body instanceof Uint8Array ? Buffer.from(body).toString("utf8") : "";

const stsCredentials =
  "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>TESTKEYID0003</AccessKeyId>" +
  "<SecretAccessKey>test-secret</SecretAccessKey><SessionToken>test-session</SessionToken>" +
  "<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>";
const stsIdentity =
  `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::${ACCOUNT}:assumed-role/collector/s</Arn>` +
  `<Account>${ACCOUNT}</Account><UserId>U</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`;

function listXml(query: Record<string, unknown>): string {
  const prefix = String(query.prefix ?? "");
  if (query.delimiter) {
    const child =
      prefix === "AWSLogs/" ? ROOT : prefix === `${ROOT}CloudTrail/` ? `${ROOT}CloudTrail/us-east-1/` : "";
    return `<ListBucketResult><Prefix>${prefix}</Prefix><IsTruncated>false</IsTruncated>${child ? `<CommonPrefixes><Prefix>${child}</Prefix></CommonPrefixes>` : ""}</ListBucketResult>`;
  }
  const hit = KEY.startsWith(prefix) && !query["start-after"];
  return `<ListBucketResult><Prefix>${prefix}</Prefix><IsTruncated>false</IsTruncated>${hit ? `<Contents><Key>${KEY}</Key><Size>${OBJECT.length}</Size></Contents>` : ""}</ListBucketResult>`;
}

function recordingHandler(sent: WireRequest[]) {
  const reply = (status: number, body: Buffer | string, headers: Record<string, string>) => ({
    response: { statusCode: status, headers, body: Readable.from([Buffer.from(body)]) },
  });
  const xml = (body: string) => reply(200, body, { "content-type": "application/xml" });
  const json = (body: unknown) =>
    reply(200, JSON.stringify(body), { "content-type": "application/x-amz-json-1.1" });
  return {
    metadata: { handlerProtocol: "http/1.1" },
    handle: async (req: WireRequest) => {
      sent.push(req);
      if (req.hostname.startsWith("sts."))
        return xml(text(req.body).includes("Action=AssumeRole") ? stsCredentials : stsIdentity);
      const target = req.headers["x-amz-target"] ?? "";
      if (target.endsWith("DescribeTrails"))
        return json({ trailList: [{ Name: "main", S3BucketName: "trail-bucket" }] });
      if (target.endsWith("LookupEvents"))
        return json({ Events: [{ EventId: "e1", CloudTrailEvent: recordJson(7, "DeleteTrail") }] });
      if (req.hostname.includes("s3") && req.query["list-type"] === "2") return xml(listXml(req.query));
      if (req.hostname.includes("s3") && req.method === "GET")
        return reply(200, Buffer.from(OBJECT), {
          "content-type": "application/json",
          "x-amz-version-id": "v-wire-1",
        });
      return reply(403, "<Error><Code>AccessDenied</Code></Error>", { "content-type": "application/xml" });
    },
    updateHttpClientConfig: () => undefined,
    httpHandlerConfigs: () => ({}),
    destroy: () => undefined,
  };
}

function operation(req: WireRequest): string {
  const target = req.headers["x-amz-target"];
  if (target) return target.split(".").pop() ?? target;
  const action = /(?:^|&)Action=([A-Za-z]+)/.exec(text(req.body))?.[1];
  if (action) return action;
  if (req.hostname.includes("s3") && req.method === "GET")
    return req.query["list-type"] === "2" ? "ListObjectsV2" : "GetObject";
  return `${req.method} ${req.hostname}${req.path}`;
}

const roleAccount = (): OpenCloudAccount => ({
  id: "a1",
  name: "AWS wire",
  revision: 1,
  createdAt: "",
  updatedAt: "",
  provider: "aws",
  settings: {
    authMode: "assume-role",
    roleArn: `arn:aws:iam::${ACCOUNT}:role/collector`,
    baseCredential: "access-key",
    region: "us-east-1",
  },
  secrets: { accessKeyId: fakeAccessKeyId(), secretAccessKey: fakeAwsSecret(), externalId: "ext-1" },
});

describe("AWS collection on the wire (#2313)", () => {
  it("every client and the assume-role STS call use the injected handler; reads only", async () => {
    const sent: WireRequest[] = [];
    const handler = recordingHandler(sent);
    const provider = createAwsCollectProvider({
      transport: () => createCloudTransport({}),
      config: () => ({ requestHandler: handler }),
    });
    const session = provider.open(roleAccount());
    const who = await session.identity();
    expect(who.accountRef).toBe(ACCOUNT);
    expect(Object.keys(who.sdkVersions)).toContain("@aws-sdk/client-s3");
    const window = { start: "2026-10-01T00:00:00Z", end: "2026-10-01T06:00:00Z" };
    const s3 = await session.fetchPage({ source: "s3-trail", subWindowId: "s", window });
    expect(Buffer.from(s3.body).equals(Buffer.from(OBJECT))).toBe(true);
    expect(s3.requestParams).toMatchObject({ key: KEY, versionId: "v-wire-1", bucket: "trail-bucket" });
    const lookup = await session.fetchPage({
      source: "cloudtrail-lookup",
      subWindowId: "l",
      window,
      partition: { region: "us-east-1" },
    });
    expect(Buffer.from(lookup.body).toString("utf8")).toBe(`{"Records":[${recordJson(7, "DeleteTrail")}]}`);
    const ops = sent.map(operation);
    expect(ops[0]).toBe("AssumeRole"); // the role is assumed once, through the handler
    expect(ops.filter((o) => o === "AssumeRole")).toHaveLength(1);
    expect(new Set(ops)).toEqual(
      new Set([
        "AssumeRole",
        "GetCallerIdentity",
        "DescribeTrails",
        "ListObjectsV2",
        "GetObject",
        "LookupEvents",
      ]),
    );
    expect(text(sent[0].body)).toContain("ExternalId=ext-1");
    for (const req of sent) expect(["GET", "POST"]).toContain(req.method);
  });
});
